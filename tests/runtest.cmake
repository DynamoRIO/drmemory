# **********************************************************
# Copyright (c) 2009 VMware, Inc.  All rights reserved.
# **********************************************************

# Dr. Memory: the memory debugger
# 
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; 
# version 2.1 of the License, and no later version.
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Library General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# input:
# * cmd = command to run, with intra-arg space=@@ and inter-arg space=@
# * TOOL_DR_HEAPSTAT = whether the tool is Dr. Heapstat instead of Dr. Memory
# * outpat = file containing expected patterns in output
# * respat = file containing expected patterns in results.txt
# * nudge = command to run perl script that takes -nudge for nudge
# * toolbindir = location of DynamoRIO tools dir
# * VMKERNEL = whether running on vmkernel
# * USE_DRSYMS = whether running a DRSYMS build
# * postcmd = post-process command for Dr. Heapstat leak results or
#     Dr. Memory -skip_results + -results
#
# these allow for parameterization for more portable tests (PR 544430)
# env vars will override; else passed-in default settings will be used:
# * DRMEMORY_CTEST_SRC_DIR = source dir
# * DRMEMORY_CTEST_DR_DIR = DynamoRIO cmake dir
#
# any regex chars in the patterns will be escaped.
# a line beginning with # is a comment and is ignored.
# basic conditionals are "!if WINDOWS" and "!if UNIX" ending with
# "!endif".

##################################################
# let env vars override build-dir defaults passed in as cmake defines

if (NOT "$ENV{DRMEMORY_CTEST_SRC_DIR}" STREQUAL "")
  set(DRMEMORY_CTEST_SRC_DIR "$ENV{DRMEMORY_CTEST_SRC_DIR}")
endif ()
if (NOT "$ENV{DRMEMORY_CTEST_DR_DIR}" STREQUAL "")
  set(DRMEMORY_CTEST_DR_DIR "$ENV{DRMEMORY_CTEST_DR_DIR}")
endif ()

foreach (var cmd outpat respat nudge toolbindir)
  string(REGEX REPLACE "{DRMEMORY_CTEST_SRC_DIR}"
    "${DRMEMORY_CTEST_SRC_DIR}" ${var} "${${var}}")
  string(REGEX REPLACE "{DRMEMORY_CTEST_DR_DIR}"
    "${DRMEMORY_CTEST_DR_DIR}" ${var} "${${var}}")
endforeach ()

##################################################
# ensure the two files with expected results exist

file(READ "${outpat}" outmatch)
if (TOOL_DR_HEAPSTAT)
  # different file to match against
  string(REGEX REPLACE "\\.res" ".heapstat.res" respat "${respat}")
endif (TOOL_DR_HEAPSTAT)
if (EXISTS "${respat}")
  file(READ "${respat}" resmatch)
  set(patterns outmatch resmatch)
else ()
  set(resmatch OFF)
  set(patterns outmatch)
endif()

##################################################
# run the test

# used for sleeping, and for nudge test
find_program(PERL perl)
if (NOT PERL)
  message(FATAL_ERROR "cannot find perl")
endif (NOT PERL)

# use perl since /bin/sleep not on all platforms
set(SLEEP_SHORT ${PERL} -e "sleep(0.2)")
set(SLEEP_LONG ${PERL} -e "sleep(2)")

# intra-arg space=@@ and inter-arg space=@
set(cmd_with_at ${cmd})
string(REGEX REPLACE "@@" " " cmd "${cmd}")
string(REGEX REPLACE "@" ";" cmd "${cmd}")

if ("${cmd}" MATCHES "run_in_bg")
  # nudge test
  # modeled after DR's runall.cmake
  string(REGEX MATCHALL "-out@[^@]+@" out "${cmd_with_at}")
  string(REGEX REPLACE "-out@([^@]+)@" "\\1" out "${out}")

  if (WIN32)
    # can't get pid from run_in_bg for 2 reasons: not printed to stdout,
    # and drmemory.pl doesn't exec.  so we pass in pidfile to drmemory.pl.
    string(REGEX REPLACE "(dr[a-z]*.pl);" "\\1;-pid_file;${out}pid;" cmd "${cmd}")
    string(REGEX REPLACE "(drmemory.exe);" "\\1;-pid_file;${out}pid;" cmd "${cmd}")
    file(REMOVE "${out}pid")
  endif (WIN32)

  # we must remove so we know when the background process has re-created it
  file(REMOVE "${out}")

  # run in the background.  run_in_bg prints the bg pid to stdout.
  execute_process(COMMAND ${cmd}
    RESULT_VARIABLE cmd_result
    ERROR_VARIABLE cmd_err
    OUTPUT_VARIABLE pid OUTPUT_STRIP_TRAILING_WHITESPACE)
  if (cmd_result)
    message(FATAL_ERROR "*** ${cmd} failed (${cmd_result}): ${cmd_err}***\n")
  endif (cmd_result)

  if (VMKERNEL)
    # have to wait for probe loop init
    execute_process(COMMAND ${SLEEP_LONG})
  endif (VMKERNEL)

  while (NOT EXISTS "${out}")
    execute_process(COMMAND ${SLEEP_SHORT})
  endwhile ()
  file(READ "${out}" output)
  while (NOT "${output}" MATCHES "starting\n")
    execute_process(COMMAND ${SLEEP_SHORT})
    file(READ "${out}" output)
  endwhile()

  if (WIN32)
    while (NOT EXISTS "${out}pid")
      execute_process(COMMAND ${SLEEP_SHORT})
    endwhile ()
    file(READ "${out}pid" pid)
    string(REGEX REPLACE "\r?\n" "" pid "${pid}")
  endif (WIN32)
  # PR 562051: try to ensure nudge doesn't go out too early
  execute_process(COMMAND ${SLEEP_SHORT})

  string(REGEX REPLACE "@@" " " nudge "${nudge}")
  string(REGEX REPLACE "@" ";" nudge "${nudge}")
  execute_process(COMMAND ${nudge} -nudge ${pid}
    RESULT_VARIABLE nudge_result
    ERROR_VARIABLE nudge_err
    OUTPUT_VARIABLE nudge_out)
  # combine out and err
  set(nudge_err "${nudge_out}${nudge_err}")
  if (nudge_result)
    message(FATAL_ERROR "*** ${script} failed (${nudge_result}): ${nudge_err}***\n")
  endif (nudge_result)
  # do a second nudge to test accumulation of leak counts
  execute_process(COMMAND ${nudge} -nudge ${pid}
    RESULT_VARIABLE nudge_result
    ERROR_VARIABLE nudge_err
    OUTPUT_VARIABLE nudge_out)
  # combine out and err
  set(nudge_err "${nudge_out}${nudge_err}")
  if (nudge_result)
    message(FATAL_ERROR "*** ${script} failed (${nudge_result}): ${nudge_err}***\n")
  endif (nudge_result)

  # wait for summary output: last line has "report_leak_max" on it
  # we also need to wait for Details line
  if (TOOL_DR_HEAPSTAT)
    # there is no tool output so just wait for both nudges
    set(lookfor "received nudge.*received nudge")
  else ()
    set(lookfor "report_leak_max\n.*Details: ")
  endif ()
  file(READ "${out}" output)
  while (NOT "${output}" MATCHES "${lookfor}")
    execute_process(COMMAND ${SLEEP_SHORT})
    file(READ "${out}" output)
  endwhile()

  string(REGEX MATCHALL "/[^/]+$" exename "${cmd}")
  string(REGEX REPLACE "/" "" exename "${exename}")
  if (UNIX)
    # use perl since /usr/bin/kill not on all platforms
    # we do a hard kill, since daemons often are killed w/o DrMem cleanup
    execute_process(COMMAND uname OUTPUT_VARIABLE uname_out)
    # VMKERNEL doesn't reflect what we're really on
    if ("${uname_out}" MATCHES "VMkernel")
      # on esxi the sideline thread has the same pid (clone differences)
      execute_process(COMMAND "${PERL}" -e "kill 9, ${pid}"
        RESULT_VARIABLE kill_result
        ERROR_VARIABLE kill_err
        OUTPUT_VARIABLE kill_out)
    else ("${uname_out}" MATCHES "VMkernel")
      # we need to also kill the sideline thread which has a different pid.
      # if we use "kill -9, getpgrp ${pid}" we take down ctest too.
      # what we want is perl Proc::Killfam but it's not standard enough.
      find_program(PKILL pkill PATHS "/build/toolchain/lin32/procps-3.2.7/bin/pkill")
      if (NOT PKILL)
        message(FATAL_ERROR "cannot find pkill")
      endif (NOT PKILL)
      # we're assuming only infloop is run: if we add more bg tests we'll
      # need to generalize this
      if (NOT "${exename}" MATCHES "infloop")
        message(FATAL_ERROR "only support infloop for now")
      endif ()
      execute_process(COMMAND "${PKILL}" -9 infloop
        RESULT_VARIABLE kill_result
        ERROR_VARIABLE kill_err
        OUTPUT_VARIABLE kill_out)
    endif ("${uname_out}" MATCHES "VMkernel")
    # combine out and err
    set(kill_err "${kill_out}${kill_err}")
  else (UNIX)
    execute_process(COMMAND "${toolbindir}/DRkill.exe" -exe "${exename}"
      RESULT_VARIABLE kill_result
      ERROR_VARIABLE kill_err
      OUTPUT_QUIET) # prints "killing process ..."
  endif (UNIX)
  if (kill_result)
    message(FATAL_ERROR "*** kill failed (${kill_result}): ${kill_err}***\n")
  endif (kill_result)

  file(READ "${out}" cmd_err)

else ()
  execute_process(COMMAND ${cmd}
    RESULT_VARIABLE cmd_result
    ERROR_VARIABLE cmd_err
    OUTPUT_VARIABLE cmd_out)
  # combine out and err
  set(cmd_err "${cmd_out}${cmd_err}")
  if (cmd_result)
    message(FATAL_ERROR "*** ${cmd} failed (${cmd_result}): ${cmd_err}***\n")
  endif (cmd_result)
endif ()

##################################################
# process the patterns

foreach (str ${patterns})
  # turn regex chars into literals
  string(REGEX REPLACE "([\\^\\$\\.\\*\\+\\?\\|\\(\\)\\[])" "\\\\\\1" ${str} "${${str}}")
  # \\] somehow messes up the match when inside the long string so we separate it
  string(REGEX REPLACE "\\]" "\\\\]" ${str} "${${str}}")

  # remove comments
  string(REGEX REPLACE "(^|\n)#[^\n]*\n" "\\1\n" ${str} "${${str}}")

  # evaluate conditionals
  # cmake's regex matcher is maximal unfortunately: for now we disallow !
  # inside conditional
  if (WIN32 AND NOT USE_DRSYMS AND "${${str}}" MATCHES "!if CYGWIN") # cygwin
    # if !CYGWIN is NOT present then counts as Windows
    string(REGEX REPLACE "(^|\n)!if UNIX[^!]+\n!endif\n" "\\1" ${str} "${${str}}")
    string(REGEX REPLACE "(^|\n)!if WINDOWS[^!]+\n!endif\n" "\\1" ${str} "${${str}}")
  else (WIN32 AND NOT USE_DRSYMS AND "${${str}}" MATCHES "!if CYGWIN")
    if (WIN32)
      string(REGEX REPLACE "(^|\n)!if UNIX[^!]+\n!endif\n" "\\1" ${str} "${${str}}")
      string(REGEX REPLACE "(^|\n)!if CYGWIN[^!]+\n!endif\n" "\\1" ${str} "${${str}}")
    elseif (UNIX)
      string(REGEX REPLACE "(^|\n)!if WINDOWS[^!]+\n!endif\n" "\\1" ${str} "${${str}}")
      string(REGEX REPLACE "(^|\n)!if CYGWIN[^!]+\n!endif\n" "\\1" ${str} "${${str}}")
    endif (WIN32)
  endif (WIN32 AND NOT USE_DRSYMS AND "${${str}}" MATCHES "!if CYGWIN")

  string(REGEX REPLACE "(^|\n)!(if|endif)[^\n]*\n" "\\1" ${str} "${${str}}")
endforeach (str)

##################################################
# check stderr

string(REGEX MATCHALL "([^\n]+)\n" lines "${outmatch}")
foreach (line ${lines})
  # we include the newline in the match
  if (WIN32)
    string(REGEX REPLACE "\n" "\r?\n" line "${line}")
  endif (WIN32)
  if (NOT "${cmd_err}" MATCHES "${line}")
    # ignore Dr. Memory lines for Dr. Heapstat
    # FIXME PR 470723: add Dr. Heapstat-specific tests
    if (NOT TOOL_DR_HEAPSTAT OR
        NOT "${line}" MATCHES "^:::Dr\\\\.Memory:::")
      message(FATAL_ERROR "stderr failed to match: \"${line}\"")
    endif ()
  endif ()
endforeach (line)

##################################################
# check results.txt

if (resmatch)
  if (NOT "${postcmd}" STREQUAL "")
    string(REGEX REPLACE "@@" " " postcmd "${postcmd}")
    string(REGEX REPLACE "@" ";" postcmd "${postcmd}")
  endif (NOT "${postcmd}" STREQUAL "")
  if (TOOL_DR_HEAPSTAT)
    set(data_prefix "Data is in ")
  else (TOOL_DR_HEAPSTAT)
    if ("${postcmd}" STREQUAL "")
      set(data_prefix "Details: ")
    else ()
      set(data_prefix "To obtain results, run with: -results ")
    endif ()
  endif (TOOL_DR_HEAPSTAT)
  # it may not be created yet
  while (NOT "${cmd_err}" MATCHES "${data_prefix}")
    execute_process(COMMAND ${SLEEP_SHORT})
  endwhile ()
  string(REGEX MATCHALL "${data_prefix}([^\n]+)[\n]" resfiles "${cmd_err}")
  
  set(maxlen 0)
  foreach (resfile ${resfiles})
    # for execve test we have multiple: could use name but that's not
    # available on vmkernel (grrr...) so we take the largest (can't rely
    # on last being the right one, and exec target malloc will produce
    # larger log than parent or pre-exec child)
    string(REGEX REPLACE "${data_prefix}" "" resfile "${resfile}")
    string(REGEX REPLACE "[\n]" "" resfile "${resfile}")

    if (NOT "${postcmd}" STREQUAL "")
      # generate resfile
      set(thiscmd "${postcmd};${resfile}")
      execute_process(COMMAND ${thiscmd}
        RESULT_VARIABLE postcmd_result
        ERROR_VARIABLE postcmd_err
        OUTPUT_VARIABLE postcmd_out)
      if (postcmd_result)
        message(FATAL_ERROR
          "*** ${thiscmd} failed (${postcmd_result}): ${postcmd_err}***\n")
      endif (postcmd_result)
      set(resfile "${resfile}/results.txt")
    else (NOT "${postcmd}" STREQUAL "")
      set(postcmd_err "")
    endif (NOT "${postcmd}" STREQUAL "")

    file(READ "${resfile}" contents)
    string(LENGTH "${contents}" reslen)
    if (reslen GREATER maxlen)
      set(maxlen ${reslen})
      # include postcmd summary for Dr. Heapstat
      set(results "${postcmd_err}\n${contents}")
      set(resfile_using ${resfile})
    endif ()
  endforeach (resfile)
  
  # remove absolute addresses (from PR 535568)
  string(REGEX REPLACE " 0x[0-9a-f]+-0x[0-9a-f]+" "" results "${results}")

  string(REGEX MATCHALL "([^\n]+)\n" lines "${resmatch}")
  foreach (line ${lines})
    # we do NOT include the newline, to support matching intra-line substrings
    string(REGEX REPLACE "\r?\n" "" line "${line}")
    if (NOT "${results}" MATCHES "${line}")
      message(FATAL_ERROR "${resfile_using} failed to match: \"${line}\"")
    endif ()
  endforeach (line)
  # FIXME: should also ensure there aren't superfluous errors reported
endif (resmatch)
