# **********************************************************
# Copyright (c) 2010-2011 Google, Inc.  All rights reserved.
# Copyright (c) 2009-2010 VMware, Inc.  All rights reserved.
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

cmake_minimum_required(VERSION 2.6)

# tests are always built w/o optimizations and with symbols,
# regardless of DrMem library settings
set(CMAKE_BUILD_TYPE "Debug")

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/tests")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/tests")
if ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
  # we don't support the Debug and Release subdirs
  foreach (config ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER "${config}" config_upper)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${config_upper}
      "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${config_upper}
      "${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}")
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${config_upper}
      "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
  endforeach ()
endif ()

function(set_props target)
  if (UNIX)
    set(defs "-DLINUX")
    if (HAVE_FVISIBILITY)
      set(defs "${defs} -DUSE_VISIBILITY_ATTRIBUTES")
    endif (HAVE_FVISIBILITY)
  else (UNIX)
    set(defs "-DWINDOWS")
  endif (UNIX)
  if (VMKERNEL)
    set(defs "${defs} -DVMX86_SERVER")
  endif (VMKERNEL)
  set_target_properties(${target} PROPERTIES COMPILE_FLAGS "${defs}")
endfunction(set_props)

function(tobuild name source)
  add_executable(${name} ${source})
  set_props(${name})
endfunction(tobuild)

function(tobuild_lib name source cust_flags cust_link)
  add_library(${name} SHARED ${source})
  set_props(${name})
  get_target_property(cur_flags ${name} COMPILE_FLAGS)
  set_target_properties(${name} PROPERTIES COMPILE_FLAGS "${cur_flags} ${cust_flags}")
  get_target_property(cur_link ${name} LINK_FLAGS)
  if (NOT cur_link)
    set(cur_link "")
  endif (NOT cur_link)
  set_target_properties(${name} PROPERTIES LINK_FLAGS "${cur_link} ${cust_link}")
endfunction(tobuild_lib)

# tools for nudge tests
# to avoid conflict w/ DR's run_in_bg target we use a different target name
tobuild(run_in_bg_tgt run_in_bg.c)
set_target_properties(run_in_bg_tgt PROPERTIES OUTPUT_NAME run_in_bg)
if (WIN32)
  target_link_libraries(run_in_bg_tgt ntdll)
endif (WIN32)

# For more portable testing (PR 544430):
# 1) use relative dirs within parent build dir
if (USE_DRSYMS)
  file(RELATIVE_PATH bin_relative "${CMAKE_CURRENT_BINARY_DIR}"
    "${PROJECT_BINARY_DIR}/${BUILD_BIN_PREFIX}/bin")
else (USE_DRSYMS)
  file(RELATIVE_PATH bin_relative "${CMAKE_CURRENT_BINARY_DIR}"
    "${PROJECT_BINARY_DIR}/${BUILD_BIN_PREFIX}")
endif (USE_DRSYMS)
# 2) parameterize dirs outside of build dir
set(src_param_pattern "{DRMEMORY_CTEST_SRC_DIR}")
set(DR_param_pattern "{DRMEMORY_CTEST_DR_DIR}")

function (get_relative_location target outvar)
  get_target_property(tgtpath ${target} LOCATION${location_suffix})
  # For more portable testing (PR 544430) use relative dirs within parent build dir
  file(RELATIVE_PATH relpath "${CMAKE_CURRENT_BINARY_DIR}" "${tgtpath}")
  if (NOT "${relpath}" MATCHES "^\\.\\.")
    set(relpath "./${relpath}")
  endif()
  set(${outvar} "${relpath}" PARENT_SCOPE)
endfunction (get_relative_location)

if (UNIX)
  set(cmd_shell ${bin_relative}/${toolname}.pl)
else (UNIX)
  if (PERL_TO_EXE OR USE_DRSYMS)
    set(cmd_shell ${bin_relative}/${toolname}.exe)
  else (PERL_TO_EXE OR USE_DRSYMS)
    find_program(PERL perl)
    if (NOT PERL)
      message(FATAL_ERROR "cannot find perl.exe")
    endif (NOT PERL)
    set(cmd_shell ${PERL} ${bin_relative}/${toolname}.pl)
  endif (PERL_TO_EXE OR USE_DRSYMS)

  # FIXME PR 406287: with /MDd, the app somehow gets an exception, and
  # though the app's output looks normal, Dr. Memory only reports
  # a bunch of ininit accesses by NtContinue.  Disabling /MDd for now.
  # Also, /MTd results in the debug heap code throwing an exception
  # when malloc.exe does free(0x1234).
  # We also avoid msvcrt*.dll differences by using static libc (/MT).
  string(TOUPPER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_UPPER)
  string(REGEX REPLACE "/MDd?" "/MT" CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}
    "${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")
  string(REGEX REPLACE "/MDd?" "/MT" CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER}
    "${CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")
  # With /MT, cs2bug.cpp gets link errors with libcpmtd.lib so we remove _DEBUG:
  string(REGEX REPLACE "/D_DEBUG" "" CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER}
    "${CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")
  string(REGEX REPLACE "/O2" "/Od" CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}
    "${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")
  # removing RTC really just for tests/unload
  string(REGEX REPLACE "/RTC1" "" CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}
    "${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")
  if (NOT DEBUG_BUILD)
    if ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
      foreach (var C;CXX;EXE_LINKER;MODULE_LINKER;SHARED_LINKER)
        set(CMAKE_${var}_FLAGS_RELEASE ${CMAKE_${var}_FLAGS_DEBUG})
        set(CMAKE_${var}_FLAGS_RELWITHDEBINFO ${CMAKE_${var}_FLAGS_DEBUG})
      endforeach ()
    endif ()
  endif (NOT DEBUG_BUILD)
endif (UNIX)
if (DEBUG_BUILD)
  # use debug DR as well to catch asserts there
  set(dbg_args "-debug;-dr_debug")
else (DEBUG_BUILD)
  set(dbg_args "")
endif (DEBUG_BUILD)
if (WIN32)
  # we need the nudge notification msgs
  # we want core dumps on asserts, etc.
  set(default_dr_ops "-dumpcore_mask 0x87fd -stderr_mask 15 -msgbox_mask 0")
else (WIN32)
  # stderr_mask 15 is the default for debug build, and we don't want to go
  # over option buffer limit on esxi
  set(default_dr_ops "-dumpcore_mask 0")
endif (WIN32)
set(cmd_base ${cmd_shell} ${dbg_args} -dr ${DR_param_pattern}/..)
if (NOT TOOL_DR_HEAPSTAT)
  set(cmd_base ${cmd_base} -batch)
endif (NOT TOOL_DR_HEAPSTAT)
# there's no easy way to set a cmake or env var for running
# from build dir to make runtest.cmake have a relative path so we
# copy to build dir
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/runtest.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/runtest.cmake" COPYONLY)
set(cmd_script -P "./runtest.cmake")

# test_ops and drmem_ops should have words separated by ; so they'll
# be separate arguments on the cmdline, while dr_ops should be
# separated by spaces and will remain a single arg.
# be wary of trailing spaces or extra spaces: could cause problems.
# Note: For args with spaces (or multiple args) passed via drmem_ops a ;
# should be used instead of each space.  Otherwise, the whole of
# drmem_ops is passed in as a single argument, which results in
# options parsing errors in drmemory.pl and drmem client.
# The postprocess arg is a bool that applies only for Dr. Memory:
# whether to run the front-end with -results after the app is run.
function(newtest_nobuild test exe test_ops drmem_ops dr_ops postprocess)
  get_relative_location(${exe} exepath)

  set(cmd ${cmd_base})
  if (NOT "${dr_ops}" STREQUAL "")
    set(cmd ${cmd} -dr_ops "${default_dr_ops} ${dr_ops}")
  else()
    set(cmd ${cmd} -dr_ops "${default_dr_ops}")
  endif ()
  # script ops last since using as hack for nudge test app
  # we request callstacks w/ file:line on separate line for matching our templates
  # we include absaddr and mod+offs for easier debugging of problems
  set(drmem_ops -callstack_style 0x27 ${drmem_ops})
  if (NOT "${drmem_ops}" STREQUAL "")
    set(cmd ${cmd} ${drmem_ops})
  endif ()
  if ("${exepath}" MATCHES "run_in_bg")
    # unfortunately we have to hardcode support here: if we run drmemory.pl
    # as the command, cmake waits for its direct children to exit (including
    # postprocess.pl): instead we run run_in_bg as the primary app, which
    # makes it much easier to run drmemory.pl in the background.
    set(cmd ${exepath} ${test_ops} ${cmd})
    if (WIN32)
      # run_in_bg spawns perl.exe and perl then re-parses the args, so we need
      # extra quotes.  '' works for cygwin perl but not ActiveState: "" works
      # for both (PR 506111)
      string(REGEX REPLACE ";-dr_ops;([^;]+);" ";-dr_ops;\"\\1\";" cmd "${cmd}")
    endif (WIN32)
  else ()
    set(cmd ${cmd} -- ${exepath})
    if (NOT "${test_ops}" STREQUAL "")
      set(cmd ${cmd} ${test_ops})
    endif ()
  endif ()
  # pass intra-arg spaces via @@ and inter-arg via @
  # to get around the pain of trying to quote everything just right:
  # much simpler this way.
  string(REGEX REPLACE " " "@@" cmd "${cmd}")
  string(REGEX REPLACE ";" "@" cmd "${cmd}")
  string(REGEX REPLACE " " "@@" nudge "${cmd_base}")
  string(REGEX REPLACE ";" "@" nudge "${nudge}")
  if (TOOL_DR_HEAPSTAT)
    # XXX: this works manually but doesn't seem to get through ctest: but
    # the test is passing so not taking the time to figure it out
    set(postcmd "${cmd_base};-view_leaks;-callstack_modname_hide '';-callstack_style 0x21;-x;${exepath};-profdir")
  else (TOOL_DR_HEAPSTAT)
    if (postprocess)
      # test -skip_results + -results (PR 575481)
      set(postcmd "${cmd_base};-results")
    else (postprocess)
      set(postcmd "")
    endif (postprocess)
  endif (TOOL_DR_HEAPSTAT)
  string(REGEX REPLACE " " "@@" postcmd "${postcmd}")
  string(REGEX REPLACE ";" "@" postcmd "${postcmd}")
  add_test(${test} ${CMAKE_COMMAND}
    -D cmd:STRING=${cmd}
    -D TOOL_DR_HEAPSTAT:BOOL=${TOOL_DR_HEAPSTAT}
    -D outpat:STRING=${src_param_pattern}/${test}.out
    -D respat:STRING=${src_param_pattern}/${test}.res
    -D nudge:STRING=${nudge}
    -D VMKERNEL:BOOL=${VMKERNEL}
    -D USE_DRSYMS:BOOL=${USE_DRSYMS}
    -D toolbindir:STRING=${DR_param_pattern}/../bin32
    -D DRMEMORY_CTEST_SRC_DIR:STRING=${CMAKE_CURRENT_SOURCE_DIR}
    -D DRMEMORY_CTEST_DR_DIR:STRING=${DynamoRIO_DIR}
    -D CMAKE_SYSTEM_VERSION:STRING=${CMAKE_SYSTEM_VERSION}
    # runtest.cmake will add the -profdir arg
    -D postcmd:STRING=${postcmd}
    ${cmd_script})
endfunction(newtest_nobuild)

function(newtest_ex test source test_ops drmem_ops dr_ops postprocess)
  tobuild(${test} ${source})
  newtest_nobuild(${test} ${test} "${test_ops}" "${drmem_ops}" "${dr_ops}" ${postprocess})
endfunction(newtest_ex)

function(newtest test source)
  newtest_ex(${test} ${source} "" "" "" OFF)
endfunction(newtest)

function(newtest_custbuild test source cust_flags)
  newtest_ex(${test} ${source} "" "" "" OFF)
  get_target_property(cur_flags ${test} COMPILE_FLAGS)
  set_target_properties(${test} PROPERTIES COMPILE_FLAGS "${cur_flags} ${cust_flags}")
endfunction(newtest_custbuild)

newtest(hello hello.c)
newtest(malloc malloc.c)
newtest(free free.c)
newtest(registers registers.c)
# linux glibc backtrace on hashtable curiosities causing problems:
# * making syscalls => hit sysenter hook
# * w/ -sysenter_is_int80 => calls abort() for some reason
newtest_ex(cs2bug cs2bug.cpp "" "" "" OFF)
newtest(float float.c)
newtest(selfmod selfmod.c)
newtest(patterns patterns.c)

if (UNIX)
  newtest(signal signal.c)
  target_link_libraries(signal m)
  if (NOT VMKERNEL)
    # PR 468352: SYS_clone w/o CLONE_SETTLS not supported on ESXi
    newtest(clone clone.c)
  endif (NOT VMKERNEL)
  get_relative_location(malloc malloc_path)
  newtest_ex(execve execve.c "${malloc_path}" "" "" OFF)
  newtest(pthreads pthreads.c)
  target_link_libraries(pthreads pthread)
  tobuild_lib(loaderlib loader.lib.c "" "")
  get_relative_location(loaderlib loaderlib_path)
  newtest_ex(loader loader.c "${loaderlib_path}" "" "" OFF)
  target_link_libraries(loader dl)
else (UNIX)
  newtest(winthreads winthreads.c)
endif (UNIX)

if (UNIX)
  tobuild_lib(unloadlib unload.lib.c "-fno-builtin" "")
else (UNIX)
  tobuild_lib(unloadlib unload.lib.c "" "/nodefaultlib /noentry")
endif (UNIX)
get_relative_location(unloadlib unloadlib_path)
newtest_ex(unload unload.c "${unloadlib_path}" "" "" OFF)
if (UNIX)
  target_link_libraries(unload dl)
endif (UNIX)

if (NOT TOOL_DR_HEAPSTAT)
  # PR 525807: test malloc stacks
  newtest(varstack varstack.c)

  # PR 464804: test runtime options
  # FIXME: we should set up a suite like DR uses.  For now hand-picking
  # a few to run w/ options.
  newtest_nobuild(leaks-only malloc "" "-leaks_only" "" OFF)
  newtest_nobuild(slowpath registers "" "-no_fastpath" "" OFF)
  newtest_nobuild(slowesp registers "" "-no_esp_fastpath" "" OFF)
  newtest_nobuild(addronly free "" "-no_check_uninitialized" "" OFF)

  # shared by all suppress tests
  tobuild(suppress suppress.c)

  # test suppress wildcards
  if (UNIX)
    if (VMKERNEL)
      set(supp_fileA "{DRMEMORY_CTEST_SRC_DIR}/suppress.vmk.suppress")
      set(supp_fileB "{DRMEMORY_CTEST_SRC_DIR}/suppress.vmk.suppress")
    else (VMKERNEL)
      set(supp_fileA "{DRMEMORY_CTEST_SRC_DIR}/suppress.lin.suppress")
      set(supp_fileB "{DRMEMORY_CTEST_SRC_DIR}/suppressB.lin.suppress")
    endif (VMKERNEL)
  else (UNIX)
    set(supp_fileA "{DRMEMORY_CTEST_SRC_DIR}/suppress.win.suppress")
    set(supp_fileB "{DRMEMORY_CTEST_SRC_DIR}/suppressB.win.suppress")
  endif (UNIX)
  # test multiple supp files (i#574)
  if (USE_DRSYMS)
    newtest_nobuild(suppress suppress ""
      "-suppress;${supp_fileA};-suppress;${supp_fileB};-callstack_modname_hide;;" "" OFF)
  else (USE_DRSYMS)
    newtest_nobuild(suppress suppress ""
      "-suppress;${supp_fileA};-suppress;${supp_fileB}" "" OFF)
  endif (USE_DRSYMS)

  # i#80: test suppression file generation and use via multiple runs
  # since we need the name of the suppress file, runtest.cmake must do
  # the second run.  it looks for "suppress" with no "-suppress" option,
  # rather than taking explicit params, and for the 2nd run uses the
  # suppress output files
  if (USE_DRSYMS)
    newtest_nobuild(suppress-genoffs suppress ""
      "-no_gen_suppress_syms;-callstack_modname_hide;;" "" OFF)
    newtest_nobuild(suppress-gensyms suppress ""
      "-no_gen_suppress_offs;-callstack_modname_hide;;" "" OFF)
  else (USE_DRSYMS)
    newtest_nobuild(suppress-genoffs suppress "" "-no_gen_suppress_syms" "" OFF)
    newtest_nobuild(suppress-gensyms suppress "" "-no_gen_suppress_offs" "" OFF)
  endif (USE_DRSYMS)

  set(nudge_test_args "")

  if (UNIX)
    # test -skip_results + -results (PR 575481)
    newtest_nobuild(skip-results malloc "" "-skip_results" "" ON)
  endif (UNIX)

  # For -perturb_only we do not have a .res file so that runtest.cmake
  # won't wait for a message showing that results are ready
  if (UNIX)
    newtest_nobuild(perturb pthreads "" "-perturb_only" "" OFF)
  else (UNIX)
    newtest_nobuild(perturb winthreads  "" "-perturb_only" "" OFF)
  endif (UNIX)

  if (WIN32)
    newtest(wincrt wincrt.cpp)
    if (USE_DRSYMS)
      # cygwin build can't see static malloc routines
      newtest_custbuild(wincrtdbg wincrt.cpp "/MTd")
      newtest_custbuild(malloccrt malloc.c "/MTd")
    endif (USE_DRSYMS)
    # FIXME PR 406287: add /MDd test
  endif (WIN32)

  newtest(realloc realloc.c)
  if (UNIX)
    target_link_libraries(realloc pthread)
  endif (UNIX)

  if (UNIX)
    newtest(memalign memalign.c)
  endif (UNIX)

else (NOT TOOL_DR_HEAPSTAT)
  newtest_ex(stale stale.c "" "-staleness;-stale_granularity 100" "" OFF)

  newtest_nobuild(time-allocs malloc "" "-time_allocs" "" OFF)
  newtest_nobuild(time-bytes malloc "" "-time_bytes" "" OFF)
  newtest_nobuild(time-instrs malloc "" "-time_instrs" "" OFF)
  newtest_nobuild(dump malloc "" "-dump" "" OFF)

  set(nudge_test_args "")
endif (NOT TOOL_DR_HEAPSTAT)

# nudge test: runs infloop in background and runtest.cmake nudges it
tobuild(infloop infloop.c)
get_relative_location(infloop infloop_path)
# we have special support to put run_in_bg and its args first, so we put
# the test to run as a final drmem arg
newtest_nobuild(nudge run_in_bg_tgt
  "-out;./nudge-out"
  "${nudge_test_args}--;${infloop_path}" "" OFF)

newtest(leakcycle leakcycle.cpp)

add_subdirectory(app_suite)
