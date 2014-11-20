# **********************************************************
# Copyright (c) 2010-2014 Google, Inc.  All rights reserved.
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

cmake_minimum_required (VERSION 2.2)

# custom args beyond the base runsuite_common_pre.cmake:
# arguments are a ;-separated list (must escape as \; from ctest_run_script())
set(arg_test_vmk OFF) # for testing of ESXi on Linux: run vmk builds
set(arg_vmk_only  OFF) # for testing on ESXi: run only vmk builds
set(arg_drmemory_only OFF)   # only run Dr. Memory tests
set(arg_drheapstat_only OFF) # only run Dr. Heapstat tests
set(DR_path "")       # path to DynamoRIO cmake dir; if this arg is not set or
                      # doesn't exist, will build DynamoRIO from local copy
set(DRvmk_path "")    # path to DynamoRIO VMKERNEL build cmake dir;
                      # ../exports_vmk/cmake will be used as a default

set(DRvmk_path "${CTEST_SCRIPT_DIRECTORY}/../../../exports_vmk/cmake") # default

foreach (arg ${CTEST_SCRIPT_ARG})
  if (${arg} STREQUAL "test_vmk")
    set(arg_test_vmk ON)
  endif (${arg} STREQUAL "test_vmk")
  if (${arg} STREQUAL "vmk_only")
    set(arg_vmk_only ON)
  endif (${arg} STREQUAL "vmk_only")
  if (${arg} STREQUAL "drmemory_only")
    set(arg_drmemory_only ON)
  endif (${arg} STREQUAL "drmemory_only")
  if (${arg} STREQUAL "drheapstat_only")
    set(arg_drheapstat_only ON)
  endif (${arg} STREQUAL "drheapstat_only")
  if (${arg} MATCHES "^DR=")
    string(REGEX REPLACE "^DR=" "" DR_path "${arg}")
  endif (${arg} MATCHES "^DR=")
  if (${arg} MATCHES "^dr=")
    string(REGEX REPLACE "^dr=" "" DR_path "${arg}")
  endif (${arg} MATCHES "^dr=")
  if (UNIX)
    if (${arg} MATCHES "^DRvmk=")
      string(REGEX REPLACE "^DRvmk=" "" DRvmk_path "${arg}")
    endif (${arg} MATCHES "^DRvmk=")
  endif (UNIX)
endforeach (arg)

if (arg_test_vmk AND arg_vmk_only)
  message(FATAL_ERROR "you can't specify both test_vmk and vmk_only")
endif (arg_test_vmk AND arg_vmk_only)

set(DR_entry "")
if (NOT arg_vmk_only)
  if (NOT "${DR_path}" STREQUAL "")
    if (NOT EXISTS "${DR_path}")
      message(FATAL_ERROR "cannot find DynamoRIO build at ${DR_path}")
    endif (NOT EXISTS "${DR_path}")
    set(DR_entry "DynamoRIO_DIR:PATH=${DR_path}")
    set(runsuite_include_path "${DR_path}")
    # else will build from local sources
    # XXX: we could share the first DR local build w/ later drmem builds:
    # for now, if user wants faster suite, must build DR separately first
    # and point at it
  else (NOT "${DR_path}" STREQUAL "")
    # include from source instead of exports dir
    set(runsuite_include_path "${CTEST_SCRIPT_DIRECTORY}/../dynamorio/suite")
  endif (NOT "${DR_path}" STREQUAL "")
endif (NOT arg_vmk_only)

if (arg_vmk_only OR arg_test_vmk)
  if (NOT EXISTS "${DRvmk_path}")
    message(FATAL_ERROR "cannot find DynamoRIO VMKERNEL build at ${DRvmk_path}")
    set(runsuite_include_path "${DRvmk_path}")
  endif (NOT EXISTS "${DRvmk_path}")
endif (arg_vmk_only OR arg_test_vmk)

set(CTEST_PROJECT_NAME "DrMemory")
set(cpack_project_name "DrMemory")
set(run_tests ON)
set(CTEST_SOURCE_DIRECTORY "${CTEST_SCRIPT_DIRECTORY}/..")
if (APPLE)
  # For now we just run a few tests with labels.
  # XXX i#58: get all the tests working.
  set(extra_ctest_args INCLUDE_LABEL OSX)
endif ()
include("${runsuite_include_path}/runsuite_common_pre.cmake")


##################################################
# pre-commit source file checks
file(GLOB_RECURSE cfiles
  ${CTEST_SOURCE_DIRECTORY}/*)
foreach (cfile ${cfiles})
  if (NOT "${cfile}" MATCHES "dynamorio/" AND
      NOT "${cfile}" MATCHES "\\.git/" AND
      NOT "${cfile}" MATCHES "\\.svn/" AND
      NOT "${cfile}" MATCHES "third_party/" AND
      NOT "${cfile}" MATCHES "\\.png$" AND
      NOT "${cfile}" MATCHES "~$" AND
      NOT "${cfile}" MATCHES "runsuite\\.cmake$")
    file(READ "${cfile}" string)

    # Check for NL instead of \n in NOTIFY*
    string(REGEX MATCH "NOTIFY[^(\n]*\\([^)]*\\\\n" match "${string}")
    if (NOT "${match}" STREQUAL "")
      message(FATAL_ERROR "In ${cfile}, use NL macro, not \\n, for NOTIFY string: ${match}")
    endif ()

    # Check for NOCHECKIN
    string(REGEX MATCH "NOCHECKIN" match "${string}")
    if (NOT "${match}" STREQUAL "")
      if (NOT "${cfile}" MATCHES "codereview\\.cmake$")
        message(FATAL_ERROR "In ${cfile}, remove NOCHECKIN: ${match}")
      endif ()
    endif ()

    # Check for trailing space
    string(REGEX MATCH " \n" match "${string}")
    if (NOT "${match}" STREQUAL "")
      # Get more context
      string(REGEX MATCH "\n[^\n]* \n" match "${string}")
      message(FATAL_ERROR "In ${cfile}, remove trailing space: ${match}")
    endif ()

    # Check for CR.  Unfortunately file(READ) seems to throw away CR's
    # so we resort to perl.  Dev must run suite on Linux where perl
    # is likely to be found.
    include(FindPerl)
    if (PERL_FOUND)
      execute_process(COMMAND
        ${PERL} -n -e "print $_ if (/\\r\\n/);" "${cfile}"
        RESULT_VARIABLE perl_result
        ERROR_QUIET
        OUTPUT_VARIABLE perl_out)
      if (NOT perl_result)
        if (NOT "${perl_out}" STREQUAL "")
          string(REGEX MATCHALL "\n" perl_lines "${perl_out}")
          list(LENGTH perl_lines num_perl_lines)
          message(FATAL_ERROR "${cfile} has ${num_perl_lines} DOS line endings")
        endif ()
      endif ()
    endif ()

  endif ()
endforeach ()
##################################################


# i#1099: avoid absolute path complaint on package build step
set(base_cache "BUILDING_PACKAGE:BOOL=ON")

set(tools "")
# build drmemory last, so our package is a drmem package
if (NOT arg_drmemory_only)
  set(tools ${tools} "TOOL_DR_HEAPSTAT:BOOL=ON")
endif ()
if (NOT arg_drheapstat_only)
  # this var is ignored but easier to read than having ""
  set(tools ${tools} "TOOL_DR_MEMORY:BOOL=ON")
endif ()
foreach (tool ${tools})
  if ("${tool}" MATCHES "HEAPSTAT")
     set(name "drheapstat")
  else ("${tool}" MATCHES "HEAPSTAT")
     set(name "drmemory")
  endif ("${tool}" MATCHES "HEAPSTAT")

  if (NOT arg_vmk_only)
    testbuild_ex("${name}-dbg-32" OFF "
      ${base_cache}
      ${tool}
      ${DR_entry}
      CMAKE_BUILD_TYPE:STRING=Debug
      " OFF ON "")
    testbuild_ex("${name}-rel-32" OFF "
      ${base_cache}
      ${tool}
      ${DR_entry}
      CMAKE_BUILD_TYPE:STRING=Release
      " OFF ON "") # we do run some release tests in short suite
    # DRi#58: core DR does not yet support 64-bit Mac
    if ("${tool}" MATCHES "MEMORY" AND NOT APPLE)
      testbuild_ex("${name}-dbg-64" ON "
        ${base_cache}
         ${tool}
         ${DR_entry}
         CMAKE_BUILD_TYPE:STRING=Debug
         " OFF ON "")
      testbuild_ex("${name}-rel-64" ON "
        ${base_cache}
         ${tool}
         ${DR_entry}
         CMAKE_BUILD_TYPE:STRING=Release
         " OFF ON "")
    endif ()
  endif (NOT arg_vmk_only)
  if (UNIX)
    if (arg_vmk_only OR arg_test_vmk)
      testbuild_ex("${name}-vmk-dbg-32" OFF "
        ${base_cache}
        ${tool}
        DynamoRIO_DIR:PATH=${DRvmk_path}
        CMAKE_BUILD_TYPE:STRING=Debug
        VMKERNEL:BOOL=ON
        " OFF ON "")
      testbuild_ex("${name}-vmk-rel-32" OFF "
        ${base_cache}
        ${tool}
        DynamoRIO_DIR:PATH=${DRvmk_path}
        CMAKE_BUILD_TYPE:STRING=Release
        VMKERNEL:BOOL=ON
        " ON ON "") # only run release tests for long suite
    endif (arg_vmk_only OR arg_test_vmk)
  endif (UNIX)
endforeach (tool)

if (NOT arg_vmk_only AND NOT arg_already_built)
  set(build_package ON)
else ()
  set(build_package OFF)
endif ()

# sets ${outvar} in PARENT_SCOPE
function (error_string str outvar)
  # DrMem assert somehow gets split across 3 lines
  string(REGEX MATCHALL "[^\n]*ASSERT[^\n]*\n[^\n]*\n[^\n\\*]*" reason "${str}")
  if (NOT reason)
    string(REGEX MATCHALL "[^\n]*Unrecoverable[^\n]*" reason "${str}")
    if (NOT reason)
      string(REGEX MATCHALL "[^\n]*Internal DynamoRIO Error[^\n]*" reason "${str}")
      if (NOT reason)
        string(REGEX MATCHALL "[^\n]*CURIOSITY[^\n]*" reason "${str}")
        if (NOT reason)
          # % is what is inserted to identify the </Measurement>
          string(REGEX MATCHALL "[^\n]*failed to match[^%]*instead" reason "${str}")
        endif (NOT reason)
      endif (NOT reason)
    endif (NOT reason)
  endif (NOT reason)
  string(REGEX REPLACE "^.*<Name>([^<]+)<.*$" "\\1" name "${str}")
  if (reason)
    string(REGEX REPLACE "[ \t]*<Value>" "" reason "${reason}")
    string(REGEX REPLACE "(\r?\n)" "\\1\t\t" reason "${reason}")
    set(${outvar} "=> ${reason}" PARENT_SCOPE)
  else (reason)
    set(${outvar} "" PARENT_SCOPE)
  endif (reason)
endfunction (error_string)

include("${runsuite_include_path}/runsuite_common_post.cmake")
