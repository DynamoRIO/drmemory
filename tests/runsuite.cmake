# **********************************************************
# Copyright (c) 20011 Google, Inc.  All rights reserved.
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
    set(runsuite_include_path "${CTEST_SCRIPT_DIRECTORY}/../dynamorio/cmake")
  endif (NOT "${DR_path}" STREQUAL "")
endif (NOT arg_vmk_only)

if (arg_vmk_only OR arg_test_vmk)
  if (NOT EXISTS "${DRvmk_path}")
    message(FATAL_ERROR "cannot find DynamoRIO VMKERNEL build at ${DRvmk_path}")
    set(runsuite_include_path "${DRvmk_path}")
  endif (NOT EXISTS "${DRvmk_path}")
endif (arg_vmk_only OR arg_test_vmk)

set(CTEST_PROJECT_NAME "Dr. Memory")
set(cpack_project_name "DrMemory")
set(run_tests ON)
set(CTEST_SOURCE_DIRECTORY "${CTEST_SCRIPT_DIRECTORY}/..")
include("${runsuite_include_path}/runsuite_common_pre.cmake")

# run cygwin tests only if cygwin is installed
set(test_cygwin ${have_cygwin}) # have_cygwin set by runsuite_common_pre.cmake

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
      ${tool}
      ${DR_entry}
      CMAKE_BUILD_TYPE:STRING=Debug
      " OFF ON "")
    testbuild_ex("${name}-rel-32" OFF "
      ${tool}
      ${DR_entry}
      CMAKE_BUILD_TYPE:STRING=Release
      " ON ON "") # only run release tests for long suite
  endif (NOT arg_vmk_only)
  if (UNIX)
    if (arg_vmk_only OR arg_test_vmk)
      testbuild_ex("${name}-vmk-dbg-32" OFF "
        ${tool}
        DynamoRIO_DIR:PATH=${DRvmk_path}
        CMAKE_BUILD_TYPE:STRING=Debug
        VMKERNEL:BOOL=ON
        " OFF ON "")
      testbuild_ex("${name}-vmk-rel-32" OFF "
        ${tool}
        DynamoRIO_DIR:PATH=${DRvmk_path}
        CMAKE_BUILD_TYPE:STRING=Release
        VMKERNEL:BOOL=ON
        " ON ON "") # only run release tests for long suite
    endif (arg_vmk_only OR arg_test_vmk)
  else (UNIX)
    if ("${tool}" MATCHES "MEMORY" AND test_cygwin)
      # No online symbol support for cygwin yet so using separate build
      # with postprocess model (PR 561181)
      testbuild("${name}-cygwin-dbg-32" OFF "
        ${tool}
        ${DR_entry}
        CMAKE_BUILD_TYPE:STRING=Debug
        USE_DRSYMS:BOOL=OFF
        ")
      testbuild_ex("${name}-cygwin-rel-32" OFF "
        ${tool}
        ${DR_entry}
        CMAKE_BUILD_TYPE:STRING=Release
        USE_DRSYMS:BOOL=OFF
        " ON OFF "") # only run release tests for long suite
    endif ("${tool}" MATCHES "MEMORY" AND test_cygwin)
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
  string(REGEX MATCHALL "[^\n]*ASSERT[^\n]*\n[^\n]*\n[^\n\\*]*"
    drmem_assert "${str}")
  string(REGEX MATCHALL "[^\n]*Unrecoverable[^\n]*" crash "${str}")
  string(REGEX MATCHALL "[^\n]*Internal DynamoRIO Error[^\n]*" 
    assert "${str}")
  string(REGEX MATCHALL "[^\n]*CURIOSITY[^\n]*" curiosity "${str}")
  string(REGEX REPLACE "^.*<Name>([^<]+)<.*$" "\\1" name "${str}")
  if (drmem_assert OR crash OR assert OR curiosity)
    string(REGEX REPLACE "[ \t]*<Value>" "" assert "${assert}")
    set(${outvar} "=> ${drmem_assert} ${crash} ${assert} ${curiosity}" PARENT_SCOPE)
  else (drmem_assert OR crash OR assert OR curiosity)
    set(${outvar} "" PARENT_SCOPE)
  endif (drmem_assert OR crash OR assert OR curiosity)
endfunction (error_string)

include("${runsuite_include_path}/runsuite_common_post.cmake")
