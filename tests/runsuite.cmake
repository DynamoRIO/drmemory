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

# **********************************************************
# Copyright (c) 2009 VMware, Inc.    All rights reserved.
# **********************************************************

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# * Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
# 
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# 
# * Neither the name of VMware, Inc. nor the names of its contributors may be
#   used to endorse or promote products derived from this software without
#   specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.

cmake_minimum_required (VERSION 2.2)
set(cmake_ver_string
  "${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION}.${CMAKE_RELEASE_VERSION}")

# arguments are a ;-separated list (must escape as \; from ctest_run_script())
set(arg_nightly OFF)  # whether to report the results
set(arg_long OFF)     # whether to run the long suite
set(arg_already_built OFF) # for testing on ESXi w/ already-built suite
set(arg_test_vmk OFF) # for testing of ESXi on Linux: run vmk builds
set(arg_vmk_only  OFF) # for testing on ESXi: run only vmk builds
set(arg_include "")   # cmake file to include up front
set(arg_preload "")   # cmake file to include prior to each 32-bit build
set(arg_preload64 "") # cmake file to include prior to each 64-bit build
set(arg_exclude "")   # regex of tests to exclude
set(arg_site "")      # site name when reporting results
set(arg_drmemory_only OFF)   # only run Dr. Memory tests
set(arg_drheapstat_only OFF) # only run Dr. Heapstat tests
set(arg_ssh OFF)      # running over cygwin ssh: disable pdbs
set(DR_path "")       # path to DynamoRIO cmake dir; if this arg is not set or
                      # doesn't exist, will build DynamoRIO from local copy
set(DRvmk_path "")    # path to DynamoRIO VMKERNEL build cmake dir;
                      # ../exports_vmk/cmake will be used as a default
set(arg_use_nmake OFF) # use nmake even if gnu make is present

set(DRvmk_path "${CTEST_SCRIPT_DIRECTORY}/../../../exports_vmk/cmake") # default

foreach (arg ${CTEST_SCRIPT_ARG})
  if (${arg} STREQUAL "nightly")
    set(arg_nightly ON)
  endif (${arg} STREQUAL "nightly")
  if (${arg} STREQUAL "long")
    set(arg_long ON)
  endif (${arg} STREQUAL "long")
  if (${arg} STREQUAL "already_built")
    set(arg_already_built ON)
  endif (${arg} STREQUAL "already_built")
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
  if (${arg} MATCHES "^include=")
    string(REGEX REPLACE "^include=" "" arg_include "${arg}")
  endif (${arg} MATCHES "^include=")
  if (${arg} MATCHES "^preload=")
    string(REGEX REPLACE "^preload=" "" arg_preload "${arg}")
  endif (${arg} MATCHES "^preload=")
  if (${arg} MATCHES "^preload64=")
    string(REGEX REPLACE "^preload64=" "" arg_preload64 "${arg}")
  endif (${arg} MATCHES "^preload64=")
  if (${arg} MATCHES "^exclude=")
    # not parallel to include=.  this excludes individual tests.
    string(REGEX REPLACE "^exclude=" "" arg_exclude "${arg}")
  endif (${arg} MATCHES "^exclude=")
  if (${arg} MATCHES "^site=")
    string(REGEX REPLACE "^site=" "" arg_site "${arg}")
  endif (${arg} MATCHES "^site=")
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
  if (${arg} STREQUAL "ssh")
    set(arg_ssh ON)
  endif (${arg} STREQUAL "ssh")
  if (${arg} MATCHES "^use_nmake")
    set(arg_use_nmake ON)
  endif ()
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
    # else will build from local sources
    # XXX: we could share the first DR local build w/ later drmem builds:
    # for now, if user wants faster suite, must build DR separately first
    # and point at it
  endif (NOT "${DR_path}" STREQUAL "")
endif (NOT arg_vmk_only)

if (arg_vmk_only OR arg_test_vmk)
  if (NOT EXISTS "${DRvmk_path}")
    message(FATAL_ERROR "cannot find DynamoRIO VMKERNEL build at ${DRvmk_path}")
  endif (NOT EXISTS "${DRvmk_path}")
endif (arg_vmk_only OR arg_test_vmk)

if (WIN32)
  # build and run cygwin only if cygwin is installed
  find_program(CYGPATH cygpath)
  if (CYGPATH)
    set(have_cygwin ON)
    set(test_cygwin ON)
  else (CYGPATH)
    set(have_cygwin OFF)
    set(test_cygwin OFF)
  endif (CYGPATH)
endif (WIN32)

if (WIN32 AND NOT arg_use_nmake)
  find_program(MAKE_COMMAND make DOC "make command")
  if (NOT make)
    set(arg_use_nmake ON)
  endif (NOT make)
endif (WIN32 AND NOT arg_use_nmake)

# allow setting the base cache variables via an include file
set(base_cache "")
if (arg_include)
  message("including ${arg_include}")
  include(${arg_include})
endif (arg_include)
set(aux_cache "")
if (arg_ssh)
  # avoid problems creating pdbs as cygwin ssh user (DR i#310)
  set(aux_cache "${aux_cache}
    GENERATE_PDBS:BOOL=OFF")
endif (arg_ssh)

if (arg_long)
  set(TEST_LONG ON)
else (arg_long)
  set(TEST_LONG OFF)
endif (arg_long)

get_filename_component(BINARY_BASE "." ABSOLUTE)

if (arg_nightly)
  # FIXME: not yet supported: currently just using DynamoRIO framework here
  # i#11: nightly run
  # Caller should have set CTEST_SITE via site= arg
  if (arg_site)
    set(CTEST_SITE "${arg_site}")
  else (arg_site)
    message(FATAL_ERROR "must set sitename via site= arg")
  endif (arg_site)

  set(CTEST_DASHBOARD_ROOT "${BINARY_BASE}")

  # We assume a manual check out was done, and that CTest can just do "update".
  # If we want a fresh checkout we can set CTEST_BACKUP_AND_RESTORE
  # and CTEST_CHECKOUT_COMMAND but the update should be fine.
  # FIXME: p4 is not officially supported by ctest
  find_program(CTEST_UPDATE_COMMAND p4 DOC "source code update command")

  set(SUITE_TYPE Nightly)
  set(DO_UPDATE ON)
  set(DO_SUBMIT ON)
  set(SUBMIT_LOCAL OFF)
else (arg_nightly)
  # a local run, not a nightly
  set(SUITE_TYPE Experimental)
  set(DO_UPDATE OFF)
  set(DO_SUBMIT ON)
  set(SUBMIT_LOCAL ON)
  # CTest does "scp file ${CTEST_DROP_SITE}:${CTEST_DROP_LOCATION}" so for
  # local copy w/o needing sshd on localhost we arrange to have : in the
  # absolute filepath.  Note that I would prefer having the results inside
  # each build dir, but having : in the build dir name complicates
  # LD_LIBRARY_PATH.
  if (WIN32)
    # Colon not allowed in name so use drive
    string(REGEX MATCHALL "^[A-Za-z]" drive "${BINARY_BASE}")
    string(REGEX REPLACE "^[A-Za-z]:" "" nondrive "${BINARY_BASE}")
    set(CTEST_DROP_SITE "${drive}")
    set(CTEST_DROP_LOCATION "${nondrive}/xmlresults")
    set(RESULTS_DIR "${CTEST_DROP_SITE}:${CTEST_DROP_LOCATION}")
  else (WIN32)
    set(CTEST_DROP_SITE "${BINARY_BASE}/xml")
    set(CTEST_DROP_LOCATION "results")
    set(RESULTS_DIR "${CTEST_DROP_SITE}:${CTEST_DROP_LOCATION}")
  endif (WIN32)
  if (EXISTS "${RESULTS_DIR}")
    file(REMOVE_RECURSE "${RESULTS_DIR}")
  endif (EXISTS "${RESULTS_DIR}")
  file(MAKE_DIRECTORY "${CTEST_DROP_SITE}:${CTEST_DROP_LOCATION}")
endif (arg_nightly)

set(CTEST_SOURCE_DIRECTORY "${CTEST_SCRIPT_DIRECTORY}/..")
# CTest goes and does our builds and then wants to configure
# and build again and complains there's no top-level setting of
# CTEST_BINARY_DIRECTORY: 
#   "CMake Error: Some required settings in the configuration file were missing:"
# but we don't want to do another build so we just ignore the error.
set(CTEST_CMAKE_COMMAND "${CMAKE_EXECUTABLE_NAME}")
set(CTEST_PROJECT_NAME "Dr. Memory")
set(CTEST_COMMAND "${CTEST_EXECUTABLE_NAME}")
if (UNIX OR NOT arg_use_nmake)
  set(CTEST_CMAKE_GENERATOR "Unix Makefiles")
  find_program(MAKE_COMMAND make DOC "make command")
  if (have_cygwin)
    # seeing errors building in parallel: pdb collision?
    set(CTEST_BUILD_COMMAND_BASE "${MAKE_COMMAND} -j2")
  else (have_cygwin)
    set(CTEST_BUILD_COMMAND_BASE "${MAKE_COMMAND} -j5")
  endif (have_cygwin)
else (UNIX OR NOT arg_use_nmake)
  set(CTEST_CMAKE_GENERATOR "NMake Makefiles")
  find_program(MAKE_COMMAND nmake DOC "nmake command")
  # no -j support
  set(CTEST_BUILD_COMMAND_BASE "${MAKE_COMMAND}")
endif (UNIX OR NOT arg_use_nmake)

# returns the build dir in "last_build_dir"
function(testbuild name is64 initial_cache test_only_in_long)
  set(CTEST_BUILD_NAME "${name}")
  set(CTEST_BUILD_COMMAND "${CTEST_BUILD_COMMAND_BASE}")
  set(CTEST_BINARY_DIRECTORY "${BINARY_BASE}/build_${CTEST_BUILD_NAME}")
  set(last_build_dir "${CTEST_BINARY_DIRECTORY}" PARENT_SCOPE)

  if (NOT arg_already_built)
    # Support other VC installations than VS2005 via pre-build include file.
    # Preserve path so include file can simply prepend each time.
    set(pre_path "$ENV{PATH}")
    if (is64)
      set(preload_file "${arg_preload64}")
    else (is64)
      set(preload_file "${arg_preload}")
    endif (is64)
    if (preload_file)
      # Command-style CTest (i.e., using ctest_configure(), etc.) does
      # not support giving args to CTEST_CMAKE_COMMAND so we are forced
      # to do an include() instead of -C
      include("${preload_file}")
    endif (preload_file)
    set(CTEST_INITIAL_CACHE "${initial_cache}
      ${base_cache}
      ${aux_cache}
      ")
    ctest_empty_binary_directory(${CTEST_BINARY_DIRECTORY})
    file(WRITE "${CTEST_BINARY_DIRECTORY}/CMakeCache.txt" "${CTEST_INITIAL_CACHE}")

    if (WIN32)
      # If other compilers also on path ensure we pick cl
      set(ENV{CC} "cl")
      set(ENV{CXX} "cl")
      # Convert env vars to run proper compiler.
      # Note that this is fragile and won't work with non-standard
      # directory layouts: we assume standard VS2005 or SDK.
      # FIXME: would be nice to have case-insensitive regex flag!
      # For now hardcoding VC, Bin, amd64
      if (is64)
        if (NOT "$ENV{LIB}" MATCHES "[Aa][Mm][Dd]64")
          # Note that we can't set ENV{PATH} as the output var of the replace:
          # it has to be its own set().
          string(REGEX REPLACE "VC([/\\\\])Bin" "VC\\1Bin\\1amd64"
            newpath "$ENV{PATH}")
          set(ENV{PATH} "${newpath}")
          string(REGEX REPLACE "([/\\\\])([Ll][Ii][Bb])" "\\1\\2\\1amd64"
            newlib "$ENV{LIB}")
          set(ENV{LIB} "${newlib}")
          string(REGEX REPLACE "([/\\\\])([Ll][Ii][Bb])" "\\1\\2\\1amd64"
            newlibpath "$ENV{LIBPATH}")
          set(ENV{LIBPATH} "${newlibpath}")
        endif (NOT "$ENV{LIB}" MATCHES "[Aa][Mm][Dd]64")
      else (is64)
        if ("$ENV{LIB}" MATCHES "[Aa][Mm][Dd]64")
          string(REGEX REPLACE "(VC[/\\\\]Bin[/\\\\])amd64" "\\1"
            newpath "$ENV{PATH}")
          set(ENV{PATH} "${newpath}")
          string(REGEX REPLACE "([Ll][Ii][Bb])[/\\\\]amd64" "\\1"
            newlib "$ENV{LIB}")
          set(ENV{LIB} "${newlib}")
          string(REGEX REPLACE "([Ll][Ii][Bb])[/\\\\]amd64" "\\1"
            newlibpath "$ENV{LIBPATH}")
          set(ENV{LIBPATH} "${newlibpath}")
        endif ("$ENV{LIB}" MATCHES "[Aa][Mm][Dd]64")
      endif (is64)
    else (WIN32)
      if (is64)
        set(ENV{CFLAGS} "-m64")
        set(ENV{CXXFLAGS} "-m64")
      else (is64)
        set(ENV{CFLAGS} "-m32")
        set(ENV{CXXFLAGS} "-m32")
      endif (is64)
    endif (WIN32)
  else (NOT arg_already_built)
    # remove the Last* files from the prior run
    file(GLOB lastrun ${CTEST_BINARY_DIRECTORY}/Testing/Temporary/Last*)
    if (lastrun)
      file(REMOVE ${lastrun})
    endif (lastrun)
  endif (NOT arg_already_built)

  ctest_start(${SUITE_TYPE})
  if (NOT arg_already_built)
    if (DO_UPDATE)
      ctest_update(SOURCE "${CTEST_SOURCE_DIRECTORY}")
    endif (DO_UPDATE)
    ctest_configure(BUILD "${CTEST_BINARY_DIRECTORY}")
    ctest_build(BUILD "${CTEST_BINARY_DIRECTORY}")
  endif (NOT arg_already_built)
  if (NOT test_only_in_long OR ${TEST_LONG})
    # to run a subset of tests add an INCLUDE regexp to ctest_test.  e.g.:
    #   INCLUDE broadfun
    if (NOT "${arg_exclude}" STREQUAL "")
      if ("${cmake_ver_string}" STRLESS "2.6.3")
        # EXCLUDE arg to ctest_test() is not available so we edit the list of tests
        file(READ "${CTEST_BINARY_DIRECTORY}/tests/CTestTestfile.cmake" testlist)
        string(REGEX REPLACE "ADD_TEST\\((${arg_exclude}) [^\\)]*\\)\n" ""
          testlist "${testlist}")
        file(WRITE "${CTEST_BINARY_DIRECTORY}/tests/CTestTestfile.cmake" "${testlist}")
      else ("${cmake_ver_string}" STRLESS "2.6.3")
        set(ctest_test_args ${ctest_test_args} EXCLUDE ${arg_exclude})
      endif ("${cmake_ver_string}" STRLESS "2.6.3")
    endif (NOT "${arg_exclude}" STREQUAL "")
    if ("${cmake_ver_string}" STRLESS "2.8.")
      # Parallel tests not supported
    else ()
      # i#111: run tests in parallel, supported on CTest 2.8.0+
      # Note that adding -j to CMAKE_COMMAND does not work, though invoking
      # this script with -j does work, but we want parallel by default.
      set(ctest_test_args ${ctest_test_args} PARALLEL_LEVEL 5)
    endif ()
    ctest_test(BUILD "${CTEST_BINARY_DIRECTORY}" ${ctest_test_args})
  endif ()
  if (DO_SUBMIT)
    # include any notes via set(CTEST_NOTES_FILES )?
    ctest_submit()
  endif (DO_SUBMIT)
  if (NOT arg_already_built)
    set(ENV{PATH} "${pre_path}")
  endif (NOT arg_already_built)

  # PR 534018: pre-commit test suite should build the full package
  # FIXME: perhaps should replace package.cmake w/ invocation of runsuite.cmake
  # w/ certain params, since they're pretty similar at this point?
  # communicate w/ caller
  if (name MATCHES "drmemory")
    # don't build DrHeapstat package: used a drmem build dir
    set(last_drmem_build "${CTEST_BINARY_DIRECTORY}" PARENT_SCOPE)
  endif ()
  # prepend rather than append to get debug first, so we take release
  # files preferentially in case of overlap
  set(cpack_projects 
    "\"${CTEST_BINARY_DIRECTORY};DrMemory;ALL;/\"\n  ${cpack_projects}" PARENT_SCOPE)

endfunction(testbuild)

set(tools "")
if (NOT arg_drheapstat_only)
  # this var is ignored but easier to read than having ""
  set(tools ${tools} "TOOL_DR_MEMORY:BOOL=ON")
endif ()
if (NOT arg_drmemory_only)
  set(tools ${tools} "TOOL_DR_HEAPSTAT:BOOL=ON")
endif ()
foreach (tool ${tools})
  if ("${tool}" MATCHES "HEAPSTAT")
     set(name "drheapstat")
  else ("${tool}" MATCHES "HEAPSTAT")
     set(name "drmemory")
  endif ("${tool}" MATCHES "HEAPSTAT")

  if (NOT arg_vmk_only)
    testbuild("${name}-dbg-32" OFF "
      ${tool}
      ${DR_entry}
      CMAKE_BUILD_TYPE:STRING=Debug
      " OFF)
    testbuild("${name}-rel-32" OFF "
      ${tool}
      ${DR_entry}
      CMAKE_BUILD_TYPE:STRING=Release
      " ON) # only run release tests for long suite
  endif (NOT arg_vmk_only)
  if (UNIX)
    if (arg_vmk_only OR arg_test_vmk)
      testbuild("${name}-vmk-dbg-32" OFF "
        ${tool}
        DynamoRIO_DIR:PATH=${DRvmk_path}
        CMAKE_BUILD_TYPE:STRING=Debug
        VMKERNEL:BOOL=ON
        " OFF)
      testbuild("${name}-vmk-rel-32" OFF "
        ${tool}
        DynamoRIO_DIR:PATH=${DRvmk_path}
        CMAKE_BUILD_TYPE:STRING=Release
        VMKERNEL:BOOL=ON
        " ON) # only run release tests for long suite
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
        " OFF)
      testbuild("${name}-cygwin-rel-32" OFF "
        ${tool}
        ${DR_entry}
        CMAKE_BUILD_TYPE:STRING=Release
        USE_DRSYMS:BOOL=OFF
        " ON) # only run release tests for long suite
    endif ("${tool}" MATCHES "MEMORY" AND test_cygwin)
  endif (UNIX)
endforeach (tool)

if (NOT arg_vmk_only AND NOT arg_already_built)
  # PR 534018: pre-commit test suite should build the full package
  # now package up all the builds
  message("building package in ${last_drmem_build}")
  file(APPEND "${last_drmem_build}/CPackConfig.cmake"
    "set(CPACK_INSTALL_CMAKE_PROJECTS\n  ${cpack_projects})")
  set(CTEST_BUILD_COMMAND "${MAKE_COMMAND} package")
  set(CTEST_BUILD_NAME "final package")
  set(CTEST_BINARY_DIRECTORY "${last_drmem_build}")
  ctest_start(${SUITE_TYPE})
  ctest_build(BUILD "${CTEST_BINARY_DIRECTORY}")
  ctest_submit() # copy into xml dir
endif ()

# workaround for http://www.cmake.org/Bug/view.php?id=9647
# it complains and returns error if CTEST_BINARY_DIRECTORY not set at
# global scope (we do all our real runs inside a function).
set(CTEST_BUILD_NAME "bug9647workaround")
set(CTEST_BINARY_DIRECTORY "${last_build_dir}")
set(CTEST_SOURCE_DIRECTORY "${CTEST_SCRIPT_DIRECTORY}/..")
set(CTEST_COMMAND "${CTEST_EXECUTABLE_NAME}")
# it tries to configure+build, but with a start command it does nothing,
# which is what we want:
ctest_start(${SUITE_TYPE})
# actually it still complains so I'm not sure what version I was using where
# just the start was enough: so we do a test w/ no tests that would match,
# which does work for cmake 2.6, but not for 2.8: grrr
ctest_test(BUILD "${CTEST_BINARY_DIRECTORY}" INCLUDE notestwouldmatchthis)

######################################################################
# SUMMARY

set(outf "${BINARY_BASE}/results.txt")
file(WRITE ${outf} "==================================================\nRESULTS\n\n")
if (arg_already_built)
  file(GLOB all_xml ${RESULTS_DIR}/*Test.xml)
else (arg_already_built)
  # final package sometimes has Configure.xml and sometimes not
  file(GLOB all_xml ${RESULTS_DIR}/*32*Configure.xml ${RESULTS_DIR}/*final*Build.xml)
endif (arg_already_built)
list(SORT all_xml)
foreach (xml ${all_xml})
  get_filename_component(fname "${xml}" NAME_WE)
  string(REGEX REPLACE "^___([^_]+)___.*$" "\\1" build "${fname}")
  file(READ ${xml} string)
  if ("${string}" MATCHES "Configuring incomplete")
    file(APPEND ${outf} "${build}: **** pre-build configure errors ****\n")
  else ("${string}" MATCHES "Configuring incomplete")
    string(REGEX REPLACE "Configure.xml$" "Build.xml" xml "${xml}")
    file(READ ${xml} string)
    string(REGEX MATCHALL "<Error>" build_errors "${string}")
    if (build_errors)
      list(LENGTH build_errors num_errors)
      file(APPEND ${outf} "${build}: **** ${num_errors} build errors ****\n")
      # avoid ; messing up interp as list
      string(REGEX REPLACE ";" ":" string "${string}")
      string(REGEX MATCHALL
        "<Error>[^<]*<BuildLogLine>[^<]*</BuildLogLine>[^<]*<Text>[^<]+<"
        failures "${string}")
      foreach (failure ${failures})
        string(REGEX REPLACE "^.*<Text>([^<]+)<" "\\1" text "${failure}")
        # replace escaped chars for weird quote with simple quote
        string(REGEX REPLACE "&lt:-30&gt:&lt:-128&gt:&lt:-10[34]&gt:" "'" text "${text}")
        string(STRIP "${text}" text)
        file(APPEND ${outf} "\t${text}\n")
      endforeach (failure)
    else (build_errors)
      string(REGEX REPLACE "Build.xml$" "Test.xml" xml "${xml}")
      if (EXISTS ${xml})
        file(READ ${xml} string)
        string(REGEX MATCHALL "Status=\"passed\"" passed "${string}")
        list(LENGTH passed num_passed)
        string(REGEX MATCHALL "Status=\"failed\"" test_errors "${string}")
      else (EXISTS ${xml})
        set(passed OFF)
        set(test_errors OFF)
      endif (EXISTS ${xml})
      if (test_errors)
        list(LENGTH test_errors num_errors)

        # sanity check
        file(GLOB lastfailed build_${build}/Testing/Temporary/LastTestsFailed*.log)
        file(READ ${lastfailed} faillist)
        string(REGEX MATCHALL "\n" faillines "${faillist}")
        list(LENGTH faillines failcount)
        if (NOT failcount EQUAL num_errors)
          message("WARNING: ${num_errors} errors != ${lastfailed} => ${failcount}")
        endif (NOT failcount EQUAL num_errors)

        file(APPEND ${outf}
          "${build}: ${num_passed} tests passed, **** ${num_errors} tests failed: ****\n")
        # avoid ; messing up interp as list
        string(REGEX REPLACE "&[^;]+;" "" string "${string}")
        string(REGEX REPLACE ";" ":" string "${string}")
        # work around cmake regexps doing maximal matching: we want minimal
        # so we pick a char unlikely to be present to avoid using ".*"
        string(REGEX REPLACE "</Measurement>" "%</Measurement>" string "${string}")
        string(REGEX MATCHALL "Status=\"failed\">[^%]*%</Measurement>"
          failures "${string}")
        # FIXME: have a list of known failures and label w/ " (known: i#XX)"
        foreach (failure ${failures})
          # show key failures like crashes and asserts
          # DrMem assert somehow gets split across 3 lines
          string(REGEX MATCHALL "[^\n]*ASSERT[^\n]*\n[^\n]*\n[^\n\\*]*"
            drmem_assert "${failure}")
          string(REGEX MATCHALL "[^\n]*Unrecoverable[^\n]*" crash "${failure}")
          string(REGEX MATCHALL "[^\n]*Internal DynamoRIO Error[^\n]*" 
            assert "${failure}")
          string(REGEX MATCHALL "[^\n]*CURIOSITY[^\n]*" curiosity "${failure}")
          string(REGEX REPLACE "^.*<Name>([^<]+)<.*$" "\\1" name "${failure}")
          if (drmem_assert OR crash OR assert OR curiosity)
            string(REGEX REPLACE "[ \t]*<Value>" "" assert "${assert}")
            set(reason "=> ${drmem_assert} ${crash} ${assert} ${curiosity}")
          else (drmem_assert OR crash OR assert OR curiosity)
            set(reason "")
          endif (drmem_assert OR crash OR assert OR curiosity)
          file(APPEND ${outf} "\t${name} ${reason}\n")
        endforeach (failure)
      else (test_errors)
        if (passed)
          file(APPEND ${outf} "${build}: all ${num_passed} tests passed\n")
        else (passed)
          file(APPEND ${outf} "${build}: build successful; no tests for this build\n")
        endif (passed)
      endif (test_errors)
    endif (build_errors)
  endif ("${string}" MATCHES "Configuring incomplete")
endforeach (xml)

file(READ ${outf} string)
message("${string}")


