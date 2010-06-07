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

# Combines debug and release DrMemory builds into a single package.
# Uses ctest command mode.
#
# Uses same base as DynamoRIO's make/package.cmake.
#
# Invoke like this: "ctest -S package.cmake,dr=<path-to-DynamoRIO>\;build=<build#>"

cmake_minimum_required (VERSION 2.2)

# arguments are a ;-separated list (must escape as \; from ctest_run_script())
set(arg_build "")      # build #
set(arg_DR_dir "")     # DynamoRIO dir
# optional args:
set(arg_ubuild "")     # unique build #
set(arg_version "")    # version #
set(arg_outdir ".")    # directory in which to place deliverables
set(arg_preload "")    # cmake file to include prior to each 32-bit build
set(arg_preload64 "")  # cmake file to include prior to each 64-bit build
set(arg_cacheappend "")# string to append to every build's cache
set(arg_external OFF)  # building an external (open-source) release?

foreach (arg ${CTEST_SCRIPT_ARG})
  if (${arg} MATCHES "^build=")
    string(REGEX REPLACE "^build=" "" arg_build "${arg}")
  endif ()
  if (${arg} MATCHES "^ubuild=")
    string(REGEX REPLACE "^ubuild=" "" arg_ubuild "${arg}")
  endif ()
  if (${arg} MATCHES "^dr=")
    string(REGEX REPLACE "^dr=" "" arg_DR_dir "${arg}")
  endif ()
  if (${arg} MATCHES "^version=")
    string(REGEX REPLACE "^version=" "" arg_version "${arg}")
  endif ()
  if (${arg} MATCHES "^outdir=")
    string(REGEX REPLACE "^outdir=" "" arg_outdir "${arg}")
  endif ()
  if (${arg} MATCHES "^preload=")
    string(REGEX REPLACE "^preload=" "" arg_preload "${arg}")
  endif ()
  if (${arg} MATCHES "^preload64=")
    string(REGEX REPLACE "^preload64=" "" arg_preload64 "${arg}")
  endif ()
  if (${arg} MATCHES "^cacheappend=")
    string(REGEX REPLACE "^cacheappend=" "" arg_cacheappend "${arg}")
  endif ()
  if (${arg} MATCHES "^external")
    set(arg_external ON)
  endif ()
endforeach (arg)

if ("${arg_build}" STREQUAL "")
  message(FATAL_ERROR "build number not set: pass as build= arg")
endif()
if ("${arg_ubuild}" STREQUAL "")
  set(arg_ubuild "${arg_build}")
endif()
if ("${arg_DR_dir}" STREQUAL "")
  message(FATAL_ERROR "path to DynamoRIO not set: pass as dr= arg")
endif()

get_filename_component(BINARY_BASE "." ABSOLUTE)
set(SUITE_TYPE Experimental)
set(DO_UPDATE OFF)

set(CTEST_SOURCE_DIRECTORY "${CTEST_SCRIPT_DIRECTORY}")
set(CTEST_CMAKE_COMMAND "${CMAKE_EXECUTABLE_NAME}")
# FIXME: for now assuming cygwin on Windows
set(CTEST_CMAKE_GENERATOR "Unix Makefiles")
set(CTEST_PROJECT_NAME "DrMemory")
find_program(MAKE_COMMAND make DOC "make command")
set(CTEST_BUILD_COMMAND "${MAKE_COMMAND} -j5")
set(CTEST_COMMAND "${CTEST_EXECUTABLE_NAME}")

function(dobuild name is64 initial_cache)
  set(CTEST_BUILD_NAME "${name}")

  # preload file can set base_cache
  set(base_cache "")
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

  # version is optional
  if (arg_version)
    set(base_cache "${base_cache}
      VERSION_NUMBER:STRING=${arg_version}")
  endif (arg_version)

  set(CTEST_BINARY_DIRECTORY "${BINARY_BASE}/build_${CTEST_BUILD_NAME}")
  set(CTEST_INITIAL_CACHE "${initial_cache}
    DynamoRIO_DIR:PATH=${arg_DR_dir}
    BUILD_NUMBER:STRING=${arg_build}
    UNIQUE_BUILD_NUMBER:STRING=${arg_ubuild}
    ${arg_cacheappend}
    ${base_cache}
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

  ctest_start(${SUITE_TYPE})
  if (DO_UPDATE)
    ctest_update(SOURCE "${CTEST_SOURCE_DIRECTORY}")
  endif (DO_UPDATE)
  ctest_configure(BUILD "${CTEST_BINARY_DIRECTORY}")
  ctest_build(BUILD "${CTEST_BINARY_DIRECTORY}")

  # communicate w/ caller
  set(last_build "${CTEST_BINARY_DIRECTORY}" PARENT_SCOPE)
  # prepend rather than append to get debug first, so we take release
  # files preferentially in case of overlap
  set(cpack_projects 
    "\"${CTEST_BINARY_DIRECTORY};DrMemory;ALL;/\"\n  ${cpack_projects}" PARENT_SCOPE)

endfunction(dobuild)

# the build dir names here must match those in tests/runsuite.cmake to
# support running ctest using gobuild-packaged builds (PR 518715, PR 544430).
# perhaps the two scripts should be merged.
if ("${arg_cacheappend}" MATCHES "VMKERNEL:BOOL=ON")
  set(name_sfx "vmk-")
elseif ("${arg_cacheappend}" MATCHES "USE_DRSYMS:BOOL=OFF")
  set(name_sfx "cygwin-")
else ()
  set(name_sfx "")
endif ()

if (NOT arg_external)
  dobuild("drheapstat-${name_sfx}release-32" OFF "
    TOOL_DR_HEAPSTAT:BOOL=ON
    CMAKE_BUILD_TYPE:STRING=Release
    ")
  dobuild("drheapstat-${name_sfx}debug-32" OFF "
    TOOL_DR_HEAPSTAT:BOOL=ON
    CMAKE_BUILD_TYPE:STRING=Debug
    ")
endif (NOT arg_external)
dobuild("drmemory-${name_sfx}release-32" OFF "
  CMAKE_BUILD_TYPE:STRING=Release
  ")
dobuild("drmemory-${name_sfx}debug-32" OFF "
  CMAKE_BUILD_TYPE:STRING=Debug
  ")

# now package up all the builds
file(APPEND "${last_build}/CPackConfig.cmake"
  "set(CPACK_INSTALL_CMAKE_PROJECTS\n  ${cpack_projects})")
set(CTEST_BUILD_COMMAND "${MAKE_COMMAND} package")
set(CTEST_BUILD_NAME "final package")
ctest_build(BUILD "${last_build}")


# copy the final archive into cur dir
# "cmake -E copy" only takes one file so use 'z' => .tar.gz or .zip
file(GLOB results ${last_build}/DrMemory-*)
foreach (f ${results})
  execute_process(COMMAND ${CMAKE_COMMAND} -E copy ${f} "${arg_outdir}")
endforeach (f)

# workaround for http://www.cmake.org/Bug/view.php?id=9647
# it complains and returns error if CTEST_BINARY_DIRECTORY not set
set(CTEST_BINARY_DIRECTORY "${BINARY_BASE}/")
# it tries to configure+build, but with a start command it does nothing,
# which is what we want:
ctest_start(${SUITE_TYPE})
