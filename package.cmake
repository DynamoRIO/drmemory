# **********************************************************
# Copyright (c) 2010-2020 Google, Inc.  All rights reserved.
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

# Combines debug and release DrMemory builds into a single package.
# Uses ctest command mode.
#
# Uses same base as DynamoRIO's make/package.cmake.
#
# Invoke like this: "ctest -S package.cmake,dr=<path-to-DynamoRIO>\;build=<build#>"

cmake_minimum_required (VERSION 2.6)

# set from an including package script
if (NOT DEFINED arg_sub_package)
  set(arg_sub_package OFF) # build DrMem as a sub-package of containing script
  set(arg_sub_script "")   # path to this script file
endif ()

# arguments are a ;-separated list (must escape as \; from ctest_run_script())
set(arg_build "")      # build #
set(arg_DR_dir "")     # DynamoRIO dir: else builds from local sources
# optional args:
set(arg_ubuild "")     # unique build #
set(arg_version "")    # version #
set(arg_outdir ".")    # directory in which to place deliverables
set(arg_cacheappend "")# string to append to every build's cache
set(arg_drmem_only OFF) # do not include Dr. Heapstat
# also takes args parsed by runsuite_common_pre.cmake, in particular:
set(arg_preload "")    # cmake file to include prior to each 32-bit build
set(arg_preload64 "")  # cmake file to include prior to each 64-bit build
set(arg_use_nmake OFF) # use nmake even if gnu make is present
set(arg_cpackappend "")# string to append to CPackConfig.cmake before packaging
set(arg_travis OFF)
set(arg_copy_docs OFF)

foreach (arg ${CTEST_SCRIPT_ARG})
  if (${arg} MATCHES "^build=")
    string(REGEX REPLACE "^build=" "" arg_build "${arg}")
  endif ()
  # alternate name to distinguish from containing DR build #
  if (${arg} MATCHES "^tool_build=")
    string(REGEX REPLACE "^tool_build=" "" arg_build "${arg}")
  endif ()
  if (${arg} MATCHES "^ubuild=")
    string(REGEX REPLACE "^ubuild=" "" arg_ubuild "${arg}")
  endif ()
  if (${arg} MATCHES "^dr=")
    string(REGEX REPLACE "^dr=" "" arg_DR_dir "${arg}")
  endif ()
  if (${arg} MATCHES "^DR=") # support both caps and lowercase
    string(REGEX REPLACE "^DR=" "" arg_DR_dir "${arg}")
  endif ()
  if (${arg} MATCHES "^version=")
    string(REGEX REPLACE "^version=" "" arg_version "${arg}")
  endif ()
  if (${arg} MATCHES "^outdir=")
    string(REGEX REPLACE "^outdir=" "" arg_outdir "${arg}")
  endif ()
  if (${arg} MATCHES "^cacheappend=")
    # support multiple, appending each time
    string(REGEX REPLACE "^cacheappend=" "" entry "${arg}")
    set(arg_cacheappend "${arg_cacheappend}\n${entry}")
  endif ()
  if (${arg} MATCHES "^cpackappend=")
    string(REGEX REPLACE "^cpackappend=" "" arg_cpackappend "${arg}")
  endif ()
  if (${arg} MATCHES "^drmem_only" OR
      ${arg} MATCHES "^drmemory_only")
    set(arg_drmem_only ON)
  endif ()
  if (${arg} STREQUAL "travis")
    set(arg_travis ON)
  endif ()
  if (${arg} MATCHES "^copy_docs")
    set(arg_copy_docs ON)
  endif ()
endforeach (arg)

if ("${arg_build}" STREQUAL "")
  message(FATAL_ERROR "build number not set: pass as build= arg")
endif()
if ("${arg_ubuild}" STREQUAL "")
  set(arg_ubuild "${arg_build}")
endif()
if (NOT "${arg_DR_dir}" STREQUAL "")
  if (NOT EXISTS "${arg_DR_dir}")
    message(FATAL_ERROR "invalid DynamoRIO dr= arg")
  endif ()
  set(DR_entry "DynamoRIO_DIR:PATH=${arg_DR_dir}")
  set(runsuite_include_path "${arg_DR_dir}")
else ()
  set(DR_entry "")
  # include from source instead of exports dir
  set(runsuite_include_path "${CTEST_SCRIPT_DIRECTORY}/dynamorio/suite")
endif()

if (arg_sub_package)
  set(sub_entry "BUILDING_SUB_PACKAGE:BOOL=ON")
  get_filename_component(CTEST_SOURCE_DIRECTORY "${arg_sub_script}" PATH)
else ()
  set(sub_entry "")
  set(CTEST_PROJECT_NAME "DrMemory")
  set(cpack_project_name "DrMemory")
  set(run_tests OFF)
  set(CTEST_SOURCE_DIRECTORY "${CTEST_SCRIPT_DIRECTORY}")
  include("${runsuite_include_path}/runsuite_common_pre.cmake")
endif ()

if (APPLE)
  # Macs no longer support 32-bit at all.
  set(arg_64_only ON)
endif ()

# i#1099: be sure to set BUILDING_PACKAGE
set(base_cache "
  ${DR_entry}
  TOOL_BUILD_NUMBER:STRING=${arg_build}
  UNIQUE_BUILD_NUMBER:STRING=${arg_ubuild}
  BUILD_TOOL_TESTS:BOOL=OFF
  BUILDING_PACKAGE:BOOL=ON
  ${sub_entry}
  ${arg_cacheappend}
  ${base_cache}
  ")

# version is optional
if (arg_version)
  set(base_cache "${base_cache}
    TOOL_VERSION_NUMBER:STRING=${arg_version}")
endif (arg_version)

# the build dir names here must match those in tests/runsuite.cmake to
# support running ctest using gobuild-packaged builds (PR 518715, PR 544430).
# perhaps the two scripts should be further merged.
if ("${arg_cacheappend}" MATCHES "VMKERNEL:BOOL=ON")
  set(name_sfx "vmk-")
elseif ("${arg_cacheappend}" MATCHES "USE_DRSYMS:BOOL=OFF")
  set(name_sfx "cygwin-")
else ()
  set(name_sfx "")
endif ()

if (NOT arg_drmem_only)
  if (NOT arg_64_only)
    testbuild_ex("drheapstat-${name_sfx}release-32" OFF "
      TOOL_DR_HEAPSTAT:BOOL=ON
      CMAKE_BUILD_TYPE:STRING=Release
      " OFF ON "")
    testbuild_ex("drheapstat-${name_sfx}debug-32" OFF "
      TOOL_DR_HEAPSTAT:BOOL=ON
      CMAKE_BUILD_TYPE:STRING=Debug
      " OFF ON "")
  endif ()
  testbuild_ex("drheapstat-${name_sfx}release-64" ON "
    TOOL_DR_HEAPSTAT:BOOL=ON
    CMAKE_BUILD_TYPE:STRING=Release
    " OFF ON "")
  testbuild_ex("drheapstat-${name_sfx}debug-64" ON "
    TOOL_DR_HEAPSTAT:BOOL=ON
    CMAKE_BUILD_TYPE:STRING=Debug
    " OFF ON "")
endif (NOT arg_drmem_only)
if (NOT arg_32_only)
  testbuild_ex("drmemory-${name_sfx}release-64" ON "
    CMAKE_BUILD_TYPE:STRING=Release
    " OFF ON "")
  testbuild_ex("drmemory-${name_sfx}debug-64" ON "
    CMAKE_BUILD_TYPE:STRING=Debug
    " OFF ON "")
endif (NOT arg_32_only)
if (NOT arg_64_only)
  # 32-bit last, to match DR for embedded packaging
  testbuild_ex("drmemory-${name_sfx}release-32" OFF "
    CMAKE_BUILD_TYPE:STRING=Release
    " OFF ON "")
  testbuild_ex("drmemory-${name_sfx}debug-32" OFF "
    CMAKE_BUILD_TYPE:STRING=Debug
    " OFF ON "")
endif ()

if (arg_cpackappend)
  # ${last_package_build_dir} is a global var set in parent scope by
  # testbuild_ex to communicate with runsuite_common_post.  We use it to access
  # the CPackConfig.cmake file.
  file(APPEND "${last_package_build_dir}/CPackConfig.cmake"
    "\n${arg_cpackappend}\n")
endif ()

if (NOT arg_sub_package)
  set(build_package ON)
  # Some packagers request an official source tarball, so we create one (i#1287).
  # However, this fails on Appveyor for as-yet-undiagnosed reasons (i#2255),
  # and Github supplies its own source tarball, so we disable there.
  if (NOT arg_travis)
    set(build_source_package ON)
  endif ()
  include("${runsuite_include_path}/runsuite_common_post.cmake")

  # copy the final archive into cur dir
  # "cmake -E copy" only takes one file so use 'z' => .tar.gz or .zip
  file(GLOB results ${last_build_dir}/DrMemory-*)
  foreach (f ${results})
    execute_process(COMMAND ${CMAKE_COMMAND} -E copy ${f} "${arg_outdir}")
  endforeach (f)

  if (arg_copy_docs)
    # Prepare for copying the documentation to our Github Pages site by placing it
    # in a single fixed-name location with a .nojekyll file.
    message("Copying documentation into ${arg_outdir}/html")
    message("Looking for ${last_package_build_dir}/_CPack_Packages/*/*/DrMemory-*/drmemory/docs/html")
    file(GLOB allhtml "${last_package_build_dir}/_CPack_Packages/*/*/DrMemory-*/drmemory/docs/html")
    # If there's a source package we'll have multiple.  Just take the first one.
    list(GET allhtml 0 html)
    if (EXISTS "${html}")
      execute_process(COMMAND ${CMAKE_COMMAND} -E make_directory "${arg_outdir}/html")
      execute_process(COMMAND
        ${CMAKE_COMMAND} -E copy_directory ${html} "${arg_outdir}/html")
      # Create a .nojekyll file so Github Pages will display this as raw html.
      execute_process(COMMAND ${CMAKE_COMMAND} -E touch "${arg_outdir}/html/.nojekyll")
      message("Successully copied docs")
    else ()
      message(FATAL_ERROR "failed to find html docs")
    endif ()
  endif ()
endif ()
