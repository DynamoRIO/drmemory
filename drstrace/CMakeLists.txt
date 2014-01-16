# **********************************************************
# Copyright (c) 2013-2014 Google, Inc.  All rights reserved.
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

find_package(DrMemoryFramework PATHS ${framework_dir})

##################################################
# drstracelib

# We do not need libc, and we avoid a 10x size increase in both our
# dll and pdb (plus we avoid stressing private library isolation) by
# not using it (i#714).
set(DynamoRIO_USE_LIBC OFF)

add_library(drstracelib SHARED drstrace.c)

# We share the framework version # for now
set_target_properties(drstracelib PROPERTIES VERSION ${DRMF_VERSION})

set_property(TARGET drstracelib PROPERTY COMPILE_DEFINITIONS ${DEFINES_NO_D})

set_target_properties(drstracelib PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY${location_suffix} "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")

# We rely on i#955's "rpath file" to locate the extension on Windows, for
# the build dir at least.
set(DynamoRIO_RPATH ON)
configure_DynamoRIO_client(drstracelib)

# We could link with the internal static lib but it's a good exercise
# to test the public version:
# While we seem to need the drmf_ prefix here for shared drsyscall, for static
# that doesn't work while this does -- go figure:
use_DynamoRIO_extension(drstracelib drsyscall_static)
use_DynamoRIO_extension(drstracelib drmgr_static)
use_DynamoRIO_extension(drstracelib drx_static)
add_dependencies(drstracelib drsyscall)

install(TARGETS drstracelib
  RUNTIME DESTINATION "${INSTALL_LIB}" # dll
  LIBRARY DESTINATION "${INSTALL_LIB}" # .so
  PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
  WORLD_READ WORLD_EXECUTE)

# XXX DRi#1078: we should add the relative dir .drpath support!
# For now we copy drsyscall.dll.  CMake won't let us install it as a
# target from this dir so we copy it as a file.
get_target_property(drsys_path drsyscall LOCATION${location_suffix})
install(FILES ${drsys_path} DESTINATION "${INSTALL_LIB}"
  PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
  WORLD_READ WORLD_EXECUTE)

##################################################
# drstrace frontend

# We don't restore global flags (from each ${SAVE_${var}}) b/c cmake
# waits until the end of the file to take the global values into
# effect.  We don't seem to need them for the front-end though.

add_executable(drstrace drstrace_frontend.c)
configure_DynamoRIO_standalone(drstrace)
target_link_libraries(drstrace drinjectlib drconfiglib)
set_target_properties(drstrace PROPERTIES VERSION ${DRMF_VERSION})
set_property(TARGET drstrace PROPERTY COMPILE_DEFINITIONS ${DEFINES_NO_D})

install(TARGETS drstrace DESTINATION "${INSTALL_BIN}"
  PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
  WORLD_READ WORLD_EXECUTE)

##################################################
# drstrace test

if (BUILD_TOOL_TESTS)
  get_target_property(app_path drsyscall_test LOCATION${location_suffix})
  get_target_property(drstrace_path drstrace LOCATION${location_suffix})
  add_test(drstrace ${drstrace_path} -dr ${DynamoRIO_DIR}/.. -- ${app_path})
endif (BUILD_TOOL_TESTS)
