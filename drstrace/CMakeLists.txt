# **********************************************************
# Copyright (c) 2013 Google, Inc.  All rights reserved.
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
# to test the shared, public version:
use_DynamoRIO_extension(drstracelib drmf_drsyscall)
use_DynamoRIO_extension(drstracelib drmgr)
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

# Restore global flags
foreach (config "" ${CMAKE_BUILD_TYPE} ${CMAKE_CONFIGURATION_TYPES})
  if ("${config}" STREQUAL "")
    set(config_upper "")
  else ("${config}" STREQUAL "")
    string(TOUPPER "_${config}" config_upper)
  endif ("${config}" STREQUAL "")
  foreach (var CMAKE_C_FLAGS${config_upper};CMAKE_CXX_FLAGS${config_upper})
    set(${var} "${SAVE_${var}}")
  endforeach (var)
endforeach (config)

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
