# **********************************************************
# Copyright (c) 2012 Google, Inc.  All rights reserved.
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

# Always build Debug
set(CMAKE_BUILD_TYPE "Debug")

set_output_dirs("${PROJECT_BINARY_DIR}/tests")

if (UNIX)
  set(arch_defs "LINUX")
else (UNIX)
  set(arch_defs "WINDOWS")
endif (UNIX)

find_package(DrMemoryFramework PATHS ${framework_dir})

# We only expect a few tests, so we simplify things by having a simple
# regex output for whether they passed.
# ext_list should be a list of extensions minus the drmf_ prefix.
function(add_drmf_test test_name src_app src_client ext_list pass_regex)
  add_executable(${test_name} ${src_app})
  set_property(TARGET ${test_name} PROPERTY COMPILE_DEFINITIONS ${arch_defs})
  if (UNIX AND NOT X64)
    append_property_string(TARGET ${test_name} COMPILE_FLAGS "-m32")
    append_property_string(TARGET ${test_name} LINK_FLAGS "-m32")
  endif ()

  set(client_name ${test_name}.client)
  add_library(${client_name} SHARED ${src_client})
  set_property(TARGET ${client_name} PROPERTY COMPILE_DEFINITIONS ${arch_defs})
  set(DynamoRIO_RPATH ON)
  configure_DynamoRIO_client(${client_name})

  foreach (ext ${ext_list})
    use_DynamoRIO_extension(${client_name} drmf_${ext})
    # We use the namespace prefix to allow us to avoid target conflicts
    # (else we'd need a completely separate build for these tests),
    # but cmake gets confused and we have to tell it the two are the same.
    add_dependencies(${client_name} ${ext})

    if (WIN32)
      get_target_property(extpath drmf_${ext} LOCATION)
      # See DR notes on locating the client dll.
      # XXX i#955: we'll need a better solution for 3rd-party extensions
      # in general and we should eliminate this copy once we have that.
      if (NOT created_copy_${ext}_target)
        set(copy_${ext}_stamp "${CMAKE_CURRENT_BINARY_DIR}/copy_${ext}.stamp")
        add_custom_command(OUTPUT "${copy_${ext}_stamp}"
          DEPENDS drmf_${ext}
          COMMAND ${CMAKE_COMMAND} ARGS -E touch "${copy_${ext}_stamp}"
          COMMAND ${CMAKE_COMMAND} ARGS
            -E copy ${extpath} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${ext}.dll
          VERBATIM)
        add_custom_target(copy_${ext} DEPENDS "${copy_${ext}_stamp}")
        set(created_copy_${ext}_target ON PARENT_SCOPE)
      endif ()
      add_dependencies(${client_name} copy_${ext})
    endif (WIN32)
  endforeach (ext)

  get_target_property(app_path ${test_name} LOCATION${location_suffix})
  get_target_property(client_path ${client_name} LOCATION${location_suffix})
  add_test(${test_name}
    ${DynamoRIO_DIR}/../${BIN_ARCH}/drrun -debug
    -client ${client_path} 0 ""
    -msgbox_mask 0
    "--" ${app_path})
  set_tests_properties(${test_name} PROPERTIES PASS_REGULAR_EXPRESSION "${pass_regex}")
endfunction(add_drmf_test)

add_drmf_test(drsyscall_test drsyscall_app.c drsyscall_client.c
  drsyscall "TEST PASSED")
