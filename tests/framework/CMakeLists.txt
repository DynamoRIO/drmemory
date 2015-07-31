# **********************************************************
# Copyright (c) 2012-2015 Google, Inc.  All rights reserved.
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
  set(arch_defs "UNIX")
  if (APPLE)
    set(arch_defs ${arch_defs} "MACOS")
  else (APPLE)
    set(arch_defs ${arch_defs} "LINUX")
  endif (APPLE)
else (UNIX)
  set(arch_defs "WINDOWS")
endif (UNIX)

find_package(DrMemoryFramework PATHS ${framework_dir})

# As we'll be calling configure_DynamoRIO_{client,standalone} from within
# a function scope, we must set the global vars ahead of time:
configure_DynamoRIO_global(OFF ON)

# We only expect a few tests, so we simplify things by having a simple
# regex output for whether they passed.
# ext_list should be a list of extensions minus the drmf_ prefix.
function(add_drmf_test test_name src_app src_client ext_list pass_regex)
  add_executable(${test_name} ${src_app})
  set_property(TARGET ${test_name} PROPERTY COMPILE_DEFINITIONS ${arch_defs})
  if (UNIX AND NOT X64 AND NOT ARM)
    append_property_string(TARGET ${test_name} COMPILE_FLAGS "-m32")
    append_property_string(TARGET ${test_name} LINK_FLAGS "-m32")
  endif ()

  set(client_name ${test_name}.client)
  add_library(${client_name} SHARED ${src_client})
  set_property(TARGET ${client_name} PROPERTY COMPILE_DEFINITIONS ${arch_defs})
  # We rely on i#955's "rpath file" to locate the extension on Windows
  set(DynamoRIO_RPATH ON)
  configure_DynamoRIO_client(${client_name})

  foreach (ext ${ext_list})
    use_DynamoRIO_extension(${client_name} drmf_${ext}) # drmf_ prefix b/c internal
    use_DynamoRIO_extension(${client_name} drmgr)
    # We use the namespace prefix to allow us to avoid target conflicts
    # (else we'd need a completely separate build for these tests),
    # but cmake gets confused and we have to tell it the two are the same.
    add_dependencies(${client_name} ${ext})
  endforeach (ext)

  get_target_property(app_path ${test_name} LOCATION${location_suffix})
  get_target_property(client_path ${client_name} LOCATION${location_suffix})
  if (DEBUG_BUILD)
    set(drrun_extra -quiet -debug)
  else ()
    set(drrun_extra -quiet)
  endif ()
  add_test(${test_name}
    ${DynamoRIO_DIR}/../${BIN_ARCH}/drrun ${drrun_extra}
    -client ${client_path} 0 ""
    -msgbox_mask 0 -stderr_mask 0xc
    "--" ${app_path})
  set_tests_properties(${test_name} PROPERTIES PASS_REGULAR_EXPRESSION "${pass_regex}")
endfunction(add_drmf_test)

add_drmf_test(drsyscall_test drsyscall_app.c drsyscall_client.c
  drsyscall "done\nTEST PASSED")

add_drmf_test(strace_test drsyscall_app.c strace_client.c
  drsyscall "done\n.*TEST PASSED")

# drfuzz tests
add_drmf_test(drfuzz_test_empty drfuzz_app_empty.c drfuzz_client_empty.c
  drfuzz "done\nTEST PASSED")

add_drmf_test(drfuzz_test_repeat drfuzz_app_repeat.c drfuzz_client_repeat.c
  drfuzz "hello 1\nhello 2\nhello 3\nhello 4\nhello 5\ndone\nTEST PASSED")
