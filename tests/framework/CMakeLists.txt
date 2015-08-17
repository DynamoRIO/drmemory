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

function(add_drmf_test_app app_name src_app)
  add_executable(${app_name} ${src_app})
  set_property(TARGET ${app_name} PROPERTY COMPILE_DEFINITIONS ${arch_defs})
  if (UNIX AND NOT X64 AND NOT ARM)
    append_property_string(TARGET ${app_name} COMPILE_FLAGS "-m32")
    append_property_string(TARGET ${app_name} LINK_FLAGS "-m32")
  endif ()
  if (UNIX)
    append_property_string(TARGET ${app_name} COMPILE_FLAGS "-g")
  else (UNIX)
    # i#1748: disable inlining optimization to avoid calls to
    # fuzzing targets being inlined
    append_property_string(TARGET ${app_name} COMPILE_FLAGS "/Zi /Ob0")
  endif (UNIX)
endfunction(add_drmf_test_app)

# We only expect a few tests, so we simplify things by having a simple
# regex output for whether they passed.
# ext_list should be a list of extensions minus the drmf_ prefix.
function(add_drmf_test test_name app_name src_client ext_list client_options pass_regex)
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

  get_target_property(app_path ${app_name} LOCATION${location_suffix})
  get_target_property(client_path ${client_name} LOCATION${location_suffix})
  if (DEBUG_BUILD)
    set(drrun_extra -quiet -debug)
  else ()
    set(drrun_extra -quiet)
  endif ()
  add_test(${test_name}
    ${DynamoRIO_DIR}/../${BIN_ARCH}/drrun ${drrun_extra}
    -client ${client_path} 0 "${client_options}"
    -msgbox_mask 0 -stderr_mask 0xc
    "--" ${app_path})
  set_tests_properties(${test_name} PROPERTIES PASS_REGULAR_EXPRESSION "${pass_regex}")
endfunction(add_drmf_test)

add_drmf_test_app(drsyscall_app drsyscall_app.c)
add_drmf_test(drsyscall_test drsyscall_app drsyscall_client.c
  drsyscall "" "done\nTEST PASSED")
add_drmf_test(strace_test drsyscall_app strace_client.c
  drsyscall "" "done\n.*TEST PASSED")

# drfuzz tests
add_drmf_test_app(drfuzz_app_empty drfuzz_app_empty.c)
add_drmf_test(drfuzz_test_empty drfuzz_app_empty drfuzz_client_empty.c
  drfuzz "" "done\nTEST PASSED")
add_drmf_test(drfuzz_test_mutator drfuzz_app_empty drfuzz_client_mutator.c
  drfuzz "" "TEST PASSED\n.*done")

add_drmf_test_app(drfuzz_app_repeat drfuzz_app_repeat.c)
add_drmf_test(drfuzz_test_repeat drfuzz_app_repeat drfuzz_client_repeat.c
  drfuzz "" "hello 1\nhello 2\nhello 3\nhello 4\nhello 5\ndone\nTEST PASSED")

add_drmf_test_app(drfuzz_app_segfault drfuzz_app_segfault.c)

set(segfault_regex_1 "Fault occured in target.*with 1 args.*")
set(segfault_regex_2 "Crash originated in target.*with 1 args.*")
set(segfault_regex_3 "TEST PASSED")

add_drmf_test(drfuzz_test_segfault drfuzz_app_segfault drfuzz_client_segfault.c
  drfuzz "-crash" "${segfault_regex_1}${segfault_regex_2}${segfault_regex_3}")
use_DynamoRIO_extension(drfuzz_test_segfault.client drsyms)

add_drmf_test(drfuzz_test_app_abort drfuzz_app_segfault drfuzz_client_segfault.c
  drfuzz "-abort" "${segfault_regex_2}${segfault_regex_3}")
use_DynamoRIO_extension(drfuzz_test_app_abort.client drsyms)

add_drmf_test(drfuzz_test_no_crash drfuzz_app_segfault drfuzz_client_segfault.c
  drfuzz "" ".*TEST PASSED")
use_DynamoRIO_extension(drfuzz_test_no_crash.client drsyms)

# XXX i#1734: add multi-threaded test, checking for aborted fuzz targets on all threads
