# **********************************************************
# Copyright (c) 2012-2016 Google, Inc.  All rights reserved.
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

# XXX i#1652: make this a separate project and use --build-and-test

cmake_minimum_required(VERSION 2.6)

include(${PROJECT_SOURCE_DIR}/make/policies.cmake NO_POLICY_SCOPE)

# Always build Debug
set(CMAKE_BUILD_TYPE "Debug")

set_output_dirs("${PROJECT_BINARY_DIR}/tests")

find_package(DrMemoryFramework PATHS ${framework_dir})

# As we'll be calling configure_DynamoRIO_{client,standalone} from within
# a function scope, we must set the global vars ahead of time:
configure_DynamoRIO_global(OFF ON)

# We save pdb+dll space by not using libc (xref DRi#714).
# For Android, we allow running w/o a private Bionic.
# For Linux x86 we need libc for div+mod routines, as well
# as for Umbra.
if (WIN32 OR ANDROID)
  set(DynamoRIO_USE_LIBC OFF)
endif ()

function(add_drmf_test_app app_name src_app)
  tobuild(${app_name} ${src_app})
  if (WIN32)
    # i#1748: disable inlining optimization to avoid calls to
    # fuzzing targets being inlined
    append_property_string(TARGET ${app_name} COMPILE_FLAGS "/Zi /Ob0")
  endif (WIN32)
  copy_target_to_device(${app_name})
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
    if ("${CMAKE_VERSION}" VERSION_EQUAL "3.0" OR
        "${CMAKE_VERSION}" VERSION_GREATER "3.0")
      use_DynamoRIO_extension(${client_name} ${ext})
    else ()
      use_DynamoRIO_extension(${client_name} drmf_${ext}) # drmf_ prefix b/c internal
    endif ()
    use_DynamoRIO_extension(${client_name} drmgr)
    # We use the namespace prefix to allow us to avoid target conflicts
    # (else we'd need a completely separate build for these tests),
    # but cmake gets confused and we have to tell it the two are the same.
    add_dependencies(${client_name} ${ext})
  endforeach (ext)

  copy_target_to_device(${client_name})
  copy_and_adjust_drpaths(${CMAKE_RUNTIME_OUTPUT_DIRECTORY} ${client_name})

  get_target_path_for_execution(app_path ${app_name})
  get_target_path_for_execution(client_path ${client_name})
  if (DEBUG_BUILD)
    set(drrun_extra -quiet -debug)
  else ()
    set(drrun_extra -quiet)
  endif ()
  set(drrun_path ${DynamoRIO_DIR}/../${BIN_ARCH}/drrun)
  convert_local_path_to_device_path(drrun_path ${drrun_path})
  prefix_cmd_if_necessary(drrun_path OFF ${drrun_path})
  if (NOT ANDROID) # FIXME i#1860: fix for Android
    add_test(${test_name}
      ${drrun_path} ${drrun_extra}
      -client ${client_path} 0 "${client_options}"
      -msgbox_mask 0 -stderr_mask 0xc
      "--" ${app_path})
    set_tests_properties(${test_name} PROPERTIES PASS_REGULAR_EXPRESSION "${pass_regex}")
  endif ()
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

# umbra tests

set(asm_defs "${asm_defs}" -I "${CMAKE_CURRENT_SOURCE_DIR}") # for umbra_test_shared.h
add_drmf_test_app(umbra_app umbra_app.c)
target_include_directories(umbra_app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_drmf_test(umbra_test_empty      umbra_app umbra_client_empty.c
  umbra "" ".*TEST PASSED")

add_drmf_test(umbra_test_shadow_mem umbra_app umbra_client_shadow_mem.c
  umbra "" ".*TEST PASSED")
use_DynamoRIO_extension(umbra_test_shadow_mem.client drreg)
use_DynamoRIO_extension(umbra_test_shadow_mem.client drutil)
target_include_directories(umbra_test_shadow_mem.client PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR})

add_drmf_test(umbra_test_insert_app_to_shadow umbra_app
  umbra_client_insert_app_to_shadow.c umbra "" ".*TEST PASSED")
use_DynamoRIO_extension(umbra_test_insert_app_to_shadow.client drreg)
use_DynamoRIO_extension(umbra_test_insert_app_to_shadow.client drutil)
target_include_directories(umbra_test_insert_app_to_shadow.client PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR})

add_drmf_test(umbra_test_consistency umbra_app
  umbra_client_consistency.c umbra "" ".*TEST PASSED")
use_DynamoRIO_extension(umbra_test_consistency.client drreg)
use_DynamoRIO_extension(umbra_test_consistency.client drutil)
target_include_directories(umbra_test_consistency.client PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR})
