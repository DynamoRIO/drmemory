# **********************************************************
# Copyright (c) 2010-2017 Google, Inc.    All rights reserved.
# Copyright (c) 2009-2010 VMware, Inc.    All rights reserved.
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

cmake_minimum_required(VERSION 2.6)

include(${PROJECT_SOURCE_DIR}/make/policies.cmake NO_POLICY_SCOPE)

##################################################
# drltracelib

set(srcs
    drltrace.cpp
    drltrace_libcalls.cpp
    drltrace_options.cpp)

if (WIN32)
  set(srcs ${srcs} ${PROJECT_SOURCE_DIR}/make/resources.rc)
endif ()

set(DynamoRIO_USE_LIBC OFF)

add_library(drltracelib SHARED ${srcs})

# We share the framework version # for now
set_library_version(drltracelib ${DRMF_VERSION_MAJOR_MINOR})

if (WIN32)
  set_property(TARGET drltracelib PROPERTY COMPILE_DEFINITIONS
    "${DEFINES_NO_D};RC_IS_DRLTRACELIB")
else ()
  set_property(TARGET drltracelib PROPERTY COMPILE_DEFINITIONS ${DEFINES_NO_D})
endif ()

set(DynamoRIO_RPATH ON)
set_target_properties(drltracelib PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY${location_suffix} "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")

configure_DynamoRIO_client(drltracelib)

use_DynamoRIO_extension(drltracelib drmgr_static)
use_DynamoRIO_extension(drltracelib drwrap_static)
use_DynamoRIO_extension(drltracelib drx_static)
use_DynamoRIO_extension(drltracelib drsyscall_static)
use_DynamoRIO_extension(drltracelib drcovlib_static)
use_DynamoRIO_extension(drltracelib droption)

# XXX i#2429: DR's droption.h includes both <string.h> and <string.h>
# we should remove <string.h> and replace the strcmp comparison with
# a std::string. Then we can remove special if here and below.
if (UNIX)
  # to avoid conflicts with new declaration with "C" linkage in utils.h
  append_property_string(TARGET drltracelib COMPILE_FLAGS "-DNOLINK_STRCASESTR")
endif()
if ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
  # i#1805: see comment in drstrace/CMakeLists.txt
  append_property_string(TARGET drltracelib LINK_FLAGS "/force:multiple")
endif ()

install(TARGETS drltracelib
  RUNTIME DESTINATION "${INSTALL_LIB}" # dll
  LIBRARY DESTINATION "${INSTALL_LIB}" # .so
  PERMISSIONS ${owner_access} OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
  WORLD_READ WORLD_EXECUTE)
copy_target_to_device(drltracelib)
copy_and_adjust_drpaths(${CMAKE_RUNTIME_OUTPUT_DIRECTORY} drltracelib)
##################################################
# drltrace frontend

set(front_srcs
    drltrace_frontend.cpp
    drltrace_options.cpp)
if (WIN32)
  set(front_srcs ${front_srcs} ${PROJECT_SOURCE_DIR}/make/resources.rc)
endif ()

add_executable(drltrace ${front_srcs})

configure_DynamoRIO_standalone(drltrace)

target_link_libraries(drltrace drinjectlib drconfiglib drfrontendlib)

set_library_version(drltrace ${DRMF_VERSION})

if (WIN32)
  set_property(TARGET drltrace PROPERTY COMPILE_DEFINITIONS
               ${DEFINES_NO_D} RC_IS_DRLTRACE)
else ()
  set_property(TARGET drltrace PROPERTY COMPILE_DEFINITIONS ${DEFINES_NO_D})
endif ()

# XXX: see DR's i#2429 and comment above.
if (UNIX)
  # to avoid conflicts with new declaration with "C" linkage in utils.h
  append_property_string(TARGET drltrace COMPILE_FLAGS "-DNOLINK_STRCASESTR")
endif()

install(TARGETS drltrace DESTINATION "${INSTALL_BIN}"
  PERMISSIONS ${owner_access} OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
  WORLD_READ WORLD_EXECUTE)
copy_target_to_device(drltrace)
copy_and_adjust_drpaths(${CMAKE_RUNTIME_OUTPUT_DIRECTORY} drltrace)

##################################################
# drltrace config

set(conf_out ${PROJECT_BINARY_DIR}/${BUILD_BIN}/drltrace.config)
if (WIN32)
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/drltrace_win.config ${conf_out} COPYONLY)
else ()
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/drltrace_linux.config ${conf_out} COPYONLY)
endif ()

install(FILES ${conf_out} DESTINATION "${INSTALL_BIN}" PERMISSIONS ${owner_access}
        GROUP_READ WORLD_READ)
copy_target_to_device(${conf_out})

##################################################
# drltrace tests

# XXX i#1960: add more tests for drltrace that check the output contains
# expected library calls.
#
if (BUILD_TOOL_TESTS)
  get_target_path_for_execution(drltrace_path drltrace)
  get_target_path_for_execution(app_path drsyscall_app)
  prefix_cmd_if_necessary(drltrace_path OFF ${drltrace_path})
  add_test(drltrace ${drltrace_path} -- ${app_path})
  add_test(drltrace_libcalls ${drltrace_path} -logdir - -print_ret_addr -- ${app_path})
  add_test(drltrace_symargs ${drltrace_path} -logdir - -num_max_args 4 -- ${app_path})

  add_test(drltrace_libargs ${drltrace_path} -logdir - -only_from_app -- ${app_path})

  #regex strings for libcalls and arguments printing test
  set(libcall_ret "    and return to module id:([0-9]+), offset:0x([0-9a-f]+)\n")

if (WIN32)
  set(libcall_args1_01 "    arg 0: 0x([0-9a-f]+) => 0x([0-9a-f]+) \\(type=void\\*, size=0x([0-9a-f]+)\\)\n")
  set(libcall_args1_02 "    arg 2: 0x([0-9a-f]+) \\(type=size_t, size=0x([0-9a-f]+)\\)\n")

  set(libcall_args2_0 "    arg 0: 0x([0-9a-f]+) \\(type=HANDLE, size=0x([0-9a-f]+)\\)\n")
  set(libcall_args2_1 "    arg 1: 0x([0-9a-f]+) \\(type=int, size=0x([0-9a-f]+)\\)\n")

  set(libcall_name1 "~~([0-9a-f]+)~~ KERNELBASE.dll!VirtualQuery\n")
  set(libcall_name2 "~~([0-9a-f]+)~~ ntdll.dll!ZwQueryInformationProcess\n")
  set(libcall_printf "arg 0: done\n \\(type=char\\*, size=0x([0-9a-f]+)\\)\n")
  # some machines use WriteFile instead of printf, trying to handle both
  set(libcall_WriteFile "arg 2: 0x([0-9a-f]+) \\(type=DWORD, size=0x([0-9a-f]+)\\)\n")
  set(libcall_both_variants "${libcall_printf}\;${libcall_WriteFile}")
else ()
  set(libcall_both_variants "    arg 0: done \\(type=char\\*, size=0x([0-9a-f]+)\\)\n")
  set(libcall_args1_01 ${libcall_both_variants})

  set(libcall_args2_0 "    arg 0: /dev/null \\(type=char \\*\\*, size=0x([0-9a-f]+)\\)\n")
  set(libcall_args2_1 "    arg 1: 0x([0-9a-f]+) \\(type=<unknown>\\*, size=0x([0-9a-f]+)\\)\n")

  set(libcall_name1 "~~([0-9a-f]+)~~ libc.so.6!puts\n")
  set(libcall_name2 "~~([0-9a-f]+)~~ libc.so.6!open\n")
endif(WIN32)
  set_tests_properties(drltrace_libcalls PROPERTIES PASS_REGULAR_EXPRESSION
                       ${libcall_name1}${libcall_args1_01}${libcall_args1_02}${libcall_ret})
  set_tests_properties(drltrace_symargs PROPERTIES PASS_REGULAR_EXPRESSION
                       ${libcall_name2}${libcall_args2_0}${libcall_args2_1})
  set_tests_properties(drltrace_libargs PROPERTIES PASS_REGULAR_EXPRESSION
                       ${libcall_both_variants})
endif (BUILD_TOOL_TESTS)
