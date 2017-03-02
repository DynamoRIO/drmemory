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
    drltrace.c)

set(external_srcs ../framework/drmf_utils.c)

if (WIN32)
  set(srcs ${srcs} ${PROJECT_SOURCE_DIR}/make/resources.rc)
endif ()

set(DynamoRIO_USE_LIBC OFF)

add_library(drltracelib SHARED ${srcs} ${external_srcs})

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
# ensure we rebuild if includes change
add_dependencies(drltracelib api_headers)

if ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
  # i#1805: see comment in drstrace/CMakeLists.txt
  append_property_string(TARGET drltracelib LINK_FLAGS "/force:multiple")
endif ()

install(TARGETS drltracelib
  RUNTIME DESTINATION "${INSTALL_LIB}" # dll
  LIBRARY DESTINATION "${INSTALL_LIB}" # .so
  PERMISSIONS ${owner_access} OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
  WORLD_READ WORLD_EXECUTE)


##################################################
# drltrace frontend

set(front_srcs drltrace_frontend.cpp)
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

install(TARGETS drltrace DESTINATION "${INSTALL_BIN}"
  PERMISSIONS ${owner_access} OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
  WORLD_READ WORLD_EXECUTE)
