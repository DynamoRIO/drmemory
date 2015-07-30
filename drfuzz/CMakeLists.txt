# **********************************************************
# Copyright (c) 2015 Google, Inc.    All rights reserved.
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
# * Neither the name of Google, Inc. nor the names of its contributors may be
#   used to endorse or promote products derived from this software without
#   specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE, INC. OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.

cmake_minimum_required(VERSION 2.6)

if ("${CMAKE_VERSION}" VERSION_EQUAL "2.8.12" OR
    "${CMAKE_VERSION}" VERSION_GREATER "2.8.12")
  # XXX DRi#1481: update to cmake 2.8.12's better handling of interface imports
  cmake_policy(SET CMP0022 OLD)
endif ()

set(srcs
    drfuzz.c
    drfuzz_mutator.c
    ../framework/version.c)

# i#1594c#3: VS generators fail if static lib has resources
set(srcs_static ${srcs})

set(external_srcs ../framework/drmf_utils.c ../common/utils_shared.c)

if (WIN32)
  set(srcs ${srcs} ${PROJECT_SOURCE_DIR}/make/resources.rc)
  set(DEFINES_NO_D ${DEFINES_NO_D} RC_IS_DRFUZZ)
endif ()

# We set DR libc option on b/c this is needed to link with drsyms_static
# on VS2010. It has a downside of increase in pdb and dll size (xref DRi#714).
set(DynamoRIO_USE_LIBC ON)

macro(configure_drfuzz_target target drwrap drmgr drsyms)
  use_DynamoRIO_extension(drfuzz ${drwrap})
  use_DynamoRIO_extension(drfuzz ${drmgr})
  use_DynamoRIO_extension(drfuzz ${drsyms})
  use_DynamoRIO_extension(drfuzz drcontainers)
  if (UNIX)
    # Avoid relocations which tend to violate security policies
    append_property_string(TARGET ${target} COMPILE_FLAGS "-fPIC")
  endif (UNIX)
  set_property(TARGET ${target} PROPERTY COMPILE_DEFINITIONS ${DEFINES_NO_D})
endmacro(configure_drfuzz_target)

macro(export_drfuzz_target target drwrap drmgr)
  # We need to clear the dependents that come from DR to avoid the prefix
  # from affecting them too.
  set_target_properties(${target} PROPERTIES LINK_INTERFACE_LIBRARIES "")
  # We use a prefix primarily to make it easy to test the imported targets,
  # and to give a better "bundled extensions" feel.
  export_target(${target} NAMESPACE drmf_)
  # Now put in our imports w/o the namespace on them
  set_target_properties(${target} PROPERTIES
    LINK_INTERFACE_LIBRARIES "dynamorio;${drwrap};${drmgr};drsyms;drcontainers")
  install(TARGETS ${target} EXPORT ${exported_targets_name}
    DESTINATION ${DRMF_INSTALL_BIN})
  # Top-level installs .debug and .pdb files
endmacro(export_drfuzz_target)

# For the exported version, we don't want to print to stderr or raise
# msgboxes, so we link in globals to suppress notification in drmf_utils.c.
add_library(drfuzz SHARED ${srcs} ${external_srcs})
# Set a preferred base to avoid conflict if we can
set(PREFERRED_BASE 0x79000000)
configure_DynamoRIO_client(drfuzz)
set_target_properties(drfuzz PROPERTIES VERSION ${DRMF_VERSION_MAJOR_MINOR})
configure_drfuzz_target(drfuzz "drwrap" "drmgr" "drsyms")
export_drfuzz_target(drfuzz "drwrap" "drmgr")
install(FILES drfuzz.h DESTINATION ${DRMF_INSTALL_INC})

# Provide a static version for those who may want it
add_library(drfuzz_static STATIC ${srcs_static} ${external_srcs})
# Set a preferred base to avoid conflict if we can
configure_DynamoRIO_client(drfuzz_static)
configure_drfuzz_target(drfuzz_static "drwrap_static" "drmgr_static" "drsyms_static")
export_drfuzz_target(drfuzz_static "drwrap_static" "drmgr_static")

# We build a separate static target for internal use that has our
# log/assert/notify infrastructure.
add_library(drfuzz_int STATIC ${srcs_static})
configure_DynamoRIO_client(drfuzz_int)
configure_drfuzz_target(drfuzz_int "drwrap_static" "drmgr_static" "drsyms_static")
