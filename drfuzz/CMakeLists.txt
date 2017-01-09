# **********************************************************
# Copyright (c) 2015-2017 Google, Inc.    All rights reserved.
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

# We save pdb+dll space by not using libc (xref DRi#714).
# For Android, we allow running w/o a private Bionic.
# For Linux x86 we need libc for div+mod routines.
if (WIN32 OR ARM OR ANDROID)
  set(DynamoRIO_USE_LIBC OFF)
endif ()

macro(configure_drfuzz_target target drwrap drmgr)
  use_DynamoRIO_extension(drfuzz ${drwrap})
  use_DynamoRIO_extension(drfuzz ${drmgr})
  use_DynamoRIO_extension(drfuzz drcontainers)
  if (UNIX)
    # Avoid relocations which tend to violate security policies
    # Avoid tolower from the strcasestr in utils_shared.c, which we don't call
    append_property_string(TARGET ${target} COMPILE_FLAGS "-fPIC -DNOLINK_STRCASESTR")
  endif (UNIX)
  set_property(TARGET ${target} PROPERTY COMPILE_DEFINITIONS ${DEFINES_NO_D})
endmacro(configure_drfuzz_target)

macro(export_drfuzz_target target drwrap drmgr)
  # We need to clear the dependents that come from DR to avoid the prefix
  # from affecting them too.
  set_target_properties(${target} PROPERTIES LINK_INTERFACE_LIBRARIES "")
  export_target(${target})
  # Now put in our imports (w/o any namespace on them)
  set_target_properties(${target} PROPERTIES
    LINK_INTERFACE_LIBRARIES "dynamorio;${drwrap};${drmgr};drcontainers")
  install(TARGETS ${target} EXPORT ${exported_targets_name}
    DESTINATION ${DRMF_INSTALL_BIN})
  # Top-level installs .debug and .pdb files
  copy_target_to_device(${target})
endmacro(export_drfuzz_target)

# For the exported version, we don't want to print to stderr or raise
# msgboxes, so we link in globals to suppress notification in drmf_utils.c.
add_library(drfuzz SHARED ${srcs} ${external_srcs})
# Set a preferred base to avoid conflict if we can
set(PREFERRED_BASE 0x79000000)
configure_DynamoRIO_client(drfuzz)
set_library_version(drfuzz ${DRMF_VERSION_MAJOR_MINOR})
configure_drfuzz_target(drfuzz "drwrap" "drmgr")
export_drfuzz_target(drfuzz "drwrap" "drmgr")
install(FILES drfuzz.h drfuzz_mutator.h DESTINATION ${DRMF_INSTALL_INC})

# Provide a static version for those who may want it
add_library(drfuzz_static STATIC ${srcs_static} ${external_srcs})
# Set a preferred base to avoid conflict if we can
configure_DynamoRIO_client(drfuzz_static)
configure_drfuzz_target(drfuzz_static "drwrap_static" "drmgr_static")
add_static_lib_debug_info(drfuzz_static ${DRMF_INSTALL_BIN})
export_drfuzz_target(drfuzz_static "drwrap_static" "drmgr_static")

# We build a separate static target for internal use that has our
# log/assert/notify infrastructure.
add_library(drfuzz_int STATIC ${srcs_static})
configure_DynamoRIO_client(drfuzz_int)
configure_drfuzz_target(drfuzz_int "drwrap_static" "drmgr_static")

# We build drfuzz_mutator.c as a separate shared library for users who
# want to extend its mutator at the API level in their own custom
# mutator library by loading and calling ours.
add_library(drfuzz_mutator SHARED
  drfuzz_mutator.c ${PROJECT_SOURCE_DIR}/make/resources.rc ${external_srcs})
set(PREFERRED_BASE 0x79100000)
configure_DynamoRIO_client(drfuzz_mutator)
use_DynamoRIO_extension(drfuzz_mutator drmgr_static)
use_DynamoRIO_extension(drfuzz_mutator drcontainers)
# Not bothering to remove RC_IS_DRFUZZ: resources.rc has this one first:
set(DEFINES_NO_D ${DEFINES_NO_D} RC_IS_DRFUZZ_MUTATOR)
set_property(TARGET drfuzz_mutator PROPERTY COMPILE_DEFINITIONS ${DEFINES_NO_D})
# We treat as a regular lib for use as a dynamically loaded plugin
# XXX: better to use export_drfuzz_target()?
install(TARGETS drfuzz_mutator DESTINATION ${DRMF_INSTALL_BIN})
