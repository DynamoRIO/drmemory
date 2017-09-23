# **********************************************************
# Copyright (c) 2014-2017 Google, Inc.  All rights reserved.
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

# UMBRA: the shadow memory framework
cmake_minimum_required(VERSION 2.8.10)

if ("${CMAKE_VERSION}" VERSION_EQUAL "2.8.12" OR
    "${CMAKE_VERSION}" VERSION_GREATER "2.8.12")
  # XXX DRi#1481: update to cmake 2.8.12's better handling of interface imports
  cmake_policy(SET CMP0022 OLD)
endif ()

set_output_dirs(${framework_bindir})

set(srcs
  umbra.c
  ../framework/version.c
  # add more here
  )

# add arch specific src here
if (X64)
  set (srcs ${srcs} umbra_64.c)
elseif (X86)
  set (srcs ${srcs} umbra_32.c)
elseif (ARM)
  set (srcs ${srcs} umbra_32.c)
else (X64)
  message(FATAL_ERROR "Umbra does not support this architecture")
endif (X64)

# i#1594c#3: VS generators fail if static lib has resources
set(srcs_static ${srcs})

if (WIN32)
  set(srcs ${srcs} ${PROJECT_SOURCE_DIR}/make/resources.rc)
  set(DEFINES_NO_D ${DEFINES_NO_D} RC_IS_UMBRA)
endif ()

macro(configure_umbra_target target)
  if (UNIX)
    # Avoid relocations which tend to violate security policies
    append_property_string(TARGET ${target} COMPILE_FLAGS "-fPIC")
  endif (UNIX)
  # We do not prevent duplicate builds of the same files as that would require
  # building a static library that is then linked with drmf_utils.c to
  # create a final static library, for DR_EXT_UMBRA_STATIC: and that's
  # a pain to export w/ the proper link rules.  But we at least use the
  # same flags and avoid compiling the same file differently.
  set_property(TARGET ${target} PROPERTY COMPILE_DEFINITIONS ${DEFINES_NO_D})
  target_link_libraries(${target} ${ntimp_lib})
endmacro(configure_umbra_target)

macro(export_umbra_target target drmgr)
  # We need to clear the dependents that come from DR to avoid the prefix
  # from affecting them too.
  set_target_properties(${target} PROPERTIES LINK_INTERFACE_LIBRARIES "")
  export_target(${target})
  # Now put in our imports (w/o any namespace)
  set_target_properties(${target} PROPERTIES
    LINK_INTERFACE_LIBRARIES "dynamorio;${drmgr};drcontainers")
  install(TARGETS ${target} EXPORT ${exported_targets_name}
    DESTINATION ${DRMF_INSTALL_BIN})
  # Top-level installs .debug and .pdb files
endmacro(export_umbra_target)

# For the exported version, we don't want to print to stderr or raise
# msgboxes, so we link in globals to suppress notification in drmf_utils.c.
add_library(umbra SHARED ${srcs} ../framework/drmf_utils.c)
# Set a preferred base to avoid conflict if we can
set(PREFERRED_BASE 0x78000000)
configure_DynamoRIO_client(umbra)
use_DynamoRIO_extension(umbra drmgr)
use_DynamoRIO_extension(umbra drcontainers)
set_library_version(umbra ${DRMF_VERSION_MAJOR_MINOR})
configure_umbra_target(umbra)
export_umbra_target(umbra "drmgr")
install(FILES umbra.h DESTINATION ${DRMF_INSTALL_INC})

# Since the license is LGPL, SHARED and not STATIC by default.
# SHARED is also required if multiple separate components all want to
# use this same extension.
# But, we also provide a static version with a different name for those
# who want it, in the style of DR's side-by-side static extensions.
add_library(umbra_static STATIC ${srcs_static} ../framework/drmf_utils.c)
configure_DynamoRIO_client(umbra_static)
use_DynamoRIO_extension(umbra_static drmgr_static)
use_DynamoRIO_extension(umbra_static drcontainers)
configure_umbra_target(umbra_static)
add_static_lib_debug_info(umbra_static ${DRMF_INSTALL_BIN})
export_umbra_target(umbra_static "drmgr_static")

# We build a separate static target for internal use that has our
# log/assert/notify infrastructure.
add_library(umbra_int STATIC ${srcs_static})
configure_DynamoRIO_client(umbra_int)
use_DynamoRIO_extension(umbra_int drmgr_static)
use_DynamoRIO_extension(umbra_int drcontainers)
if (DEBUG_BUILD)
  if (STATIC_DRSYMS)
    use_DynamoRIO_extension(umbra_int drsyms_static)
  else ()
    use_DynamoRIO_extension(umbra_int drsyms)
  endif ()
endif (DEBUG_BUILD)
configure_umbra_target(umbra_int)

# Documentation is handled as part of the main tool docs processing.
