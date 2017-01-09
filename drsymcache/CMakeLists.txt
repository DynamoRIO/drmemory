# **********************************************************
# Copyright (c) 2012-2017 Google, Inc.  All rights reserved.
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

if ("${CMAKE_VERSION}" VERSION_EQUAL "2.8.12" OR
    "${CMAKE_VERSION}" VERSION_GREATER "2.8.12")
  # XXX DRi#1481: update to cmake 2.8.12's better handling of interface imports
  cmake_policy(SET CMP0022 OLD)
endif ()

set_output_dirs(${framework_bindir})

# We do not need libc and we save space by not using it (i#714).
set(DynamoRIO_USE_LIBC OFF)

set(external_srcs ../framework/drmf_utils.c ../common/utils_shared.c)

set(srcs
  drsymcache.c
  ../framework/version.c
  # add more here
  )

# i#1594c#3: VS generators fail if static lib has resources
set(srcs_static ${srcs})

if (WIN32)
  set(srcs ${srcs} ${PROJECT_SOURCE_DIR}/make/resources.rc)
  set(DEFINES_NO_D ${DEFINES_NO_D} RC_IS_DRSYMCACHE)
endif ()

# We only need drsyms for checking whether a module has debug info,
# but a user of this extension is almost certainly already using
# drsyms, so it should be fine to unconditionally depend on it.
macro(configure_drsymcache_target target drmgr drsyms)
  if (UNIX)
    # Avoid relocations which tend to violate security policies
    append_property_string(TARGET ${target} COMPILE_FLAGS "-fPIC")
  endif (UNIX)
  if (WIN32 AND X64)
    # Avoid link errors about missing __chkstk.
    # We shouldn't need it (as the DR stack doesn't grow like that)
    # and in fact we don't want it (xref DRi#921).
    append_property_string(TARGET ${target} COMPILE_FLAGS "/Gs65536")
  endif ()
  use_DynamoRIO_extension(${target} drcontainers)
  use_DynamoRIO_extension(${target} ${drmgr})
  use_DynamoRIO_extension(${target} ${drsyms})
  set_property(TARGET ${target} PROPERTY COMPILE_DEFINITIONS ${DEFINES_NO_D})
endmacro(configure_drsymcache_target)

macro(export_drsymcache_target target drmgr drsyms)
  # We need to clear the dependents that come from DR to avoid the prefix
  # from affecting them too.
  set_target_properties(${target} PROPERTIES LINK_INTERFACE_LIBRARIES "")
  export_target(${target})
  # Now put in our imports (w/o any namespace)
  set_target_properties(${target} PROPERTIES
    LINK_INTERFACE_LIBRARIES "dynamorio;${drmgr}")
  install(TARGETS ${target} EXPORT ${exported_targets_name}
    DESTINATION ${DRMF_INSTALL_BIN})
  # Top-level installs .debug and .pdb files
endmacro(export_drsymcache_target)

# For the exported version, we don't want to print to stderr or raise
# msgboxes, so we link in globals to suppress notification in drmf_utils.c.
add_library(drsymcache SHARED ${srcs} ${external_srcs})
# Set a preferred base to avoid conflict if we can
set(PREFERRED_BASE 0x77800000)
configure_DynamoRIO_client(drsymcache)
set_library_version(drsymcache ${DRMF_VERSION_MAJOR_MINOR})
configure_drsymcache_target(drsymcache "drmgr" "drsyms")
export_drsymcache_target(drsymcache "drmgr" "drsyms")
install(FILES drsymcache.h DESTINATION ${DRMF_INSTALL_INC})

# Since the license is LGPL, SHARED and not STATIC by default.
# SHARED is also required if multiple separate components all want to
# use this same extension.
# But, we also provide a static version with a different name for those
# who want it, in the style of DR's side-by-side static extensions.
add_library(drsymcache_static STATIC ${srcs_static} ${external_srcs})
configure_DynamoRIO_client(drsymcache_static)
configure_drsymcache_target(drsymcache_static "drmgr_static" "drsyms_static")
add_static_lib_debug_info(drsymcache_static ${DRMF_INSTALL_BIN})
export_drsymcache_target(drsymcache_static "drmgr_static" "drsyms_static")

# We build a separate static target for internal use that has our
# log/assert/notify infrastructure.
add_library(drsymcache_int STATIC ${srcs_static})
configure_DynamoRIO_client(drsymcache_int)
configure_drsymcache_target(drsymcache_int "drmgr_static" "drsyms_static")

# Documentation is handled as part of the main tool docs processing.
