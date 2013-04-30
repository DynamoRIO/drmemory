# **********************************************************
# Copyright (c) 2013 Google, Inc.  All rights reserved.
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

set_output_dirs(${framework_bindir})

# Since the license is LGPL, must be SHARED and not STATIC by default.
# SHARED is also required if multiple separate components all want to
# use this same extension.
option(DR_EXT_UMBRA_STATIC "create umbra as a static, not shared, library (N.B.: ensure the LGPL license implications are acceptable for your tool, as well as ensuring no separately-linked components of your tool also use umbra, before enabling as a static library)")
if (DR_EXT_UMBRA_STATIC)
  set(libtype STATIC)
else()
  set(libtype SHARED)
endif ()

set(srcs
  umbra.c
  ../framework/version.c
  # add more here
  )

# add arch specific src here
if (X64)
  set (srcs ${srcs} umbra_x64.c)
else (X64)
  set (srcs ${srcs} umbra_x86.c)
endif (X64)

# For the exported version, we don't want to print to stderr or raise
# msgboxes, so we link in globals to suppress notification in drmf_utils.c.
add_library(umbra ${libtype} ${srcs} ../framework/drmf_utils.c)
# Set a preferred base to avoid conflict if we can
set(PREFERRED_BASE 0x78000000)
configure_DynamoRIO_client(umbra)
use_DynamoRIO_extension(umbra drmgr)
use_DynamoRIO_extension(umbra drcontainers)
if (UNIX)
  # Avoid relocations which tend to violate security policies
  append_property_string(TARGET umbra COMPILE_FLAGS "-fPIC")
endif (UNIX)
set_target_properties(umbra PROPERTIES
  VERSION ${DRMF_VERSION})
# We do not prevent duplicate builds of the same files as that would require
# building a static library that is then linked with drmf_utils.c to
# create a final static library, for DR_EXT_UMBRA_STATIC: and that's
# a pain to export w/ the proper link rules.  But we at least use the
# same flags and avoid compiling the same file differently.
set_property(TARGET umbra PROPERTY COMPILE_DEFINITIONS ${DEFINES_NO_D})

# We build a separate static target for internal use that has our
# log/assert/notify infrastructure.
add_library(umbra_int STATIC ${srcs})
configure_DynamoRIO_client(umbra_int)
use_DynamoRIO_extension(umbra_int drmgr)
use_DynamoRIO_extension(umbra_int drcontainers)
if (DEBUG_BUILD)
  use_DynamoRIO_extension(umbra_int drsyms)
endif (DEBUG_BUILD)
if (UNIX)
  append_property_string(TARGET umbra_int COMPILE_FLAGS "-fPIC")
endif (UNIX)
set_property(TARGET umbra_int PROPERTY COMPILE_DEFINITIONS ${DEFINES_NO_D})

# Documentation is handled as part of the main tool docs processing.

# We need to clear the dependents that come from DR to avoid the prefix
# from affecting them too.
set_target_properties(umbra PROPERTIES
  LINK_INTERFACE_LIBRARIES "")
# We use a prefix primarly to make it easy to test the imported targets,
# and to give a better "bundled extensions" feel.
export_target(umbra NAMESPACE drmf_)
# Now put in our imports w/o the namespace on them
set_target_properties(umbra PROPERTIES
  LINK_INTERFACE_LIBRARIES "dynamorio;drmgr;drcontainers")
install(TARGETS umbra EXPORT ${exported_targets_name} DESTINATION ${DRMF_INSTALL_BIN})
install(FILES umbra.h DESTINATION ${DRMF_INSTALL_INC})
# Top-level installs .debug and .pdb files
