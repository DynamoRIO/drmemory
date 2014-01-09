# **********************************************************
# Copyright (c) 2012-2013 Google, Inc.  All rights reserved.
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

set_output_dirs(${framework_bindir})

# Since the license is LGPL, must be SHARED and not STATIC by default.
# SHARED is also required if multiple separate components all want to
# use this same extension.
option(DR_EXT_DRSYSCALL_STATIC "create drsyscall as a static, not shared, library (N.B.: ensure the LGPL license implications are acceptable for your tool, as well as ensuring no separately-linked components of your tool also use drsyscall, before enabling as a static library)")
if (DR_EXT_DRSYSCALL_STATIC)
  set(libtype STATIC)
else()
  set(libtype SHARED)
endif ()

option(SYSCALL_DRIVER "use a kernel driver to identify system call writes")
option(SYSCALL_DRIVER_SRCDIR "source dir of kernel driver")
if (SYSCALL_DRIVER)
  set(DEFINES ${DEFINES} -DSYSCALL_DRIVER)
  include_directories(${SYSCALL_DRIVER_SRCDIR})
endif (SYSCALL_DRIVER)

set(srcs
  drsyscall.c
  ../framework/version.c
  # add more here
  )

if (UNIX)
  set(srcs ${srcs}
    drsyscall_linux.c
    ../${asm_utils_src})
else (UNIX)
  set(srcs ${srcs}
    drsyscall_windows.c
    drsyscall_wingdi.c)
  if (SYSCALL_DRIVER)
    set(srcs ${srcs}
      drmemory/syscall_driver.c)
  endif (SYSCALL_DRIVER)
endif (UNIX)

# For the exported version, we don't want to print to stderr or raise
# msgboxes, so we link in globals to suppress notification in drmf_utils.c.
add_library(drsyscall ${libtype} ${srcs} ../framework/drmf_utils.c)
# Set a preferred base to avoid conflict if we can
set(PREFERRED_BASE 0x77000000)
configure_DynamoRIO_client(drsyscall)
use_DynamoRIO_extension(drsyscall drmgr)
use_DynamoRIO_extension(drsyscall drcontainers)
if (UNIX)
  # Avoid relocations which tend to violate security policies
  append_property_string(TARGET drsyscall COMPILE_FLAGS "-fPIC")
endif (UNIX)
set_target_properties(drsyscall PROPERTIES
  VERSION ${DRMF_VERSION})
# We do not prevent duplicate builds of the same files as that would require
# building a static library that is then linked with drmf_utils.c to
# create a final static library, for DR_EXT_DRSYSCALL_STATIC: and that's
# a pain to export w/ the proper link rules.  But we at least use the
# same flags and avoid compiling the same file differently.
set_property(TARGET drsyscall PROPERTY COMPILE_DEFINITIONS ${DEFINES_NO_D})
target_link_libraries(drsyscall ${ntimp_lib})
if (NOT USER_SPECIFIED_DynamoRIO_DIR AND "${CMAKE_GENERATOR}" MATCHES "Visual Studio")
  add_dependencies(drsyscall ntimp_tgt)
endif ()

# We build a separate static target for internal use that has our
# log/assert/notify infrastructure.
add_library(drsyscall_int STATIC ${srcs})
configure_DynamoRIO_client(drsyscall_int)
use_DynamoRIO_extension(drsyscall_int drmgr_static)
use_DynamoRIO_extension(drsyscall_int drcontainers)
if (DEBUG_BUILD)
  if (STATIC_DRSYMS)
    use_DynamoRIO_extension(drsyscall_int drsyms_static)
  else ()
    use_DynamoRIO_extension(drsyscall_int drsyms)
  endif ()
endif (DEBUG_BUILD)
if (UNIX)
  append_property_string(TARGET drsyscall_int COMPILE_FLAGS "-fPIC")
endif (UNIX)
set_property(TARGET drsyscall_int PROPERTY COMPILE_DEFINITIONS ${DEFINES_NO_D})
target_link_libraries(drsyscall_int ${ntimp_lib})
if (NOT USER_SPECIFIED_DynamoRIO_DIR AND "${CMAKE_GENERATOR}" MATCHES "Visual Studio")
  add_dependencies(drsyscall_int ntimp_tgt)
endif ()

# Documentation is handled as part of the main tool docs processing.

# We need to clear the dependents that come from DR to avoid the prefix
# from affecting them too.
set_target_properties(drsyscall PROPERTIES
  LINK_INTERFACE_LIBRARIES "")
# We use a prefix primarly to make it easy to test the imported targets,
# and to give a better "bundled extensions" feel.
export_target(drsyscall NAMESPACE drmf_)
# Now put in our imports w/o the namespace on them
set_target_properties(drsyscall PROPERTIES
  LINK_INTERFACE_LIBRARIES "dynamorio;drmgr;drcontainers")
install(TARGETS drsyscall EXPORT ${exported_targets_name} DESTINATION ${DRMF_INSTALL_BIN})
install(FILES drsyscall.h DESTINATION ${DRMF_INSTALL_INC})
# Top-level installs .debug and .pdb files
