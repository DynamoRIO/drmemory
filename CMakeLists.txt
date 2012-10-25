# **********************************************************
# Copyright (c) 2010-2012 Google, Inc.  All rights reserved.
# Copyright (c) 2009-2010 VMware, Inc.  All rights reserved.
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

if ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
  # for output dir name control
  cmake_minimum_required(VERSION 2.8.2)
else ()
  # for cmake bug #8639 (asm support broken)
  cmake_minimum_required(VERSION 2.6.4)
endif ()

# like DR, we collapse VS generator into one config since
# we don't have enough control over output dirs
# in build rules (until cmake 2.8.4).
# this must be prior to the project() command.
if ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
  if ("${CMAKE_BUILD_TYPE}" MATCHES "Debug")
    set(CMAKE_CONFIGURATION_TYPES "Debug" CACHE STRING "" FORCE)
  else ()
    set(CMAKE_CONFIGURATION_TYPES "Release" CACHE STRING "" FORCE)
  endif ()
  # we want to use the _LOCATION_<config> property
  string(TOUPPER "${CMAKE_CONFIGURATION_TYPES}" upper)
  set(location_suffix "_${upper}")
else ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
  set(location_suffix "")
endif ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")

# I want to override the default CMAKE_INSTALL_PREFIX, but allow it to
# be set (as the same var name, so CPack and other standard tools
# work) externally.  The best solution is to check whether defined BEFORE
# the project() command.
# If we didn't use standard tools we could set CMAKE_INSTALL_PREFIX
# to be CACHE INTERNAL FORCE to INSTALL_PREFIX.
if (NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(install_override ON)
else (NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(install_override OFF)
endif (NOT DEFINED CMAKE_INSTALL_PREFIX)

project(DrMemory NONE)
if (DEFINED GENERATE_PDBS AND NOT GENERATE_PDBS)
  # support building over cygwin ssh where we cannot build pdbs.
  # using the same solution as DynamoRIO i#310.
  # To prevent cmake's try-compile for its working compiler test and
  # its ABI determination test we request a Release build config
  # via a custom Plaform/Windows-cl.cmake in our make/ dir.
  set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/make")
endif ()
enable_language(C)
enable_language(CXX)

option(VMKERNEL "target vmkernel")
if (VMKERNEL)
  # if we get enough of these, should use a configure.h, but would need to
  # pull the ops out like DR core does to pass to options_perl below
  set(DEFINES ${DEFINES} -DVMX86_SERVER)
endif (VMKERNEL)

option(TOOL_DR_HEAPSTAT "build Dr. Heapstat instead of Dr. Memory")
option(USE_MD5 "use md5 instead of crc32 for callstack hashes for Dr. Heapstat")
if (USE_MD5)
  set(DEFINES ${DEFINES} -DUSE_MD5)
endif (USE_MD5)
option(CHECK_WITH_MD5 "use crc32 for callstack hashes but check for collisions with md5")
if (CHECK_WITH_MD5)
  set(DEFINES ${DEFINES} -DCHECK_WITH_MD5)
endif (CHECK_WITH_MD5)
option(STATIC_DRSYMS "use static drsyms library" ON)
if (UNIX AND NOT STATIC_DRSYMS)
  # we could support dynamic but we'd have to copy libdrsym.so
  message(FATAL_ERROR "non-static drsyms not supported for Linux")
endif ()

if (TOOL_DR_HEAPSTAT)
  # Dr. Heapstat
  set(TOOL_DR_MEMORY OFF)
  set(toolname drheapstat)
  set(tooldir ${toolname})
  set(toolname_cap DrHeapstat)
  set(toolname_cap_spc "Dr. Heapstat")
  set(DEFINES ${DEFINES} -DTOOL_DR_HEAPSTAT)

  option(BUILD_VISUALIZER "build Dr. Heapstat visualizer (requires Flex SDK and Java)")
  if (BUILD_VISUALIZER)
    # Flex building is done only for Dr. HeapStat visualization tool.  So Java
    # is needed only for that too.
    if (NOT DEFINED JAVA)     # Not using toolchain then
      set(Java_FIND_QUIETLY ON) # avoid errors about missing javac
      include(FindJava)
      if (JAVA_RUNTIME)
        set(JAVA "${JAVA_RUNTIME}")
        message(STATUS "Found Java interpreter ${JAVA}")
      else (JAVA_RUNTIME)
        message(FATAL_ERROR "Can't find Java interpreter: please set JAVA var")
      endif (JAVA_RUNTIME)
    endif (NOT DEFINED JAVA)
    
    # There is no standard install path so the user must tell us where they
    # installed the Flex SDK, either via env var FLEXROOT or FLEX_SDK CMake var.
    set(FLEX_SDK "$ENV{FLEXROOT}" CACHE PATH "Path to Flex SDK.")
    set(FLEX_MXMLC "${FLEX_SDK}/lib/mxmlc.jar"
      CACHE FILEPATH "Path to Flex MXML compiler.")
    if (NOT EXISTS "${FLEX_MXMLC}")
      message(FATAL_ERROR "Flex compiler ${FLEX_MXMLC} not found: set FLEX_SDK var or FLEXROOT env var")
    endif ()
    message(STATUS "Found Flex MXML compiler ${FLEX_MXMLC}")

    set(FLEX_FRAMEWORKS "${FLEX_SDK}/frameworks"
      CACHE PATH "Path to Flex frameworks, i.e., standard libraries.")
    if (NOT EXISTS "${FLEX_FRAMEWORKS}")
      message(FATAL_ERROR "Flex frameworks path ${FLEX_FRAMEWORKS} not found.")
    endif ()
  endif (BUILD_VISUALIZER)

  # Dr. Heapstat uses drsyms only to avoid false neg on leaks (i#762, i#292).
  # XXX: use drsyms for leak reports (i#926) and usage (i#282).
  set(DRSYMS_DEFAULT ON)
else (TOOL_DR_HEAPSTAT)
  # Dr. Memory
  set(TOOL_DR_MEMORY ON)
  set(toolname drmemory)
  set(tooldir ${toolname})
  set(toolname_cap DrMemory)
  set(toolname_cap_spc "Dr. Memory")
  set(DEFINES ${DEFINES} -DTOOL_DR_MEMORY)
  set(DRSYMS_DEFAULT ON)

  option(SYSCALL_DRIVER "use a kernel driver to identify system call writes")
  option(SYSCALL_DRIVER_SRCDIR "source dir of kernel driver")
  if (SYSCALL_DRIVER)
    set(DEFINES ${DEFINES} -DSYSCALL_DRIVER)
    # include dir added below
  endif (SYSCALL_DRIVER)
endif (TOOL_DR_HEAPSTAT)

# i#83: use svn revision of last commit as patchlevel ver# to distinguish
# mid-release builds.
# XXX: if we later switch to a non-linear version control system we'll
# want to switch to a date or something, but be aware of timezone issues
# so we may want a cron job that updates an official date in the sources.
set(VERSION_NUMBER_PATCHLEVEL 0)
# for now using a hack of running svn or git to get the ver#,
# rather than having it stored in the sources and auto-updated
if (EXISTS "${PROJECT_SOURCE_DIR}/.svn")
  find_program(SVN svn DOC "subversion client")
  if (SVN)
    execute_process(COMMAND ${SVN} info
      WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
      RESULT_VARIABLE svn_result
      ERROR_VARIABLE svn_err
      OUTPUT_VARIABLE svn_out)
    if (svn_result OR svn_err)
      message(FATAL_ERROR "*** ${SVN} info failed: ***\n${svn_result} ${svn_err}")
    endif (svn_result OR svn_err)
    string(REGEX MATCH "Revision: [0-9]+" svn_out "${svn_out}")
    string(REGEX REPLACE "Revision: " "" svn_out "${svn_out}")
    set(VERSION_NUMBER_PATCHLEVEL "${svn_out}")
  endif (SVN)
else (EXISTS "${PROJECT_SOURCE_DIR}/.svn")
  if (EXISTS "${PROJECT_SOURCE_DIR}/.git")
    find_program(GIT git DOC "git client")
    if (GIT)
      execute_process(COMMAND ${GIT} log
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
        RESULT_VARIABLE git_result
        ERROR_VARIABLE git_err
        OUTPUT_VARIABLE git_out)
      if (git_result OR git_err)
        message(FATAL_ERROR "*** ${GIT} show failed: ***\n${git_err}")
      endif (git_result OR git_err)
      # look for first commit with git-svn-id
      string(REGEX MATCH "git-svn-id: http[^@]*@[0-9]+" git_out "${git_out}")
      string(REGEX REPLACE "git-svn-id: http[^@]*@" "" git_out "${git_out}")
      set(VERSION_NUMBER_PATCHLEVEL "${git_out}")
    endif (GIT)
  endif (EXISTS "${PROJECT_SOURCE_DIR}/.git")
endif (EXISTS "${PROJECT_SOURCE_DIR}/.svn")

# XXX: for windows should we have a real .rc file?
set(VERSION_NUMBER_DEFAULT "1.5.${VERSION_NUMBER_PATCHLEVEL}")
# do not store the default TOOL_VERSION_NUMBER in the cache to prevent a stale one
# from preventing future version updates in a pre-existing build dir.
# avoid "VERSION_NUMBER" name since conflics w/ DR's var
set(TOOL_VERSION_NUMBER "" CACHE STRING "Version number: leave empty for default")
if ("${TOOL_VERSION_NUMBER}" STREQUAL "")
  set(TOOL_VERSION_NUMBER ${VERSION_NUMBER_DEFAULT})
endif()
message(STATUS "Dr. Memory version number: ${TOOL_VERSION_NUMBER}")

# Avoid "BUILD_NUMBER" name since conflics w/ DR's var
set(TOOL_BUILD_NUMBER "1" CACHE STRING "Build number (must be <64K)")

set(DEFINES ${DEFINES}
  -DBUILD_NUMBER=${TOOL_BUILD_NUMBER}
  -DVERSION_NUMBER=${TOOL_VERSION_NUMBER}
  -DVERSION_STRING="${TOOL_VERSION_NUMBER}")

# i#44/PR 243532: online symbol access
option(USE_DRSYMS "use drsyms DR Extension online symbols instead of post-processing"
  ${DRSYMS_DEFAULT})
if (USE_DRSYMS)
  set(DEFINES ${DEFINES} -DUSE_DRSYMS)
endif (USE_DRSYMS)

if (WIN32)
  # With the new drinjectlib-based front end we do not use perl or perl2exe
  # at all on Windows (xref i#265/PR 486139)
  if (OFF) # disabling
    # For portability we convert our perl scripts to executables,
    # if the 'pp' tool is available.
    # For most portable results, use a native windows perl (e.g.,
    # strawberry perl) rather than cygwin perl.
    set(PERL_PATH  "" CACHE PATH "directory where perl binaries are located")
    if (PERL_PATH AND EXISTS "${PERL_PATH}/perl.exe")
      set(PERL_EXECUTABLE "${PERL_PATH}/perl.exe")
    else ()
      # we only look for perl if user doesn't specify (on windows it's common
      # to have several perls installed)
      include(FindPerl)
      if (PERL_FOUND)
        get_filename_component(PERL_PATH "${PERL_EXECUTABLE}" PATH)
      endif (PERL_FOUND)
    endif ()

    if (EXISTS "${PERL_PATH}/pp")
      set(PERL_PP "${PERL_PATH}/pp" CACHE FILEPATH
        "Path to perl PAR module's perl-to-executable tool 'pp'")
    else ()
      find_file(PERL_PP pp HINTS "${PERL_PATH}"
        DOC "Path to perl PAR module's perl-to-executable tool 'pp'")
    endif ()
    if (PERL_PP-NOTFOUND OR NOT EXISTS "${PERL_PP}")
      message(STATUS "Did not find pp: will not convert perl scripts to executables")
      set(PERL_TO_EXE OFF)
    else (PERL_PP-NOTFOUND OR NOT EXISTS "${PERL_PP}")
      message(STATUS "Found pp: ${PERL_PP}")
      set(PERL_TO_EXE ON)
    endif (PERL_PP-NOTFOUND OR NOT EXISTS "${PERL_PP}")
  else (OFF)
    set(PERL_TO_EXE OFF)
  endif (OFF)
endif (WIN32)

# i#889: Dr. Memory pattern mode supports 64-bit
# FIXME i#111, i#217: 64-bit is only supported in pattern mode
set(SUPPORT_64BIT ON)
if (CMAKE_C_SIZEOF_DATA_PTR EQUAL 8 OR CMAKE_CXX_SIZEOF_DATA_PTR EQUAL 8)
  if (NOT SUPPORT_64BIT)
    message(FATAL_ERROR "64-bit not supported (on Linux, set CFLAGS=-m32 CXXFLAGS=-m32)")
  endif (NOT SUPPORT_64BIT)
  set(X64 ON)
  set(LIB_ARCH "lib64")
  set(BIN_ARCH "bin64")
else()
  set(X64 OFF)
  set(LIB_ARCH "lib32")
  set(BIN_ARCH "bin32")
endif ()

if ("${CMAKE_BUILD_TYPE}" MATCHES "Debug")
  # FIXME: use a configure.h
  set(DEFINES ${DEFINES} -DDEBUG -DSTATISTICS)
  set(DEBUG_BUILD ON) # "DEBUG" conflicts w/ DR
else ()
  if (UNIX)
    # has enough debug info
    set(CMAKE_BUILD_TYPE "Release")
  else (UNIX)
    # we want pdb for release build
    set(CMAKE_BUILD_TYPE "RelWithDebInfo")
  endif (UNIX)
  set(DEBUG_BUILD OFF)
endif ()

string(TOUPPER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_UPPER)

if (UNIX)
  # there's no cmake warning control so we hardcode it
  # disabling strict aliasing since giving weird warning I'm not sure how to fix:
  #   alloc.c:716: warning: dereferencing type-punned pointer will break strict-aliasing rules
  set(WARN "-Wall -Werror -Wno-strict-aliasing")
  if (CMAKE_C_COMPILER MATCHES "/build/toolchain")
    # needed for linux/ipmi.h (PR 531644)
    set(EXTRA_FLAGS "-idirafter /build/toolchain/lin32/glibc-2007q3-51/usr/include")
  else ()
    set(EXTRA_FLAGS "")
  endif ()
  set(CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER} "${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}} ${ARCH_CFLAGS} ${WARN} ${EXTRA_FLAGS}")
else (UNIX)
  # FIXME: fix warnings and up to /W4
  set(WARN "/W2 /WX")
  # update flags for our types and Debug (tests always use Debug).
  # ok to double-update b/c these are are regex-replace.
  foreach (config ${CMAKE_BUILD_TYPE} ${CMAKE_CONFIGURATION_TYPES} Debug)
    string(TOUPPER "${config}" config_upper)
    foreach (var CMAKE_C_FLAGS;CMAKE_CXX_FLAGS;
        CMAKE_C_FLAGS_${config_upper};
        CMAKE_CXX_FLAGS_${config_upper})
      # default from cmake has /W3 so remove to avoid warning about overriding
      string(REGEX REPLACE "/W[0-9]" "" ${var} "${${var}}")
      # /GZ requires RTC runtime support which we don't want (i#925)
      string(REGEX REPLACE "/GZ" "" ${var} "${${var}}")
      # avoid warnings (i#925)
      string(REGEX REPLACE "/GX" "/EHsc" ${var} "${${var}}")
    endforeach ()
  endforeach ()
  # disable stack protection: "unresolved external symbol ___security_cookie"
  set(CL_CFLAGS "/GS-")
  # build in parallel, always.
  # note that /MP is not officially supported on VS 2005 and others
  # have seen occasional problems: we'll risk it.  we could check for
  # "MSVC10 OR MSVC90".
  set(CL_CFLAGS "${CL_CFLAGS} /MP")
  set(CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER} "${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}} ${WARN} ${CL_CFLAGS}")
endif (UNIX)
set(CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER} "${CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER}} ${ARCH_CFLAGS} ${WARN}")
string(STRIP "${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}"
  CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER})
string(STRIP "${CMAKE_CXX_FLAGS}" CMAKE_CXX_FLAGS)

include(CheckIncludeFiles)
check_include_files("asm-i386/stat.h" HAVE_ASM_I386)
if (HAVE_ASM_I386)
  # see comments abouve about adding configure.h
  set(DEFINES ${DEFINES} -DHAVE_ASM_I386)
endif (HAVE_ASM_I386)

if (UNIX)
  # We don't want our instrument_init() pre-empted by debug-internal DynamoRIO
  # that has visible internal routines.
  # Check for -fvisibility: code from DynamoRIO's CMakeLists.txt
  # I tried cmake's CheckCCompilerFlag but it doesn't seem to work
  execute_process(COMMAND
    ${CMAKE_C_COMPILER} -v --help
    RESULT_VARIABLE gcc_result
    ERROR_QUIET
    OUTPUT_VARIABLE gcc_out)
  if (gcc_result)
    message(FATAL_ERROR "*** ${CMAKE_C_COMPILER} failed to run ***\n")
  endif (gcc_result)
  string(REGEX MATCH "fvisibility" flag_present "${gcc_out}")
  if (NOT flag_present)
    message("${CMAKE_C_COMPILER} missing flag -fvisibility, using linker script instead")
    set(HAVE_FVISIBILITY OFF)
  else (NOT flag_present)
    set(HAVE_FVISIBILITY ON)
  endif (NOT flag_present)
  if (HAVE_FVISIBILITY)
    # Only export functions so marked via attributes
    set(CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}
      "${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}} -fvisibility=internal")
  endif (HAVE_FVISIBILITY)
endif (UNIX)

if (WIN32)
  # We need to link with ntdll.lib
  # Use convention of DynamoRIO sources: DDKROOT env var (or DDK_ROOT cmake var)
  set(DDK_ROOT "$ENV{DDKROOT}" CACHE PATH "Path to DDK.")
  if ("${DDK_ROOT}" STREQUAL "")
    # Check default install path
    if (EXISTS "$ENV{SYSTEMDRIVE}/WINDDK/3790.1830/")
      set(DDK_ROOT "$ENV{SYSTEMDRIVE}/WINDDK/3790.1830/")
    elseif (EXISTS "$ENV{SYSTEMDRIVE}/WINDDK/6000/")
      set(DDK_ROOT "$ENV{SYSTEMDRIVE}/WINDDK/6000/")
    elseif (EXISTS "$ENV{SYSTEMDRIVE}/WINDDK/7600.16385.1/")
      set(DDK_ROOT "$ENV{SYSTEMDRIVE}/WINDDK/7600.16385.1/")
    endif ()
  endif ("${DDK_ROOT}" STREQUAL "")
  # Note that we want the oldest ntdll.lib for maximum compatibility.
  # The 2003 DDK (3790.1830) or Vista WDK (6000) both have these paths:
  if (X64)
    set(NTDLL_LIB_SUBPATH lib/wnet/amd64)
  else (X64)
    # Newer WDK (7600.16385.1) does not have w2k so use wxp: if using
    # that WDK, won't be able to run on 2K or NT.
    if (EXISTS "${DDK_ROOT}/lib/w2k/i386")
      set(NTDLL_LIB_SUBPATH lib/w2k/i386)
    else (EXISTS "${DDK_ROOT}/lib/w2k/i386")
      message(STATUS "DDK/WDK is too recent: no support for Windows 2000 or earlier")
      set(NTDLL_LIB_SUBPATH lib/wxp/i386)
    endif (EXISTS "${DDK_ROOT}/lib/w2k/i386")
  endif (X64)
  # Use find_library() and not find_path() in case on LIB env var or sthg
  find_library(NTDLL_LIBPATH ntdll.lib HINTS "${DDK_ROOT}/${NTDLL_LIB_SUBPATH}"
    DOC "Path to ntdll.lib from either 2003 DDK (3790.1830) or Vista WDK (6000)")
  if (NTDLL_LIBPATH-NOTFOUND OR NOT EXISTS "${NTDLL_LIBPATH}")
    message(FATAL_ERROR "ntdll.lib not found: required to build")
  endif (NTDLL_LIBPATH-NOTFOUND OR NOT EXISTS "${NTDLL_LIBPATH}")
  message(STATUS "Found ntdll.lib: ${NTDLL_LIBPATH}")
  get_filename_component(NTDLL_LIBPATH "${NTDLL_LIBPATH}" PATH)
  link_directories(${NTDLL_LIBPATH})

  # We can't include directly from DDK b/c the DDK include dir and VS include
  # dirs are incompatible, so we have our own copies of the headers we need.
  include_directories(wininc/psdk wininc/dxsdk)

  # We need a newer version of dbghelp.dll than is in system32/ on 2K or XP.
  # It is redistributable: "you can distribute the DLL with your application".
  # 6.3+ works, 5.2 does not, haven't tested in between.
  # WINDDK/3790.1830/bin/x86/dbghelp.dll is 6.3.
  if (X64)
    # FIXME i#908: it seems cmake has trouble to lookup dbghelp.dll in
    # 64-bit directory, so we just explicitly check several possible locations
    # WinDDK/7600.16385.1/tools/tracing/amd64
    # Microsoft Visual Studio 9.0/Common7/IDE\Remote Debugger/x64
    if (EXISTS "${DDK_ROOT}/tools/tracing/amd64/dbghelp.dll")
      set(DBGHELP_DLL "${DDK_ROOT}/tools/tracing/amd64/dbghelp.dll")
    elseif (EXISTS "$ENV{PROGRAMW6432}/Debugging Tools for Windows/dbghelp.dll")
      set(DBGHELP_DLL "$ENV{PROGRAMW6432}/Debugging Tools for Windows/dbghelp.dll")
    elseif (EXISTS "$ENV{PROGRAMW6432}/Microsoft Visual Studio 9.0/Common7/IDE/Remote Debugger/x64/dbghelp.dll")
      set(DBGHELP_DLL "$ENV{PROGRAMW6432}/Microsoft Visual Studio 9.0/Common7/IDE/Remote Debugger/x64/dbghelp.dll")
    else ()
      message(FATAL_ERROR "dbghelp.dll required and not found")
    endif ()
  elseif (EXISTS "${DDK_ROOT}/bin/x86/dbghelp.dll")
    set(DBGHELP_DLL "${DDK_ROOT}/bin/x86/dbghelp.dll")
  else ()
    file(GLOB dbghelp_hint "$ENV{PROGRAMFILES}/Debugging Tools for Windows/dbghelp.dll")
    find_file(DBGHELP_DLL dbghelp.dll HINTS "${dbghelp_hint}"
      DOC "location of dbghelp.dll from recent Debugging Tools for Windows")
    if (DBGHELP_DLL-NOTFOUND OR NOT EXISTS "${DBGHELP_DLL}")
      message(FATAL_ERROR "dbghelp.dll required and not found")
    else ()
      message(STATUS "Using ${DBGHELP_DLL}")
    endif ()
  endif ()

  file(GLOB symsrv_hint "$ENV{PROGRAMFILES}/Debugging Tools for Windows/symsrv.dll")
  find_file(SYMSRV_DLL symsrv.dll HINTS "${symsrv_hint}"
    DOC "location of symsrv.dll from recent Debugging Tools for Windows")
  if (SYMSRV_DLL-NOTFOUND OR NOT EXISTS "${SYMSRV_DLL}")
    message(FATAL_ERROR "symsrv.dll required and not found")
  else ()
    message(STATUS "Using ${SYMSRV_DLL}")
  endif ()

endif (WIN32)

# To run out of build dir we put libs and scripts in dirs that match install layout
# except minus the toolname prefix dir.
# The CPack NSIS interface requires a bin/ dir, so for the Windows package
# we prefix bin/
# XXX: should clean all this up and normalize across platforms now
# that we have drsyms on Linux and once we're sure we don't need to
# support the old layout.
if (WIN32 AND USE_DRSYMS AND TOOL_DR_MEMORY)
  set(INSTALL_BIN_PREFIX ".")
  set(BUILD_BIN_PREFIX ".")
elseif (PERL_TO_EXE)
  # We are only releasing Dr. Memory so no toolnames: would need to create
  # shortcut or .bat file to run from right dir
  if (X64)
    set(INSTALL_BIN_PREFIX "bin64")
    set(BUILD_BIN_PREFIX "bin64")
  else (X64)
    set(INSTALL_BIN_PREFIX "bin")
    set(BUILD_BIN_PREFIX "bin")
  endif (X64)
else (PERL_TO_EXE)
  # When installed we now use a bin dir for scripts
  if (X64)
    set(INSTALL_BIN_PREFIX "${toolname}/bin64")
    set(BUILD_BIN_PREFIX "bin64")
  else (X64)
    set(INSTALL_BIN_PREFIX "${toolname}/bin")
    set(BUILD_BIN_PREFIX "bin")
  endif (X64)
endif (WIN32 AND USE_DRSYMS AND TOOL_DR_MEMORY)
if (WIN32 AND USE_DRSYMS AND TOOL_DR_MEMORY)
  # For NSIS we have everything in top-level bin/
  # Once we have x64 we'll need to address: fix CPack?
  if (X64)
    set(INSTALL_BIN "${INSTALL_BIN_PREFIX}/bin64")
    set(BUILD_BIN "${BUILD_BIN_PREFIX}/bin64")
  else (X64)
    set(INSTALL_BIN "${INSTALL_BIN_PREFIX}/bin")
    set(BUILD_BIN "${BUILD_BIN_PREFIX}/bin")
  endif (X64)
else (WIN32 AND USE_DRSYMS AND TOOL_DR_MEMORY)
  set(INSTALL_BIN "${INSTALL_BIN_PREFIX}/${BIN_ARCH}")
  set(BUILD_BIN "${BUILD_BIN_PREFIX}/${BIN_ARCH}")
endif (WIN32 AND USE_DRSYMS AND TOOL_DR_MEMORY)
if (DEBUG_BUILD)
  set(build_type "debug")
else (DEBUG_BUILD)
  set(build_type "release")
endif (DEBUG_BUILD)
set(INSTALL_LIB "${INSTALL_BIN}/${build_type}")
set(BUILD_LIB "${BUILD_BIN}/${build_type}")

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/${BUILD_LIB}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/${BUILD_BIN}")
if ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
  # we don't support the Debug and Release subdirs
  foreach (config ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER "${config}" config_upper)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${config_upper}
      "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${config_upper}
      "${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}")
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${config_upper}
      "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
  endforeach ()
endif ()

##################################################
# option sharing (PR 478146)

if (UNIX)
  # "gcc -E" on a non-.c-extension file gives message:
  #   "linker input file unused because linking not done"
  # and doesn't produce any output, so we must use cpp for our .asm files.
  # we assume it's in the same dir.
  get_filename_component(compiler_path ${CMAKE_C_COMPILER} PATH)
  find_program(CMAKE_CPP cpp HINTS "${compiler_path}" DOC "path to C preprocessor")
  if (cpp-NOTFOUND OR NOT EXISTS "${CMAKE_CPP}")
    message(FATAL_ERROR "cpp is required to build")
  endif (cpp-NOTFOUND OR NOT EXISTS "${CMAKE_CPP}")
  mark_as_advanced(CMAKE_CPP)
  set(CPP_NO_LINENUM -P)
else (UNIX)
  set(CMAKE_CPP ${CMAKE_C_COMPILER})
  set(CPP_NO_LINENUM /EP)
endif (UNIX)

# I would share this name w/ drmemory.pl but it's a pain to configure_file
# or generate the perl script as we also have to compile it for pp.
set(options_for_perl "${PROJECT_BINARY_DIR}/${BUILD_BIN_PREFIX}/options-perl.pl")
add_custom_target(options_perl ALL DEPENDS "${options_for_perl}")
add_custom_command(
  OUTPUT "${options_for_perl}"
  DEPENDS "${PROJECT_SOURCE_DIR}/common/options-perl.c"
  "${PROJECT_SOURCE_DIR}/${tooldir}/optionsx.h"
  COMMAND ${CMAKE_CPP} 
  ARGS -E ${CPP_NO_LINENUM} "${PROJECT_SOURCE_DIR}/common/options-perl.c"
  -I${PROJECT_SOURCE_DIR}/${tooldir} ${DEFINES} > "${options_for_perl}"
  VERBATIM)

# options_for_docs is built in docs/CMakeLists.txt since custom commands
# are directory-local

##################################################
# utility functions

function (append_property_string type target name value)
  # XXX: if we require cmake 2.8.6 we can simply use APPEND_STRING
  get_property(cur ${type} ${target} PROPERTY ${name})
  if (cur)
    set(value "${cur} ${value}")
  endif (cur)
  set_property(${type} ${target} PROPERTY ${name} "${value}")
endfunction (append_property_string)

function (set_output_dirs dir)
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${dir}" PARENT_SCOPE)
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${dir}" PARENT_SCOPE)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${dir}" PARENT_SCOPE)
  if ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
    # we don't support the Debug and Release subdirs
    foreach (config ${CMAKE_CONFIGURATION_TYPES})
      string(TOUPPER "${config}" config_upper)
      set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${config_upper}
        "${dir}" PARENT_SCOPE)
      set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${config_upper}
        "${dir}" PARENT_SCOPE)
      set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${config_upper}
        "${dir}" PARENT_SCOPE)
    endforeach ()
  endif ()
endfunction (set_output_dirs)

##################################################
# find DynamoRIO so tests has its path, but don't include it or run
# its configure commands to avoid changing cflags:

# we write DynamoRIO_DIR to the cache, so on re-interpreting the file later
# we can't tell whether the user set a value or not. we could
# use a differently-named var for the user but instead we check vs
# the local build path to avoid breaking existing scripts.
set(LOCAL_DynamoRIO_DIR "${PROJECT_BINARY_DIR}/dynamorio/cmake")
if (DEFINED DynamoRIO_DIR AND NOT "${DynamoRIO_DIR}" STREQUAL "${LOCAL_DynamoRIO_DIR}")
  set(USER_SPECIFIED_DynamoRIO_DIR ON)
else ()
  set(USER_SPECIFIED_DynamoRIO_DIR OFF)
endif ()

# when updating this, also update the svn:externals prop on trunk/
set(DynamoRIO_VERSION_REQUIRED "3.0.0")

if (USER_SPECIFIED_DynamoRIO_DIR)
  # i#67: relative dirs are not really supported in find_package: they're
  # relative to source dir not build dir, so we change that here.
  # we can't do get_filename_component(... ABSOLUTE) b/c it's relative to
  # source dir as well.
  if ("${DynamoRIO_DIR}" MATCHES "^\\.\\.")
    get_filename_component(DynamoRIO_DIR "${PROJECT_BINARY_DIR}/${DynamoRIO_DIR}" ABSOLUTE)
  endif ()
  # exit if it doesn't exist since very misleading if find_package() goes
  # and finds some other version from what was requested
  if (NOT EXISTS "${DynamoRIO_DIR}/DynamoRIOConfig.cmake")
    message(FATAL_ERROR "${DynamoRIO_DIR}/DynamoRIOConfig.cmake does not exist: invalid DynamoRIO_DIR")
  endif ()

  # ensure was built w/ static ext libs
  if (UNIX)
    set(LIB_EXT "so")
    set(LIB_PFX "lib")
  else (UNIX)
    set(LIB_EXT "dll")
    set(LIB_PFX "")
  endif (UNIX)
  if (EXISTS "${DynamoRIO_DIR}/../ext/${LIB_ARCH}/${build_type}/${LIB_PFX}drwrap.${LIB_EXT}" OR
      EXISTS "${DynamoRIO_DIR}/../ext/${LIB_ARCH}/${build_type}/${LIB_PFX}drutil.${LIB_EXT}" OR
      EXISTS "${DynamoRIO_DIR}/../ext/${LIB_ARCH}/${build_type}/${LIB_PFX}drmgr.${LIB_EXT}")
    message(FATAL_ERROR "${DynamoRIO_DIR} was built with dynamic extensions: please re-build with static extension libraries")
  endif ()
  if (STATIC_DRSYMS AND EXISTS "${DynamoRIO_DIR}/../ext/${LIB_ARCH}/${build_type}/${LIB_PFX}drsyms.${LIB_EXT}")
    message(FATAL_ERROR "${DynamoRIO_DIR} was built with dynamic drsyms: please re-build with static drsyms")
  endif ()

  message(STATUS "Attempting to use pre-built DynamoRIO: ${DynamoRIO_DIR}")
  find_package(DynamoRIO ${DynamoRIO_VERSION_REQUIRED})
  if (NOT DynamoRIO_FOUND)
    message(FATAL_ERROR "DynamoRIO package required to build")
  endif(NOT DynamoRIO_FOUND)
  # from here on use what was found, not what was passed in
  get_filename_component(DynamoRIO_DIR "${DynamoRIO_CONFIG}" PATH)
  # preserve real value in the cache so it's easy to tell
  set(DynamoRIO_DIR "${DynamoRIO_DIR}" CACHE PATH "Path to DynamoRIO.")
  message(STATUS "DynamoRIO that matches: ${DynamoRIO_VERSION} in ${DynamoRIO_DIR}")
else (USER_SPECIFIED_DynamoRIO_DIR)
  # Build from our local copy of the sources, coming from an svn external: i#74.
  set(DynamoRIO_DIR "${LOCAL_DynamoRIO_DIR}" CACHE PATH "Path to DynamoRIO.")
  message(STATUS "Building DynamoRIO from local sources ${DynamoRIO_DIR}")

  # DR clobbers the global cflags, so we save and then restore them
  foreach (config "" ${CMAKE_BUILD_TYPE} ${CMAKE_CONFIGURATION_TYPES})
    if ("${config}" STREQUAL "")
      set(config_upper "")
    else ("${config}" STREQUAL "")
      string(TOUPPER "_${config}" config_upper)
    endif ("${config}" STREQUAL "")
    foreach (var CMAKE_C_FLAGS${config_upper};CMAKE_CXX_FLAGS${config_upper})
      set(ORIG_${var} "${${var}}")
    endforeach (var)
  endforeach (config)

  # We include DynamoRIO as a subdir here to make it easy to use the
  # DynamoRIOConfig.cmake at configure time: however, that also means we have
  # potential conflicts in CMake's global option and target space.
  # Ideally, DynamoRIO would prefix all its options and targets with "DR_"
  # or something.  For now we live w/ the ugliness.
  # (An alternative would be to use the ExternalProject feature: but
  # then we don't have DynamoRIOConfig.cmake at config time and we'd
  # either need a parent build project or to hack our find_package().)

  # it seems that we must set these in the cache for the subproj to see them:
  set(BUILD_DOCS OFF CACHE BOOL "DynamoRIO option: build client samples")
  set(BUILD_SAMPLES OFF CACHE BOOL "DynamoRIO option: build documentation")
  # our local DR build matches our own build type
  if ("${CMAKE_BUILD_TYPE}" MATCHES "Debug")
    set(DEBUG ON CACHE BOOL "DynamoRIO option: debug build")
    set(INTERNAL ON CACHE BOOL "DynamoRIO option: internal build")
  endif ("${CMAKE_BUILD_TYPE}" MATCHES "Debug")
  # for efficiency, have all our extensions be static.  we have the same
  # LGPL license as drutil and drwrap so it works out.
  set(DR_EXT_DRWRAP_STATIC ON CACHE BOOL "static drwrap")
  set(DR_EXT_DRUTIL_STATIC ON CACHE BOOL "static drutil")
  set(DR_EXT_DRMGR_STATIC ON CACHE BOOL "static drmgr")
  if (STATIC_DRSYMS)
    # N.B.: static drsyms gives us kernel32 imports from elftoolchain
    # libc use.  If we end up needing late kernel32 use for early
    # injection we may want to go back to dynamic drsyms (and delayed
    # dr_enable_console_printing()).
    set(DR_EXT_DRSYMS_STATIC ON CACHE BOOL "static drsyms")
  endif (STATIC_DRSYMS)

  # we do not want DR install
  set(DO_DR_INSTALL OFF)

  add_subdirectory(dynamorio)

  # don't show DR options in drmem cmake list
  # to really hide we should mark as INTERNAL but not worth it since would
  # have to do for all of DR's many options.
  # see comment above about DR prefixing its options.
  mark_as_advanced(BUILD_CORE BUILD_DOCS BUILD_SAMPLES BUILD_EXT BUILD_TESTS
      BUILD_TOOLS DEBUG INTERNAL)

  # do not import dynamorio lib target: we'd end up w/ duplicate
  # dynamorio targets
  set(DynamoRIO_INTERNAL ON)
  # our included DynamoRIO project will set DynamoRIO_SOURCE_DIR in cache
  # for us so we'll get proper include dirs for extensions.

  find_package(DynamoRIO ${DynamoRIO_VERSION_REQUIRED})
  if (NOT DynamoRIO_FOUND OR
      # make sure it didn't go find some other pre-built version after
      # seeing that the local one is somehow not suitable
      NOT "${DynamoRIO_CONFIG}" STREQUAL "${DynamoRIO_DIR}/DynamoRIOConfig.cmake")
    message(FATAL_ERROR "Local DynamoRIO mis-configured")
  endif ()

  # Restore global flags
  foreach (config "" ${CMAKE_BUILD_TYPE} ${CMAKE_CONFIGURATION_TYPES})
    if ("${config}" STREQUAL "")
      set(config_upper "")
    else ("${config}" STREQUAL "")
      string(TOUPPER "_${config}" config_upper)
    endif ("${config}" STREQUAL "")
    foreach (var CMAKE_C_FLAGS${config_upper};CMAKE_CXX_FLAGS${config_upper})
      set(${var} "${ORIG_${var}}")
    endforeach (var)
  endforeach (config)
endif (USER_SPECIFIED_DynamoRIO_DIR)

if (USER_SPECIFIED_DynamoRIO_DIR)
  # if we're building from our own DR, DR adds this option for us
  option(GENERATE_PDBS "generate Windows debug information" ON)
  mark_as_advanced(GENERATE_PDBS)
endif (USER_SPECIFIED_DynamoRIO_DIR)

# This must be before any add_library() or add_executable()
# but that means for local DR sources we haven't yet included
# DR's option(), so we check whether defined.
if (DEFINED GENERATE_PDBS AND NOT GENERATE_PDBS)
  # Default from cmake in DEBUG and RELWITHDEBINFO has /debug
  foreach (var CMAKE_C_FLAGS;CMAKE_CXX_FLAGS;
      CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER};
      CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER};
      # tests are always built as Debug
      CMAKE_C_FLAGS_DEBUG;CMAKE_CXX_FLAGS_DEBUG)
    string(REGEX REPLACE "/Zi" "" ${var} "${${var}}")
  endforeach ()
  foreach (var CMAKE_EXE_LINKER_FLAGS_${CMAKE_BUILD_TYPE_UPPER};
      CMAKE_MODULE_LINKER_FLAGS_${CMAKE_BUILD_TYPE_UPPER};
      CMAKE_SHARED_LINKER_FLAGS_${CMAKE_BUILD_TYPE_UPPER};
      # tests are always built as Debug
      CMAKE_EXE_LINKER_FLAGS_DEBUG;
      CMAKE_MODULE_LINKER_FLAGS_DEBUG;
      CMAKE_SHARED_LINKER_FLAGS_DEBUG)
    string(REGEX REPLACE "/debug" "" ${var} "${${var}}")
  endforeach ()
endif (DEFINED GENERATE_PDBS AND NOT GENERATE_PDBS)

##################################################
# now that we have ${DynamoRIO_DIR} we can configure docs

find_package(Doxygen)
if (NOT DOXYGEN_FOUND)
  message("doxygen is required to build the documentation")
else ()
  add_subdirectory(docs)
endif ()

##################################################
# assembly support

# set up assembly support and CMAKE_CPP
include(${DynamoRIO_DIR}/cpp2asm_support.cmake)
if (UNIX)
  if (NOT CMAKE_ASM_SUPPORTS_INTEL_SYNTAX)
    message(FATAL_ERROR "${CMAKE_ASM_COMPILER} does not support required flags")
  endif (NOT CMAKE_ASM_SUPPORTS_INTEL_SYNTAX)
endif (UNIX)
# for cpp2asm_defines.h
include_directories(${DynamoRIO_DIR})

# XXX: even if we went to a configure.h, we wouldn't have the DR platform
# defines there unless we duplicated them.
if (UNIX)
  set(DEFINES ${DEFINES} -DASSEMBLE_WITH_GAS)
else (UNIX)
  set(DEFINES ${DEFINES} -DASSEMBLE_WITH_MASM)
endif (UNIX)
get_DynamoRIO_defines(DR_DEFINES OFF)
# We need defines to be a list to pass as separate args to custom command.
# We assume none have spaces inside them which seems reasonable.
string(REPLACE " " ";" DR_DEFINES "${DR_DEFINES}")
set(asm_defs ${DR_DEFINES} ${DEFINES} -I "${DynamoRIO_DIR}")

set(asm_deps "${DynamoRIO_DIR}/cpp2asm_defines.h")

add_asm_target(common/asm_utils.asm asm_utils_src asm_utils_tgt ""
  "${asm_defs}" "${asm_deps}")

##################################################

if (WIN32)
  set(FLAG_DISABLE_FPO "/Oy-")
else (WIN32)
  set(FLAG_DISABLE_FPO "-fno-omit-frame-pointer")
endif (WIN32)

function(append_src_compile_flags srcfile new_flags)
  get_source_file_property(cur_flags ${srcfile} COMPILE_FLAGS)
  # XXX: if we require cmake 2.8.6 we can simply use APPEND_STRING
  if (NOT cur_flags)
    set(cur_flags "")
  endif (NOT cur_flags)
  set_source_files_properties(${srcfile} PROPERTIES
    COMPILE_FLAGS "${cur_flags} ${new_flags}")
endfunction(append_src_compile_flags)

# new set_property() doesn't want -D but our cpp invocation above does
string(REGEX REPLACE "-D" "" DEFINES_NO_D "${DEFINES}")
string(REGEX REPLACE "-D" "" DR_DEFINES_NO_D "${DR_DEFINES}")

option(BUILD_TOOL_TESTS "build Dr. Memory/Dr. Heapstat tests" ON)
if (BUILD_TOOL_TESTS)
  # configure tests before configure_DynamoRIO_client or
  # add_subdirectory(dynamorio) clears global cflags
  enable_testing()
  add_subdirectory(tests)
endif (BUILD_TOOL_TESTS)

if (TOOL_DR_HEAPSTAT)
  # Dr. Heapstat
  set(srcs
    drheapstat/drheapstat.c
    drheapstat/staleness.c
    common/alloc.c
    common/alloc_unopt.c
    common/alloc_replace.c
    common/heap.c
    common/callstack.c
    common/utils.c
    ${asm_utils_src}
    common/redblack.c
    common/crypto.c
    # For leak checking we need stack.c but it pulls in the inter-dependent
    # readwrite, fastpath, and shadow: we'll want those for staleness anyway.
    # Looking more and more like Dr. Memory!
    drmemory/annotations.c
    drmemory/leak.c
    drmemory/options.c
    drmemory/stack.c
    drmemory/readwrite.c
    drmemory/fastpath.c
    drmemory/shadow.c
    drmemory/perturb.c)
else (TOOL_DR_HEAPSTAT)
  # Dr. Memory
  set(srcs
    drmemory/annotations.c
    drmemory/drmemory.c
    drmemory/readwrite.c
    drmemory/fastpath.c
    drmemory/stack.c
    drmemory/shadow.c
    drmemory/options.c
    drmemory/pattern.c
    common/alloc.c
    common/alloc_unopt.c
    common/alloc_replace.c
    common/heap.c
    common/callstack.c
    drmemory/alloc_drmem.c
    drmemory/syscall.c
    drmemory/report.c
    drmemory/replace.c
    drmemory/leak.c
    drmemory/perturb.c
    common/utils.c
    ${asm_utils_src}
    common/redblack.c
    common/crypto.c)
  if (UNIX)
    set(srcs ${srcs} drmemory/syscall_linux.c)
  else (UNIX)
    set(srcs ${srcs} drmemory/syscall_windows.c)
    set(srcs ${srcs} drmemory/syscall_wingdi.c)
    set(srcs ${srcs} drmemory/gdicheck.c)
    set(srcs ${srcs} drmemory/handlecheck.c)
    if (SYSCALL_DRIVER)
      set(srcs ${srcs} drmemory/syscall_driver.c)
    endif (SYSCALL_DRIVER)
  endif (UNIX)
endif (TOOL_DR_HEAPSTAT)
set(scripts ${toolname}.pl)
if (NOT USE_DRSYMS)
  set(scripts ${scripts} postprocess.pl)
endif (NOT USE_DRSYMS)

if (USE_DRSYMS)
  set(srcs ${srcs} common/symcache.c)
endif (USE_DRSYMS)

if (WIN32 AND USE_DRSYMS AND TOOL_DR_MEMORY)
  # front-end needs to be name drmemory.exe and thus has drmemory.pdb, so
  # we rename client lib (plus cmake best w/o same-name targets)
  set(client_target "${toolname}lib")
  # assuming only DrMem for now
  add_executable(${toolname} drmemory/frontend.c)
  target_link_libraries(${toolname} dbghelp)
else (WIN32 AND USE_DRSYMS AND TOOL_DR_MEMORY)
  set(client_target ${toolname})
endif (WIN32 AND USE_DRSYMS AND TOOL_DR_MEMORY)

add_library(${client_target} SHARED ${srcs})
set_target_properties(${client_target} PROPERTIES
  VERSION ${TOOL_VERSION_NUMBER})
set_property(TARGET ${client_target} PROPERTY COMPILE_DEFINITIONS ${DEFINES_NO_D})
if ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
  # ensure race-free parallel builds
  add_dependencies(${client_target} ${asm_utils_tgt})
endif ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")

# We require frames in our replacement routines in order to reliably include
# the allocator routines in the callstack for i#639.  Xref i#958.
append_src_compile_flags(common/alloc_replace.c ${FLAG_DISABLE_FPO})

if (WIN32)
  # our addr2line for Windows
  add_executable(winsyms tools/winsyms.c)
  target_link_libraries(winsyms dbghelp)
  # configure_DynamoRIO_client clears global flags so add as additional
  # request static libc to avoid manifest files and libc portability issues
  string(REGEX REPLACE "/MD" "/MT" CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}
    "${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")
  set_source_files_properties(tools/winsyms.c PROPERTIES
    COMPILE_FLAGS "${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")
endif (WIN32)

# we want a preferred base to avoid patching pcaches
set(DynamoRIO_SET_PREFERRED_BASE ON)
set(PREFERRED_BASE 0x73800000)

set(DynamoRIO_REG_COMPATIBILITY ON)
if (STATIC_DRSYMS)
  set(DynamoRIO_USE_LIBC ON)
endif (STATIC_DRSYMS)
configure_DynamoRIO_client(${client_target})
# i#277/PR 540817: features split into DynamoRIO Extensions
use_DynamoRIO_extension(${client_target} drcontainers)
use_DynamoRIO_extension(${client_target} drmgr)
use_DynamoRIO_extension(${client_target} drutil)
use_DynamoRIO_extension(${client_target} drwrap)
set_target_properties(${client_target} PROPERTIES
  # dlls are put in runtime dir but we want lib dir
  RUNTIME_OUTPUT_DIRECTORY${location_suffix} "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
if (WIN32)
  # annoying to have ASLR and not on module list
  # plus, now we require the same base for pcache
  set(new_flags "/dynamicbase:no")
  if (NOT DEFINED GENERATE_PDBS OR GENERATE_PDBS)
    set(new_flags "${new_flags} /debug")
  endif ()
  get_target_property(cur_flags ${client_target} LINK_FLAGS)
  if (NOT cur_flags)
    set(cur_flags "")
  endif (NOT cur_flags)
  set_target_properties(${client_target} PROPERTIES
    LINK_FLAGS "${cur_flags} ${new_flags}")
endif (WIN32)
if (WIN32 AND USE_DRSYMS AND TOOL_DR_MEMORY)
  configure_DynamoRIO_standalone(${toolname})
  target_link_libraries(${toolname} drinjectlib drconfiglib)
  set_target_properties(${toolname} PROPERTIES
    VERSION ${TOOL_VERSION_NUMBER})
  set_property(TARGET ${toolname} PROPERTY COMPILE_DEFINITIONS ${DEFINES_NO_D})
endif (WIN32 AND USE_DRSYMS AND TOOL_DR_MEMORY)
if (USE_DRSYMS)
  use_DynamoRIO_extension(${client_target} drsyms)
endif (USE_DRSYMS)
if (WIN32)
  # we have to link with ntdll AFTER any libcmt.lib from configure_DynamoRIO_client
  # or use_DynamoRIO_extension (w/ static libs)
  target_link_libraries(${client_target} ntdll)
  # we used to statically link with msvcrt.lib for vc /O2's use of __aulldvrm,
  # and it didn't add any dynamic dependence on libc, except now that we
  # use static extension libraries it does add msvcr*.dll imports!
  # so I removed "msvcrt" from target_link_libraries() and so far haven't
  # hit the __aulldvrm issue.
endif (WIN32)

#
##################################################

# must be AFTER DR local build since affects subdirs
include_directories(common ${tooldir} "third_party/valgrind")
if (SYSCALL_DRIVER)
  include_directories(${SYSCALL_DRIVER_SRCDIR})
endif (SYSCALL_DRIVER)

if (UNIX)
  set(DISABLE_OPTS "-O0")
else (UNIX)
  set(DISABLE_OPTS "/Od")
endif (UNIX)
# XXX: if we require cmake 2.8.6 we can use APPEND_STRING.
# Or we could redo all our flags to be lists and use APPEND.
get_source_file_property(cur_flags common/alloc_unopt.c COMPILE_FLAGS)
if (NOT cur_flags)
  set(cur_flags "")
endif (NOT cur_flags)
set_property(SOURCE common/alloc_unopt.c
  PROPERTY COMPILE_FLAGS "${cur_flags} ${DISABLE_OPTS}")

# Though the swf file isn't an executable it is in ${BIN_ARCH} because it isn't 
# exposed to the users; it isn't in lib because, well, it isn't a lib.
if (TOOL_DR_HEAPSTAT AND BUILD_VISUALIZER)
  add_custom_target(vistool ALL DEPENDS "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${toolname}.swf")
  add_custom_command(
    OUTPUT ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${toolname}.swf
    DEPENDS ${PROJECT_SOURCE_DIR}/${tooldir}/${toolname}.mxml
    COMMAND ${JAVA}
    ARGS -jar ${FLEX_MXMLC} "+flexlib=${FLEX_FRAMEWORKS}"
      ${PROJECT_SOURCE_DIR}/${tooldir}/${toolname}.mxml
      -o ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${toolname}.swf
    VERBATIM)
endif (TOOL_DR_HEAPSTAT AND BUILD_VISUALIZER)

# symbol query tool
add_executable(symquery tools/symquery.c)
configure_DynamoRIO_standalone(symquery)
use_DynamoRIO_extension(symquery drsyms)

# should go into a configure.h if we get enough of these
set(script_aux "")
if (PERL_TO_EXE)
  foreach (pl ${scripts})
    get_filename_component(base ${pl} NAME_WE)
    if ("${pl}" MATCHES "${toolname}.pl")
      set(EXE_DEST "${PROJECT_BINARY_DIR}/${BUILD_BIN_PREFIX}")
      set(script_main ${EXE_DEST}/${base}.exe)
    else ()
      set(EXE_DEST "${PROJECT_BINARY_DIR}/${BUILD_BIN}")
      set(script_aux ${script_aux} ${EXE_DEST}/${base}.exe)
    endif ()
    add_custom_target(${base}_exe ALL DEPENDS ${EXE_DEST}/${base}.exe)
    add_custom_command(
      OUTPUT ${EXE_DEST}/${base}.exe
      DEPENDS ${PROJECT_SOURCE_DIR}/${tooldir}/${pl}
      COMMAND ${PERL_EXECUTABLE}
      # If do glob() w/ spaces in path, need Text::ParseWords, but pp
      # doesn't find it as a dependence automatically.
      # FIXME: use --gui?
      ARGS ${PERL_PP} -M Text::ParseWords -o ${EXE_DEST}/${base}.exe
        ${PROJECT_SOURCE_DIR}/${tooldir}/${pl} ${options_for_perl}
      VERBATIM)
  endforeach (pl)
endif (PERL_TO_EXE)

# support running out of build dir
file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/logs")
file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/logs/codecache")
file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/logs/dynamorio")
if (NOT PERL_TO_EXE AND TOOL_DR_HEAPSTAT OR NOT USE_DRSYMS OR UNIX)
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/${tooldir}/${toolname}.pl"
    "${PROJECT_BINARY_DIR}/${BUILD_BIN_PREFIX}/${toolname}.pl" @ONLY)
  if (NOT USE_DRSYMS)
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/${tooldir}/postprocess.pl"
      "${PROJECT_BINARY_DIR}/${BUILD_BIN}/postprocess.pl" COPYONLY)
    set(script_aux "${CMAKE_CURRENT_SOURCE_DIR}/${tooldir}/postprocess.pl")
  endif (NOT USE_DRSYMS)
  set(script_main "${PROJECT_BINARY_DIR}/${BUILD_BIN_PREFIX}/${toolname}.pl"
    "${options_for_perl}")
endif ()
if (WIN32)
  # copy for winsyms and symquery
  configure_file("${DBGHELP_DLL}"
    "${PROJECT_BINARY_DIR}/${BUILD_BIN}/dbghelp.dll" COPYONLY)
  # Copy symsrv.dll so we can fetch files from the frontend.
  configure_file("${SYMSRV_DLL}"
    "${PROJECT_BINARY_DIR}/${BUILD_BIN}/symsrv.dll" COPYONLY)
  # Create symsrv.yes to avoid the EULA dialog.
  file(WRITE "${PROJECT_BINARY_DIR}/${BUILD_BIN}/symsrv.yes" "")
  if (USER_SPECIFIED_DynamoRIO_DIR)
    # already built so we can copy at config time
    configure_file("${DynamoRIO_DIR}/../${LIB_ARCH}/drconfiglib.dll"
      "${PROJECT_BINARY_DIR}/${BUILD_BIN}/drconfiglib.dll" COPYONLY)
    configure_file("${DynamoRIO_DIR}/../${LIB_ARCH}/drinjectlib.dll"
      "${PROJECT_BINARY_DIR}/${BUILD_BIN}/drinjectlib.dll" COPYONLY)
    if (USE_DRSYMS AND TOOL_DR_MEMORY)
      configure_file("${DynamoRIO_DIR}/../${BIN_ARCH}/drconfig.exe"
        "${PROJECT_BINARY_DIR}/${BUILD_BIN}/drconfig.exe" COPYONLY)
      if (NOT STATIC_DRSYMS)
        # symquery needs drsyms.dll in same dir
        configure_file("${DynamoRIO_DIR}/../ext/${LIB_ARCH}/${build_type}/drsyms.dll"
          "${PROJECT_BINARY_DIR}/${BUILD_BIN}/drsyms.dll" COPYONLY)
      endif (NOT STATIC_DRSYMS)
      # symquery needs dynamorio.dll in same dir
      configure_file("${DynamoRIO_DIR}/../${LIB_ARCH}/${build_type}/dynamorio.dll"
        "${PROJECT_BINARY_DIR}/${BUILD_BIN}/dynamorio.dll" COPYONLY)
    endif (USE_DRSYMS AND TOOL_DR_MEMORY)
  else (USER_SPECIFIED_DynamoRIO_DIR)
    # XXX: I can't get "TARGET drconfiglib POST_BUILD" to work, maybe b/c
    # the target is in a subdir?
    set(drconfiglib_copy "${PROJECT_BINARY_DIR}/${BUILD_BIN}/drconfiglib.dll")
    add_custom_target(drconfiglib_copy_tgt ALL DEPENDS "${drconfiglib_copy}")
    add_custom_command(OUTPUT "${drconfiglib_copy}" DEPENDS drconfiglib
      COMMAND ${CMAKE_COMMAND}
      ARGS -E copy "${DynamoRIO_DIR}/../${LIB_ARCH}/drconfiglib.dll"
      "${drconfiglib_copy}" VERBATIM)
    set(drinjectlib_copy "${PROJECT_BINARY_DIR}/${BUILD_BIN}/drinjectlib.dll")
    add_custom_target(drinjectlib_copy_tgt ALL DEPENDS "${drinjectlib_copy}")
    add_custom_command(OUTPUT "${drinjectlib_copy}" DEPENDS drinjectlib
      COMMAND ${CMAKE_COMMAND}
      ARGS -E copy "${DynamoRIO_DIR}/../${LIB_ARCH}/drinjectlib.dll"
      "${drinjectlib_copy}" VERBATIM)
    if (USE_DRSYMS AND TOOL_DR_MEMORY)
      set(drconfigexe_copy "${PROJECT_BINARY_DIR}/${BUILD_BIN}/drconfig.exe")
      add_custom_target(drconfigexe_copy_tgt ALL DEPENDS "${drconfigexe_copy}")
      add_custom_command(OUTPUT "${drconfigexe_copy}" DEPENDS drconfig
        COMMAND ${CMAKE_COMMAND}
        ARGS -E copy "${DynamoRIO_DIR}/../${BIN_ARCH}/drconfig.exe"
        "${drconfigexe_copy}" VERBATIM)
      if (NOT STATIC_DRSYMS)
        # symquery needs drsyms.dll in same dir
        set(drsymsdll_copy "${PROJECT_BINARY_DIR}/${BUILD_BIN}/drsyms.dll")
        add_custom_target(drsymsdll_copy_tgt ALL DEPENDS "${drsymsdll_copy}")
        add_custom_command(OUTPUT "${drsymsdll_copy}" DEPENDS drsyms
          COMMAND ${CMAKE_COMMAND}
          ARGS -E copy "${DynamoRIO_DIR}/../ext/${LIB_ARCH}/${build_type}/drsyms.dll"
        "${drsymsdll_copy}" VERBATIM)
      endif (NOT STATIC_DRSYMS)
      # symquery needs dynamorio.dll in same dir
      set(drdll_copy "${PROJECT_BINARY_DIR}/${BUILD_BIN}/dynamorio.dll")
      add_custom_target(drdll_copy_tgt ALL DEPENDS "${drdll_copy}")
      add_custom_command(OUTPUT "${drdll_copy}" DEPENDS dynamorio
        COMMAND ${CMAKE_COMMAND}
        ARGS -E copy "${DynamoRIO_DIR}/../${LIB_ARCH}/${build_type}/dynamorio.dll"
        "${drdll_copy}" VERBATIM)
    endif (USE_DRSYMS AND TOOL_DR_MEMORY)
  endif (USER_SPECIFIED_DynamoRIO_DIR)
  if (USE_DRSYMS)
    # above copy is for winsyms and symquery, this is for drmemorylib
    configure_file("${DBGHELP_DLL}"
      "${PROJECT_BINARY_DIR}/${BUILD_LIB}/dbghelp.dll" COPYONLY)
    # We don't need to copy symsrv.dll because only the frontend uses it.
  endif (USE_DRSYMS)
else (WIN32)
  if (USER_SPECIFIED_DynamoRIO_DIR)
    # already built so we can copy at config time
    configure_file("${DynamoRIO_DIR}/../${BIN_ARCH}/drconfig"
      "${PROJECT_BINARY_DIR}/${BUILD_BIN_PREFIX}/drconfig" COPYONLY)
  else (USER_SPECIFIED_DynamoRIO_DIR)
    set(drconfig_copy "${PROJECT_BINARY_DIR}/${BUILD_BIN_PREFIX}/drconfig")
    add_custom_target(drconfig_copy_tgt ALL DEPENDS "${drconfig_copy}")
    add_custom_command(OUTPUT "${drconfig_copy}" 
      COMMAND ${CMAKE_COMMAND}
      ARGS -E copy "${DynamoRIO_DIR}/../${BIN_ARCH}/drconfig"
      "${drconfig_copy}" VERBATIM)
  endif (USER_SPECIFIED_DynamoRIO_DIR)
  if (TOOL_DR_MEMORY)
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/tools/valgrind2drmemory.pl"
      "${PROJECT_BINARY_DIR}/${BUILD_BIN_PREFIX}/valgrind2drmemory.pl" COPYONLY)
  endif (TOOL_DR_MEMORY)
endif (WIN32)
if (TOOL_DR_HEAPSTAT)
  # we need a copy of Dr. Memory's postprocess for leaks (PR 536878)
  if (PERL_TO_EXE)
    message(FATAL_ERROR "perl2exe for Dr. Heapstat not supported")
  endif (PERL_TO_EXE)
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/drmemory/postprocess.pl"
    "${PROJECT_BINARY_DIR}/${BUILD_BIN}/postleaks.pl" COPYONLY)
  set(script_aux ${script_aux} "${PROJECT_BINARY_DIR}/${BUILD_BIN}/postleaks.pl")
endif (TOOL_DR_HEAPSTAT)

# Dr. Memory and Dr. Heapstat use Dr. Memory's default suppressions
set(defsupp_out "${PROJECT_BINARY_DIR}/${BUILD_BIN}/suppress-default.txt")
if (WIN32)
  set(defsupp_in "${CMAKE_CURRENT_SOURCE_DIR}/drmemory/suppress-default.win.txt")
  configure_file("${defsupp_in}" "${defsupp_out}" COPYONLY)
else (WIN32)
  set(defsupp_in "${CMAKE_CURRENT_SOURCE_DIR}/drmemory/suppress-default.lin.txt")
  file(READ "${defsupp_in}" txt)
  file(WRITE "${defsupp_out}" "${txt}")
endif (WIN32)

###########################################################################
# Dr. Memory Framework (DRMF)

# We decided against putting the extension inside frameworks/, so
# framework-shared code goes here.  Things that should be global we
# put into functions for invocation inside extension subdirs.

set(DRMF_BASEDIR "drmf")
set(DRMF_BINBASE "${LIB_ARCH}/${build_type}")
set(DRMF_INSTALL ${DRMF_BASEDIR})
set(DRMF_INSTALL_BIN ${DRMF_BASEDIR}/${DRMF_BINBASE})
set(DRMF_INSTALL_INC ${DRMF_BASEDIR}/include)
set(framework_dir "${PROJECT_BINARY_DIR}/${DRMF_BASEDIR}")
set(framework_incdir "${framework_dir}/include")
set(framework_bindir "${framework_dir}/${DRMF_BINBASE}")

# Versioning: we use separate versioning for DRMF from the tool versioning.
# This is major*100 + minor.
set(DRMF_VERSION_DEFAULT "0.9.${VERSION_NUMBER_PATCHLEVEL}")
set(DRMF_VERSION "" CACHE STRING "DRMF version number: leave empty for default")
if ("${DRMF_VERSION}" STREQUAL "")
  set(DRMF_VERSION ${DRMF_VERSION_DEFAULT})
endif()
message(STATUS "DRMF version number: ${DRMF_VERSION}")
string(REGEX REPLACE "^([0-9]+)\\..*" "\\1" DRMF_VERSION_MAJOR "${DRMF_VERSION}")
string(REGEX REPLACE "^[0-9]+\\.([0-9]+)\\..*" "\\1" DRMF_VERSION_MINOR "${DRMF_VERSION}")
math(EXPR DRMF_VERSION_INTEGER "${DRMF_VERSION_MAJOR}*100 + ${DRMF_VERSION_MINOR}")
set(DRMF_VERSION_COMPAT 9)                # Oldest compatible version
set(DRMF_VERSION_CUR ${DRMF_VERSION_INTEGER}) # Current version

configure_file(framework/public.h
  ${framework_incdir}/drmemory_framework.h)
include_directories(${framework_incdir})

configure_file(framework/drmf.cmake.in
  ${framework_dir}/DrMemoryFrameworkConfig.cmake
  @ONLY)
foreach (ext drsyscall)
  file(APPEND ${framework_dir}/DrMemoryFrameworkConfig.cmake "
set(DynamoRIO_EXT_${ext}_INC \${cwd}/include)
")
endforeach (ext)
configure_file(framework/drmf_version.cmake.in
  ${framework_dir}/DrMemoryFrameworkConfigVersion.cmake
  @ONLY)

# Export extensions for importing by clients.
if (X64)
  set(exported_targets_name "DRMFTarget64")
else (X64)
  set(exported_targets_name "DRMFTarget32")
endif (X64)

# DRi#948: we need to map RelWithDebInfo and RelMinSize to Release
file(WRITE ${framework_dir}/${exported_targets_name}.cmake "")
set(exported_targets_append "")
macro(export_target)
  export(TARGETS ${ARGV} FILE ${framework_dir}/${exported_targets_name}.cmake
    APPEND)
  set(toadd "
SET_PROPERTY(TARGET ${ARGV0} PROPERTY MAP_IMPORTED_CONFIG_RELWITHDEBINFO Release)
SET_PROPERTY(TARGET ${ARGV0} PROPERTY MAP_IMPORTED_CONFIG_RELMINSIZE Release)
")
  if (NOT DEBUG_BUILD)
    file(APPEND ${framework_dir}/${exported_targets_name}.cmake ${toadd})
  endif (NOT DEBUG_BUILD)
  # For install we want both debug and release:
  set(exported_targets_append "${exported_targets_append}${toadd}")
  set(exported_targets_append "${exported_targets_append}" PARENT_SCOPE)
endmacro(export_target)

add_subdirectory(drsyscall)

# XXX: change this to find_package() + use_DynamoRIO_extension(drsyscall)
include_directories(drsyscall)
target_link_libraries(${client_target} drsyscall_int)

if (BUILD_TOOL_TESTS)
  # We want the non-DR-client tests added before DR config, but these client
  # tests added after:
  # FIXME i#1061: disabling until works with non-pre-built-DR
  #add_subdirectory(tests/framework)
endif (BUILD_TOOL_TESTS)

###########################################################################
# installation

if (install_override)
  if (X64)
    set(EXP_DIR exports64)
  else (X64)
    set(EXP_DIR exports32)
  endif (X64)
  set(CMAKE_INSTALL_PREFIX "${PROJECT_BINARY_DIR}/../${EXP_DIR}" 
    CACHE PATH "install path" FORCE)
endif (install_override)
set(INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

install(TARGETS ${client_target}
  RUNTIME DESTINATION "${INSTALL_LIB}" # dll
  LIBRARY DESTINATION "${INSTALL_LIB}" # .so
  PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
  WORLD_READ WORLD_EXECUTE)
if (WIN32)
  install(TARGETS winsyms DESTINATION "${INSTALL_BIN}"
    PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)
  install(FILES
    ${PROJECT_BINARY_DIR}/${BUILD_BIN}/dbghelp.dll
    ${PROJECT_BINARY_DIR}/${BUILD_BIN}/symsrv.dll
    DESTINATION "${INSTALL_BIN}"
    PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)
  install(FILES
    ${PROJECT_BINARY_DIR}/${BUILD_BIN}/symsrv.yes
    DESTINATION "${INSTALL_BIN}")
  if (USE_DRSYMS)
    install(FILES
      ${PROJECT_BINARY_DIR}/${BUILD_BIN}/dbghelp.dll
      DESTINATION "${INSTALL_LIB}"
      PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
      WORLD_READ WORLD_EXECUTE)
  endif (USE_DRSYMS)
  if (USE_DRSYMS AND TOOL_DR_MEMORY)
    install(FILES
      ${PROJECT_BINARY_DIR}/${BUILD_BIN}/drconfiglib.dll
      ${PROJECT_BINARY_DIR}/${BUILD_BIN}/drinjectlib.dll
      # frontend now imports from DR (i#885)
      ${PROJECT_BINARY_DIR}/${BUILD_BIN}/dynamorio.dll
      ${PROJECT_BINARY_DIR}/${BUILD_BIN}/drconfig.exe
      DESTINATION "${INSTALL_BIN}"
      PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
      WORLD_READ WORLD_EXECUTE)
  endif (USE_DRSYMS AND TOOL_DR_MEMORY)
  install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/README
    DESTINATION "."
    RENAME "README.txt")
else (WIN32)
  install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/README
    DESTINATION ".")
endif (WIN32)
if (WIN32 AND USE_DRSYMS AND TOOL_DR_MEMORY)
  install(TARGETS ${toolname} DESTINATION "${INSTALL_BIN}"
    PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)
else (WIN32 AND USE_DRSYMS AND TOOL_DR_MEMORY)
  install(FILES
    ${script_main}
    DESTINATION "${INSTALL_BIN_PREFIX}"
    PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)
endif (WIN32 AND USE_DRSYMS AND TOOL_DR_MEMORY)
# We put "helper" files inside ${BIN_ARCH}/ so only top-level script is visible
if (NOT "${script_aux}" STREQUAL "")
  install(FILES
    ${script_aux}
    DESTINATION "${INSTALL_BIN}"
    PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)
endif ()
if (TOOL_DR_HEAPSTAT)
  if (BUILD_VISUALIZER)
    install(FILES
      ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${toolname}.swf
      DESTINATION "${INSTALL_BIN}"
      PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)
  endif (BUILD_VISUALIZER)
else (TOOL_DR_HEAPSTAT)
  install(FILES
    ${PROJECT_BINARY_DIR}/${BUILD_BIN}/suppress-default.txt
    DESTINATION "${INSTALL_BIN}"
    PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)
  if (UNIX)
    install(FILES
      ${PROJECT_BINARY_DIR}/${BUILD_BIN_PREFIX}/valgrind2drmemory.pl
      DESTINATION "bin"
      PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
      WORLD_READ WORLD_EXECUTE)
  endif (UNIX)
endif (TOOL_DR_HEAPSTAT)
install(DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/
  DESTINATION "${INSTALL_LIB}"
  FILE_PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
  WORLD_READ WORLD_EXECUTE
  FILES_MATCHING
  PATTERN "*.debug"
  PATTERN "*.pdb"
  )
install(DIRECTORY ${PROJECT_BINARY_DIR}/${BUILD_BIN}/
  DESTINATION "${INSTALL_BIN}"
  FILE_PERMISSIONS OWNER_READ OWNER_EXECUTE 
  GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
  FILES_MATCHING
  PATTERN "*.debug"
  PATTERN "*.pdb"
  )

# FIXME: support multi-tool package for Windows perl2exe by creating
# batch file: for now assuming single-tool when perl2exe
if (NOT PERL_TO_EXE AND TOOL_DR_HEAPSTAT OR NOT USE_DRSYMS OR UNIX)
  # b/c there's no way to change permissions other than an install rule,
  # and b/c the $ and @ uses make it hard to configure_file, and
  # I can find no way to generate a symlink at install time, we generate
  # this file at build time.
  # only the DIRECTORY install rule preserves symlinks so we put
  # it in its own dir:
  file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/symlink")
  file(REMOVE "${PROJECT_BINARY_DIR}/symlink/${toolname}.pl")
  if (WIN32)
    # cmake -E create_symlink not supported
    if (USE_DRSYMS) # disabled by above: leaving for example of how to make .bat
      file(WRITE "${PROJECT_BINARY_DIR}/symlink/${toolname}.bat"
        "\"%~dp0..\\drmemory\\${BIN_ARCH}\\drmemory.exe\" %*\n")
    else (USE_DRSYMS)
      file(WRITE "${PROJECT_BINARY_DIR}/symlink/${toolname}.pl"
        "#!/usr/bin/perl\nuse File::Basename;\n(\$nm,\$mypath,\$sfx) = fileparse(\$0);\nexec(\"\$mypath/../${toolname}/bin/${toolname}.pl\", @ARGV);\n")
    endif (USE_DRSYMS)
  else (WIN32)
    execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink
      "../${toolname}/bin/${toolname}.pl"
      "${PROJECT_BINARY_DIR}/symlink/${toolname}.pl"
      RESULT_VARIABLE symlink_result
      ERROR_VARIABLE symlink_error
      OUTPUT_QUIET)
    if (symlink_result OR symlink_error)
      message(FATAL_ERROR "*** ${toolname}.pl symlink failed: ***\n${symlink_error}")
    endif (symlink_result OR symlink_error)
  endif (WIN32)
  install(DIRECTORY "${PROJECT_BINARY_DIR}/symlink/"
    DESTINATION "bin")

  # create top-level html file that redirects
  install(CODE "file(WRITE \"\${CMAKE_INSTALL_PREFIX}/docs/${toolname}.html\" \"<html>\n<head>\n<meta http-equiv=\\\"refresh\\\" content=\\\"0; URL=../${toolname}/docs/html/index.html\\\">\n</head><body></body>\")")
endif (NOT PERL_TO_EXE AND TOOL_DR_HEAPSTAT OR NOT USE_DRSYMS OR UNIX)

# create empty logs dir for release package
# be sure to escape ",$ since evaluated at install time not configure time
install(CODE "file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/${toolname}/logs\")")
# CPack seems to ignore empty dirs so add a README file
install(CODE "file(WRITE \"\${CMAKE_INSTALL_PREFIX}/${toolname}/logs/README\" \"Default destination for log files.\n\")")
# ditto for pcaches
install(CODE "file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/${toolname}/logs/codecache\")")
install(CODE "file(WRITE \"\${CMAKE_INSTALL_PREFIX}/${toolname}/logs/codecache/README\" \"Default destination for code cache files.\n\")")
# ditto for DR logdir
install(CODE "file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/${toolname}/logs/dynamorio\")")
install(CODE "file(WRITE \"\${CMAKE_INSTALL_PREFIX}/${toolname}/logs/codecache/README\" \"Default destination for DynamoRIO log files (for diagnostics only).\n\")")

# Include DR so user doesn't have to download separately (PR 457417).
# We don't need docs/, include/, or 64-bit.
# We do include 32-bit debug lib (and default DR log dir) for
# debugging in the field: it does take space but we'd probably regret
# not supplying it.
set(DR_install_dir "dynamorio")
install(CODE "file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}\")")

if (UNIX)
  # FIXME: CPACK_INSTALLED_DIRECTORIES resolves symlinks instead of preserving
  # (filed as http://www.itk.org/Bug/view.php?id=10096).
  # So, since we're bundling a particular version anyway, we just take the .so
  # file itself and discard all the version-named files
  if (DEBUG_BUILD)
    install(CODE "file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/${LIB_ARCH}/debug\")")
    install(CODE "configure_file(\"${DynamoRIO_DIR}/../${LIB_ARCH}/debug/libdrpreload.so\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/${LIB_ARCH}/debug/\" COPYONLY)")
    install(CODE "configure_file(\"${DynamoRIO_DIR}/../${LIB_ARCH}/debug/libdynamorio.so\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/${LIB_ARCH}/debug/\" COPYONLY)")
    # Include both .debug files.  These have version #s so we glob.
    install(CODE "file(GLOB debugfiles \"${DynamoRIO_DIR}/../${LIB_ARCH}/debug/*.debug\")\nforeach (dbg \${debugfiles})\n  configure_file(\"\${dbg}\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/${LIB_ARCH}/debug/\" COPYONLY)\nendforeach()")
    # ext dir is currently empty but we need it to avoid drrun error (i#427)
    install(CODE "file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/ext/${LIB_ARCH}/debug\")")
    # CPack seems to ignore empty dirs so add a README file
    install(CODE "file(WRITE \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/ext/${LIB_ARCH}/debug/README\" \"Currently empty.\n\")")
  else (DEBUG_BUILD)
    install(CODE "file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/${LIB_ARCH}/release\")")
    install(CODE "configure_file(\"${DynamoRIO_DIR}/../${LIB_ARCH}/release/libdrpreload.so\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/${LIB_ARCH}/release/\" COPYONLY)")
    install(CODE "configure_file(\"${DynamoRIO_DIR}/../${LIB_ARCH}/release/libdynamorio.so\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/${LIB_ARCH}/release/\" COPYONLY)")
    # Include both .debug files.  These have version #s so we glob.
    # Note that addr2line/gdb will still find the 1.x.debug since the name is
    # stored in the library.
    install(CODE "file(GLOB debugfiles \"${DynamoRIO_DIR}/../${LIB_ARCH}/release/*.debug\")\nforeach (dbg \${debugfiles})\n  configure_file(\"\${dbg}\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/${LIB_ARCH}/release/\" COPYONLY)\nendforeach()")
    # ext dir is currently empty but we need it to avoid drrun error (i#427)
    install(CODE "file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/ext/${LIB_ARCH}/release\")")
    # CPack seems to ignore empty dirs so add a README file
    install(CODE "file(WRITE \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/ext/${LIB_ARCH}/release/README\" \"Currently empty.\n\")")
  endif (DEBUG_BUILD)
endif (UNIX)

# can't find way to package external individual files (can do whole dir)
# and we don't need entire DR docs/, include/, etc. so we do these
# files individually
if (EXISTS "${DynamoRIO_SOURCE_DIR}/License.txt")
  set(DR_LICENSE_DIR "${DynamoRIO_SOURCE_DIR}")
else ()
  set(DR_LICENSE_DIR "${DynamoRIO_DIR}/..")
endif ()
install(CODE "configure_file(\"${DR_LICENSE_DIR}/License.txt\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/License.txt\" COPYONLY)")
install(CODE "configure_file(\"${DR_LICENSE_DIR}/ACKNOWLEDGEMENTS\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/ACKNOWLEDGEMENTS\" COPYONLY)")
# rather whan whole README, which talks about running samples, etc.:
install(CODE "file(WRITE \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/README\" \"This is a copy of the parts of DynamoRIO needed to run ${toolname_cap_spc}.  See http://dynamorio.org for more information.\n\")")
# on Windows we don't need all the ${BIN_ARCH}/ tools, and they take up space
install(CODE "file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/${BIN_ARCH}\")")
if (UNIX)
  install(CODE "configure_file(\"${DynamoRIO_DIR}/../${BIN_ARCH}/drrun\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/${BIN_ARCH}/drrun\" COPYONLY)")
  install(CODE "configure_file(\"${DynamoRIO_DIR}/../${BIN_ARCH}/nudgeunix\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/${BIN_ARCH}/nudgeunix\" COPYONLY)")
else (UNIX)
  if (TOOL_DR_HEAPSTAT OR NOT USE_DRSYMS)
    install(CODE "configure_file(\"${DynamoRIO_DIR}/../${BIN_ARCH}/drconfig.exe\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/${BIN_ARCH}/drconfig.exe\" COPYONLY)")
    install(CODE "configure_file(\"${DynamoRIO_DIR}/../${BIN_ARCH}/drinject.exe\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/${BIN_ARCH}/drinject.exe\" COPYONLY)")
    install(CODE "configure_file(\"${DynamoRIO_DIR}/../${BIN_ARCH}/drrun.exe\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/${BIN_ARCH}/drrun.exe\" COPYONLY)")
  endif (TOOL_DR_HEAPSTAT OR NOT USE_DRSYMS)
  install(CODE "configure_file(\"${DynamoRIO_DIR}/../${BIN_ARCH}/drconfiglib.dll\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/${BIN_ARCH}/drconfiglib.dll\" COPYONLY)")
  install(CODE "configure_file(\"${DynamoRIO_DIR}/../${BIN_ARCH}/drinjectlib.dll\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/${BIN_ARCH}/drinjectlib.dll\" COPYONLY)")
  install(CODE "configure_file(\"${DynamoRIO_DIR}/../${BIN_ARCH}/DRcontrol.exe\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/${BIN_ARCH}/DRcontrol.exe\" COPYONLY)")
  install(CODE "configure_file(\"${DynamoRIO_DIR}/../${BIN_ARCH}/DRview.exe\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/${BIN_ARCH}/DRview.exe\" COPYONLY)")
endif (UNIX)

# DRMF install rules
install(FILES ${framework_incdir}/drmemory_framework.h DESTINATION ${DRMF_INSTALL_INC})
install(FILES ${framework_dir}/DrMemoryFrameworkConfigVersion.cmake
  ${framework_dir}/DrMemoryFrameworkConfig.cmake
  DESTINATION ${DRMF_INSTALL})
# These cover all subdirs
install(DIRECTORY ${framework_bindir}/
  DESTINATION ${DRMF_INSTALL_BIN}
  FILE_PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
  WORLD_READ WORLD_EXECUTE
  FILES_MATCHING
  PATTERN "*.debug"
  PATTERN "*.pdb"
  PATTERN "*_int.pdb" EXCLUDE
  )

# We must append to this file to avoid cmake_install.cmake's diff from thinking
# the exports have changed and thus clobbering the other config's files.
install(CODE "file(APPEND \"${PROJECT_BINARY_DIR}/CMakeFiles/Export/cmake/${exported_targets_name}.cmake\" \"${exported_targets_append}\")")
# Create the exported targets file
# FIXME i#1061: disabling until works with non-pre-built-DR
#install(EXPORT ${exported_targets_name} DESTINATION ${DRMF_INSTALL})

###########################################################################
# packaging

# "make package package_source"

if (UNIX)
  # not bothering with TZ or TBZ2 or STGZ (.sh)
  set(CPACK_GENERATOR "TGZ")
  set(CPACK_SOURCE_GENERATOR "TGZ")
  # We've already split out our separate .debug files and stripped the
  # originals in our build rules
  set(CPACK_STRIP_FILES OFF)
  if (VMKERNEL)
    set(CPACK_SYSTEM_NAME "ESXi")
  else (VMKERNEL)
    set(CPACK_SYSTEM_NAME "Linux")
  endif (VMKERNEL)
else (UNIX)
  # do not require NSIS, since we do "make package" as part of test suite
  find_program(NSIS nsis HINT "$ENV{PROGRAMFILES}/NSIS" DOC "NSIS for creating installer")
  if (NSIS)
    message(STATUS "NSIS found: will build installer")
    set(CPACK_GENERATOR "ZIP;NSIS")
  else (NSIS)
    message(STATUS "NSIS not found: will not build installer")
    set(CPACK_GENERATOR "ZIP")
  endif (NSIS)
  set(CPACK_SOURCE_GENERATOR "ZIP")
  set(CPACK_SYSTEM_NAME "Windows")
  if (USE_DRSYMS)
    set(CPACK_SYSTEM_NAME "Windows")
  else (USE_DRSYMS)
    set(CPACK_SYSTEM_NAME "Cygwin")
  endif (USE_DRSYMS)
endif (UNIX)

set(CPACK_PACKAGE_NAME "${toolname_cap_spc}")
set(CPACK_PACKAGE_VENDOR "VMware")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/README")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${toolname_cap_spc} Memory Debugging Tool")
set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/license.txt")
set(CPACK_RESOURCE_FILE_README "${PROJECT_SOURCE_DIR}/README")

set(CPACK_SOURCE_IGNORE_FILES "~$")

set(CPACK_PACKAGE_VERSION "${TOOL_VERSION_NUMBER}")
string(REGEX REPLACE 
  "^([0-9]+)\\..*" "\\1" CPACK_PACKAGE_VERSION_MAJOR "${TOOL_VERSION_NUMBER}")
string(REGEX REPLACE 
  "^[0-9]+\\.([0-9]+)\\..*" "\\1" CPACK_PACKAGE_VERSION_MINOR "${TOOL_VERSION_NUMBER}")
string(REGEX REPLACE 
  "^[0-9]+\\.[0-9]+\\.([0-9]+)" "\\1" CPACK_PACKAGE_VERSION_PATCH "${TOOL_VERSION_NUMBER}")

if (WIN32)
  # Include DR so user doesn't have to download separately (PR 457417).
  # For Unix we do this file-by-file above b/c here we'd get duplicate
  # files due to cpack not preserving symlinks (filed as
  # http://www.itk.org/Bug/view.php?id=10096)
  # We don't need docs/, include/, or 64-bit.
  # We do include 32-bit debug lib (and default DR log dir) for
  # debugging in the field: it does take space but we'd probably regret
  # not supplying it.
  if (NOT USER_SPECIFIED_DynamoRIO_DIR)
    # install to drmemory exports dir
    install(DIRECTORY "${DynamoRIO_DIR}/../${LIB_ARCH}"
      DESTINATION "${DR_install_dir}")
    install(DIRECTORY "${DynamoRIO_DIR}/../ext/${LIB_ARCH}"
      DESTINATION "${DR_install_dir}/ext")
  else (NOT USER_SPECIFIED_DynamoRIO_DIR)
    # don't take time and space copying: user can pass same dr to frontend,
    # so we only copy for package target
    if (DEBUG_BUILD)
      set(CPACK_INSTALLED_DIRECTORIES 
        "${DynamoRIO_DIR}/../${LIB_ARCH};${DR_install_dir}/${LIB_ARCH}"
        "${DynamoRIO_DIR}/../ext/${LIB_ARCH};${DR_install_dir}/ext/${LIB_ARCH}")
    else (DEBUG_BUILD)
      set(CPACK_INSTALLED_DIRECTORIES 
        "${DynamoRIO_DIR}/../${LIB_ARCH}/release;${DR_install_dir}/${LIB_ARCH}/release"
        "${DynamoRIO_DIR}/../ext/${LIB_ARCH}/release;${DR_install_dir}/ext/${LIB_ARCH}/release")
    endif (DEBUG_BUILD)
  endif (NOT USER_SPECIFIED_DynamoRIO_DIR)
endif (WIN32)

# CPack tarballs do not allow setting a different name for the base
# directory and the file: I tried a ton of CPack variables for "install
# dir" and looked at the source code.  Most of the variables are for the
# other installers (rpm, nsis).  I can hack it via
# CPACK_TEMPORARY_PACKAGE_FILE_NAME if I hardcode the exentsion: but maybe
# having the full version in the base dir is a good thing, though I'm not
# sure about the caps.
set(CPACK_PACKAGE_FILE_NAME
  "${toolname_cap}-${CPACK_SYSTEM_NAME}-${CPACK_PACKAGE_VERSION}-${TOOL_BUILD_NUMBER}")
set(CPACK_SOURCE_PACKAGE_FILE_NAME
  "${toolname_cap}-${CPACK_SYSTEM_NAME}-${CPACK_PACKAGE_VERSION}-${TOOL_BUILD_NUMBER}-Source")

# NSIS settings
set(CPACK_PACKAGE_INSTALL_DIRECTORY "${toolname_cap_spc}")
set(CPACK_PACKAGE_INSTALL_REGISTRY_KEY "${toolname_cap_spc}")
set(CPACK_PACKAGE_RELOCATABLE "true")
set(CPACK_NSIS_MODIFY_PATH ON)
if (PERL_TO_EXE OR WIN32 AND USE_DRSYMS AND TOOL_DR_MEMORY)
  # CMake hardcodes bin/ for desktop links (CMake bug #7828) so
  # we rearranged our dirs since we really need one.
  set(CPACK_PACKAGE_EXECUTABLES "${toolname}" "${toolname_cap_spc} (drag your app here)")
  set(CPACK_CREATE_DESKTOP_LINKS "${toolname}")
endif (PERL_TO_EXE OR WIN32 AND USE_DRSYMS AND TOOL_DR_MEMORY)
set(CPACK_NSIS_MENU_LINKS 
  # We automatically get an entry for ${toolname}.exe since it's in the
  # CPACK_PACKAGE_EXECUTABLES list, even though we don't want one.
  "bin/" "Explore ${toolname_cap_spc} (drag your app onto ${toolname}.exe)"
  "${toolname}/docs/html/index.html" "${toolname_cap_spc} documentation"
  "http://dynamorio.org/${toolname}.html" "${toolname_cap_spc} web page")
if (USER_SPECIFIED_DynamoRIO_DIR)
  set(CPACK_NSIS_MUI_ICON "${DynamoRIO_DIR}/../docs/html/favicon.ico")
  set(CPACK_NSIS_MUI_UNIICON "${DynamoRIO_DIR}/../docs/html/favicon.ico")
else (USER_SPECIFIED_DynamoRIO_DIR)
  set(CPACK_NSIS_MUI_ICON "${DynamoRIO_SOURCE_DIR}/api/docs/images/favicon.ico")
  set(CPACK_NSIS_MUI_UNIICON "${DynamoRIO_SOURCE_DIR}/api/docs/images/favicon.ico")
endif (USER_SPECIFIED_DynamoRIO_DIR)
# FIXME: CPACK_PACKAGE_ICON: need a .bmp

# Let external build file override all settings, but before CPack reads them
set(AUX_MAKEFILE "" CACHE FILEPATH "Path to an auxiliary CMakeLists.txt file.")
if (AUX_MAKEFILE)
  include("${AUX_MAKEFILE}")
endif (AUX_MAKEFILE)

include(CPack)
