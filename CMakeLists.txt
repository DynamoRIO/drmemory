# **********************************************************
# Copyright (c) 2010-2019 Google, Inc.  All rights reserved.
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

# We need 2.8.10.1 for crbug.com/159092
# (For multi-export-set support for DRMF, we also need >= 2.8.10.)
# (For Visual Studio generators, we also need >= 2.8.2 for output dir name control.)
# (For Linux, we also need 2.6.4+ for cmake bug #8639 (asm support broken).)
cmake_minimum_required(VERSION 2.8.10.1)

include(make/policies.cmake NO_POLICY_SCOPE)

# like DR, we collapse VS generator into one config since
# we don't have enough control over output dirs
# in build rules (until cmake 2.8.4).
# this must be prior to the project() command.
if ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
  if ("${CMAKE_BUILD_TYPE}" MATCHES "Debug")
    set(CMAKE_CONFIGURATION_TYPES "Debug" CACHE STRING "" FORCE)
  else ()
    set(CMAKE_CONFIGURATION_TYPES "RelWithDebInfo" CACHE STRING "" FORCE)
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

include(CheckCCompilerFlag)

# The target OS:
if (APPLE)
  set(MACOS 1)
elseif (UNIX)
  set(LINUX 1)
endif (APPLE)

if (CMAKE_SYSTEM_NAME MATCHES "^Android")
  set(ANDROID 1)
  set(DEFINES ${DEFINES} -DANDROID)
  set(DRM_DEVICE_BASEDIR "/data/local/tmp" CACHE STRING "base dir for Android binaries")
  option(DRM_COPY_TO_DEVICE "copy cross-compiled binaries to DRM_DEVICE_BASEDIR" OFF)
  if (DRM_COPY_TO_DEVICE)
    find_program(ADB adb DOC "adb Android utility")
    if (NOT ADB)
      message(FATAL_ERROR "Unable to find adb for DRM_COPY_TO_DEVICE")
    else ()
      execute_process(COMMAND ${ADB} get-state
        RESULT_VARIABLE adb_result
        ERROR_VARIABLE adb_err
        OUTPUT_VARIABLE adb_out OUTPUT_STRIP_TRAILING_WHITESPACE)
      if (adb_result OR NOT adb_out STREQUAL "device")
        message(FATAL_ERROR "Android device not connected for DRM_COPY_TO_DEVICE")
      endif ()
      message(STATUS "Binaries will be copied to the attached Android device")
    endif ()
  endif ()
endif ()

# The target arch:
if (CMAKE_SYSTEM_PROCESSOR MATCHES "^arm")
  set(ARM 1)
else ()
  set(X86 1)
endif ()

if (UNIX)
  set(DEFINES ${DEFINES} -DUNIX)
endif (UNIX)

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

option(TEST_SUITE "we are running a series of builds for official purposes")

if (TOOL_DR_HEAPSTAT)
  # Dr. Heapstat
  set(TOOL_DR_MEMORY OFF)
  set(toolname drheapstat)
  set(tooldir ${toolname})
  set(toolname_cap DrHeapstat)
  set(toolname_cap_spc "Dr. Heapstat")
  set(DEFINES ${DEFINES} -DTOOL_DR_HEAPSTAT)

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

endif (TOOL_DR_HEAPSTAT)

# We use a monotonically increasing integer that's larger than any bugfix
# release version as the patchlevel ver# to distinguish
# We used to use the svn revision (i#83) and we leave that code in place
# (for now at least) for anyone building an old checkout.
# For git, we follow DRi#1565 and use a date.
set(VERSION_NUMBER_PATCHLEVEL 0)
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
      # We want the committer date (not author date) (xref DRi#1565).  We request
      # UNIX timestamp format and then divide down to days to get a small enough
      # number for the Windows resource limits.
      execute_process(COMMAND ${GIT} log -n 1 --format=%ct
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
        RESULT_VARIABLE git_result
        ERROR_VARIABLE git_err
        OUTPUT_VARIABLE git_out)
      if (git_result OR git_err)
        message("*** ${GIT} log failed: ***\n${git_err}")
      else (git_result OR git_err)
        math(EXPR daycount "${git_out} / (60*60*24)")
      endif (git_result OR git_err)
    endif (GIT)
    if (NOT daycount)
      # XXX DRi#1565: to support building when not in a git repo (e.g., from a source
      # tarball) we use date to get current time for timestamp.
      # This is not ideal as it confuses the build timestamp with the commit
      # timestamp.  We should add support for a local file holding the version.
      find_program(DATE date DOC "system date")
      if (DATE)
        execute_process(COMMAND ${DATE} +%s
          RESULT_VARIABLE date_result
          ERROR_VARIABLE date_err
          OUTPUT_VARIABLE date_out)
        if (date_result OR date_err)
          message("*** ${DATE} failed: ***\n${date_err}")
        else (date_result OR date_err)
          math(EXPR daycount "${date_out} / (60*60*24)")
        endif (date_result OR date_err)
      endif (DATE)
    endif (NOT daycount)
    if (NOT daycount)
      # set a much further date in the future to avoid confusing
      # this fake date with the real date from git log
      set(daycount 33333)
    endif (NOT daycount)
    set(VERSION_NUMBER_PATCHLEVEL "${daycount}")
  endif (EXISTS "${PROJECT_SOURCE_DIR}/.git")
endif (EXISTS "${PROJECT_SOURCE_DIR}/.svn")

if (APPLE)
  # clang linker disallows any but major # being >= 256 (1024 for x64) so we do
  # mod 200 (we assume we'll never confuse versions 200 apart) and add 56 (to
  # distinguish from real releases).
  math(EXPR VERSION_NUMBER_PATCHLEVEL "(${VERSION_NUMBER_PATCHLEVEL} % 200) + 56")
endif (APPLE)

# N.B.: when updating this, update the git tag in .travis.yml.
# We should find a way to share (xref DRi#1565).
set(VERSION_NUMBER_DEFAULT "2.1.${VERSION_NUMBER_PATCHLEVEL}")
# Do not store the default TOOL_VERSION_NUMBER in the cache to prevent a stale one
# from preventing future version updates in a pre-existing build dir.
# Avoid "VERSION_NUMBER" name since conflics w/ DR's var.
set(TOOL_VERSION_NUMBER "" CACHE STRING "Version number: leave empty for default")
if ("${TOOL_VERSION_NUMBER}" STREQUAL "")
  set(TOOL_VERSION_NUMBER ${VERSION_NUMBER_DEFAULT})
endif()
message(STATUS "Dr. Memory version number: ${TOOL_VERSION_NUMBER}")

# Avoid "BUILD_NUMBER" name since conflics w/ DR's var
set(TOOL_BUILD_NUMBER "1" CACHE STRING "Build number (must be <64K)")
# However, we do want to set it to avoid "custom build" in messages
# from embedded DR when run alone (i#1717's dr_set_client_version_string() has
# already solved this for messages for DrMem on DR).  To make it easy to
# correlate, we set it to a formula computed from the DrMem ver.
string(REPLACE "." ";" ver_list ${TOOL_VERSION_NUMBER})
list(GET ver_list 0 TOOL_VERSION_MAJOR)
list(GET ver_list 1 TOOL_VERSION_MINOR)
math(EXPR BUILD_NUMBER
  "${TOOL_VERSION_MAJOR}*100 + ${TOOL_VERSION_MINOR}*10 + ${VERSION_NUMBER_PATCHLEVEL}")

string(REGEX REPLACE "\\." "," TOOL_VERSION_COMMAS "${TOOL_VERSION_NUMBER}")

set(DEFINES ${DEFINES}
  -DBUILD_NUMBER=${TOOL_BUILD_NUMBER}
  -DVERSION_NUMBER=${TOOL_VERSION_NUMBER}
  -DVERSION_STRING="${TOOL_VERSION_NUMBER}"
  -DVERSION_COMMAS=${TOOL_VERSION_COMMAS})

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

if (CMAKE_C_SIZEOF_DATA_PTR EQUAL 8 OR CMAKE_CXX_SIZEOF_DATA_PTR EQUAL 8)
  set(X64 ON)
  set(LIB_ARCH "lib64")
  set(BIN_ARCH "bin64")
  set(DEFINES ${DEFINES} -DX64)
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
  # We want Windows pdb and Unix line #s for release build.
  # We make separate debug info for Unix, and are fine shipping it to users
  # in any case as we're open-source.
  set(CMAKE_BUILD_TYPE "RelWithDebInfo")
  set(DEBUG_BUILD OFF)
endif ()

string(TOUPPER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_UPPER)

# i#1781: cmake 2.8.12+ fails to create static lib pdb by default
# XXX: we should share this with DR's copy
macro(add_static_lib_debug_info target dest_dir)
  if (WIN32)
    if ("${CMAKE_VERSION}" VERSION_EQUAL "3.1" OR
        "${CMAKE_VERSION}" VERSION_GREATER "3.1")
      append_property_string(TARGET ${target}
        COMPILE_PDB_NAME${location_suffix} "${target}"
        COMPILE_PDB_OUTPUT_DIRECTORY{location_suffix} "${dest_dir}")
    else ()
      # We just don't support it for < 3.1
    endif ()
  endif ()
endmacro()

if (UNIX)
  # there's no cmake warning control so we hardcode it
  # disabling strict aliasing since giving weird warning I'm not sure how to fix:
  #   alloc.c:716: warning: dereferencing type-punned pointer will break strict-aliasing rules
  set(WARN "-Wall -Werror -Wno-strict-aliasing")
  if (CMAKE_C_COMPILER MATCHES "/build/toolchain")
    # needed for linux/ipmi.h (PR 531644)
    set(EXTRA_FLAGS "-idirafter /build/toolchain/lin32/glibc-2007q3-51/usr/include")
  else ()
    if (APPLE AND NOT CMAKE_COMPILER_IS_GNUCC)
      # Ensure our binaries can run on older OSX
      set(EXTRA_FLAGS "-mmacosx-version-min=10.9")
    else ()
      set(EXTRA_FLAGS "")
    endif ()
  endif ()
  if (ARM)
    set(EXTRA_FLAGS "${EXTRA_FLAGS} -mthumb -march=armv7-a")
    if (ANDROID OR CMAKE_C_LIBRARY_ARCHITECTURE MATCHES "gnueabi$")
      set(EXTRA_FLAGS "${EXTRA_FLAGS} -mfloat-abi=softfp")
      # Android requires PIE.  We export symbols to match our test assumptions.
      set(CMAKE_EXE_LINKER_FLAGS
        "${CMAKE_EXE_LINKER_FLAGS} -fPIE -pie -Wl,--export-dynamic")
    endif ()
  endif ()
  set(CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}
    "${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}} ${ARCH_CFLAGS} ${WARN} ${EXTRA_FLAGS}")
  set(CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER}
    "${CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER}} ${ARCH_CFLAGS} ${WARN} ${EXTRA_FLAGS}")
else (UNIX)
  # FIXME i#1204: fix warnings and up to /W4
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
      if (NOT DEBUG_BUILD)
        # RelWithDebInfo asks for /Ob1 but we want full inlining
        string(REGEX REPLACE "/Ob1" "/Ob2" ${var} "${${var}}")
      endif ()
    endforeach ()
  endforeach ()
  # disable stack protection: "unresolved external symbol ___security_cookie"
  set(CL_CFLAGS "/GS-")
  # build in parallel, always.
  # note that /MP is not officially supported on VS 2005 and others
  # have seen occasional problems: we'll risk it.  we could check for
  # "MSVC10 OR MSVC90".
  set(CL_CFLAGS "${CL_CFLAGS} /MP")
  if (NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 18.0)
    # i#1376: VS2013 requires /FS w/ multiple cl.exe in parallel (which Ninja
    # uses).  While /MP is supposed to enable it, it doesn't seem to.
    # This is recommended after /Fd but it seems to work here.
    set(CL_CFLAGS "${CL_CFLAGS} /FS")
  endif()
  set(CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER} "${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}} ${WARN} ${CL_CFLAGS}")
endif (UNIX)
set(CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER} "${CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER}} ${ARCH_CFLAGS} ${WARN}")
string(STRIP "${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}"
  CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER})
string(STRIP "${CMAKE_CXX_FLAGS}" CMAKE_CXX_FLAGS)

if (WIN32)
  # DRi#1424: target the oldest possible platform we can
  if (X64)
    set(os_target "5.02") # Win2003x64/WinXPx64
  else (X64)
    if (CMAKE_C_COMPILER_VERSION VERSION_LESS 17.0) # up to and including VS2010
      set(os_target "5.00") # Win2K
    else () # VS2012, VS2013
      set(os_target "5.01") # WinXP
    endif ()
  endif (X64)
  foreach (lflags CMAKE_EXE_LINKER_FLAGS
      CMAKE_MODULE_LINKER_FLAGS
      CMAKE_SHARED_LINKER_FLAGS)
    set(${lflags} "${${lflags}} /subsystem:console,${os_target}")
  endforeach()
  message(STATUS "Targeting subsystem ${os_target}")
endif (WIN32)

if (UNIX)
  include(CheckIncludeFiles)
  check_include_files("asm-i386/stat.h" HAVE_ASM_I386)
  if (HAVE_ASM_I386)
    # see comments above about adding configure.h
    set(DEFINES ${DEFINES} -DHAVE_ASM_I386)
  endif (HAVE_ASM_I386)
endif (UNIX)

if (UNIX)
  # We don't want our instrument_init() pre-empted by debug-internal DynamoRIO
  # that has visible internal routines.
  CHECK_C_COMPILER_FLAG("-fvisibility=internal" HAVE_FVISIBILITY_INTERNAL)
  CHECK_C_COMPILER_FLAG("-fvisibility=hidden" HAVE_FVISIBILITY_HIDDEN)
  # Mac accepts internal but warns about it so we avoid it there.
  if (HAVE_FVISIBILITY_INTERNAL AND NOT APPLE)
    set(VISIBILITY "internal")
  elseif (HAVE_FVISIBILITY_HIDDEN)
    set(VISIBILITY "hidden")
  else ()
    message("${CMAKE_C_COMPILER} missing flag -fvisibility, using linker "
            "script instead")
    set(VISIBILITY " ")
  endif ()
  if (HAVE_FVISIBILITY_INTERNAL OR HAVE_FVISIBILITY_HIDDEN)
    set(CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}
      "${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}} -fvisibility=${VISIBILITY}")
  endif ()

  if (APPLE)
    # Incredibly, for both clang and g++, while a single compile-and-link
    # invocation will create an executable.dSYM/ dir with debug info,
    # with separate compilation the final link does NOT create the
    # dSYM dir.
    # The "dsymutil" program will create the dSYM dir for us.
    # Strangely it takes in the executable and not the object
    # files even though it's the latter that contain the debug info.
    # Thus it will only work if the object files are still sitting around.
    find_program(DSYMUTIL_PROGRAM dsymutil)
    if (DSYMUTIL_PROGRAM)
      set(CMAKE_C_LINK_EXECUTABLE
        "${CMAKE_C_LINK_EXECUTABLE}"
        "${DSYMUTIL_PROGRAM} <TARGET>")
      set(CMAKE_C_CREATE_SHARED_LIBRARY
        "${CMAKE_C_CREATE_SHARED_LIBRARY}"
        "${DSYMUTIL_PROGRAM} <TARGET>")
      set(CMAKE_CXX_LINK_EXECUTABLE
        "${CMAKE_CXX_LINK_EXECUTABLE}"
        "${DSYMUTIL_PROGRAM} <TARGET>")
      set(CMAKE_CXX_CREATE_SHARED_LIBRARY
        "${CMAKE_CXX_CREATE_SHARED_LIBRARY}"
        "${DSYMUTIL_PROGRAM} <TARGET>")
    endif ()
  endif ()
endif (UNIX)

if (WIN32)
  # Use convention of DynamoRIO sources: DDKROOT env var (or DDK_ROOT cmake var).
  # We don't require the DDK as dbghelp and symsrv are in the SDK as well, and
  # we get ntdll_imports.lib from DR.
  set(DDK_ROOT "$ENV{DDKROOT}" CACHE PATH "Path to DDK or WDK.")
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

  # We can't include directly from DDK b/c the DDK include dir and VS include
  # dirs are incompatible, so we have our own copies of the headers we need.
  include_directories(wininc/psdk wininc/dxsdk)

  # We need a newer version of dbghelp.dll than is in system32/ on 2K or XP.
  # The versions that come with Debugging Tools for Windows are redistributable:
  # "you can distribute the DLL with your application".
  # The dbghelp.dll that comes in system32/ is not redistributable.
  # We want 6.3+ for full drsyms features.
  # 5.2 does not work (it's not just slower w/o SymSearch: it fails).
  # Haven't tested in between.
  # WINDDK/3790.1830/bin/x86/dbghelp.dll is 6.3.
  # Older CMake binaries are 32-bit but newer ones can be 64-bit so we
  # cannot rely on one or the other.
  if ("$ENV{PROGRAMW6432}" STREQUAL "")
    if (X64)
      message(FATAL_ERROR "On 32-bit Windows: 64-bit build not supported")
    endif ()
    set(PROGFILES "$ENV{PROGRAMFILES}")
    set(PROGFILES32 "$ENV{PROGRAMFILES}")
    set(ARCH_SFX "x86")
    set(DDK_SFX "i386")
  else ()
    set(PROGFILES "$ENV{PROGRAMW6432}")
    set(PROGFILES32 "$ENV{PROGRAMFILES(x86)}")
    if (X64)
      set(ARCH_SFX "x64")
      set(DDK_SFX "amd64")
    else (X64)
      set(ARCH_SFX "x86")
      set(DDK_SFX "i386")
    endif (X64)
  endif ()
  # Allow packaging to specify a glob for a prefered path for x86 and x64.
  set(DBGHELP_GLOB "" CACHE STRING
    "Preferred path for dbghelp.dll with wildcard expansion")
  # Even the VS2005 copy is 6.5 (despite its headers being < 6.3) so we can
  # use those as well as the later SDK and standalone DTFW versions.
  set(dbghelp_paths
    "${DBGHELP_GLOB}"
    "${DDK_ROOT}/bin/${ARCH_SFX}/dbghelp.dll"
    "${DDK_ROOT}/tools/tracing/${DDK_SFX}/dbghelp.dll"
    "${PROGFILES32}/Windows Kits/*/Debuggers/${ARCH_SFX}/dbghelp.dll"
    # In case if SDK is not installed and we have Visual Studio, dbghelp.dll may be found in the
    # Visual Studio's directory in subfolders Remote Debugger/x86 or Remote Debugger/x64 (xref i#1956).
    # We look in both paths (Program Files and Program Files (x86)) because some versions of
    # Visual Studio put dbghelp.dll in progfiles (especially 2008) and some in progfiles32.
    "${PROGFILES}/Microsoft Visual Studio */Common7/IDE/Remote Debugger/${ARCH_SFX}/dbghelp.dll"
    "${PROGFILES32}/Microsoft Visual Studio */Common7/IDE/Remote Debugger/${ARCH_SFX}/dbghelp.dll"
    "${PROGFILES32}/Microsoft Visual Studio */Common7/Packages/Debugger/${ARCH_SFX}/dbghelp.dll")

  if (X64)
    set(dbghelp_paths ${dbghelp_paths}
      # For older versions of windbg, x64 dbghelp.dll resides here.
      "${PROGFILES}/Debugging Tools for Windows (x64)/dbghelp.dll")
  else (X64)
    set(dbghelp_paths ${dbghelp_paths}
      "${PROGFILES}/Microsoft Visual Studio */Common7/IDE/dbghelp.dll"
      # Putting this last mainly b/c only older versions (like my 6.3) are here.
      "${PROGFILES}/Debugging Tools for Windows/dbghelp.dll")
  endif (X64)
  file(GLOB dbghelp_hint ${dbghelp_paths})
  # XXX i#908: it seems cmake has trouble to lookup dbghelp.dll in
  # 64-bit directory, so we just explicitly check several possible locations.
  # Plus, we don't want system32, but NO_SYSTEM_ENVIRONMENT_PATH also
  # excludes Program Files, so we avoid find_file() in general.
  if (dbghelp_hint)
    # DRi#1219: exclude VS2005 x64 dbghelp as it is buggy
    list(LENGTH dbghelp_hint dbghelp_max)
    math(EXPR dbghelp_max "${dbghelp_max} - 1")
    set(dbghelp_index 0)
    list(GET dbghelp_hint 0 dbghelp_default)
    while (${dbghelp_index} LESS ${dbghelp_max})
      if (X64 AND dbghelp_default MATCHES "Visual Studio 8")
        # Keep looking.
      elseif (X64 AND dbghelp_default MATCHES "/x86/")
        # Keep looking.
      elseif (NOT X64 AND dbghelp_default MATCHES "/x64/")
        # Keep looking.
      elseif (NOT X64 AND dbghelp_default MATCHES "/amd64/")
        # Keep looking.
      else ()
        break ()
      endif ()
      math(EXPR dbghelp_index "${dbghelp_index} + 1")
      list(GET dbghelp_hint ${dbghelp_index} dbghelp_default)
    endwhile()
    if (X64 AND dbghelp_default MATCHES "Visual Studio 8")
      message(STATUS "Unable to find non-VS2005 dbghelp.dll")
      set(dbghelp_default "DBGHELP_DLL-NOTFOUND")
    endif ()
  else ()
    set(dbghelp_default "DBGHELP_DLL-NOTFOUND")
  endif ()
  set(DBGHELP_DLL "" CACHE STRING
    "location of dbghelp.dll from recent Debugging Tools for Windows")
  if ("${DBGHELP_DLL}" STREQUAL "")
    set(DBGHELP_DLL ${dbghelp_default})
  endif()
  if (DBGHELP_DLL-NOTFOUND OR NOT EXISTS "${DBGHELP_DLL}")
    message(FATAL_ERROR "dbghelp.dll required and not found")
  else ()
    message(STATUS "Using ${DBGHELP_DLL}")
  endif ()
  # Allow packaging to specify a glob for a prefered path for x86 and x64.
  set(SYMSRV_GLOB "" CACHE STRING
    "Preferred path for dbghelp.dll with wildcard expansion")
  set(symsrv_paths
    "{SYMSRV_GLOB}"
    "${PROGFILES32}/Windows Kits/*/Debuggers/${ARCH_SFX}/symsrv.dll"
    # In case if SDK is not installed and we have Visual Studio, symsrv.dll may be found in the
    # same place as dbghelp.dll (see comment for dbghelp.dll) (xref i#1956).
    "${PROGFILES}/Microsoft Visual Studio */Common7/IDE/Remote Debugger/${ARCH_SFX}/symsrv.dll"
    "${PROGFILES32}/Microsoft Visual Studio */Common7/IDE/Remote Debugger/${ARCH_SFX}/symsrv.dll"
    "${PROGFILES32}/Microsoft Visual Studio */Common7/Packages/Debugger/${ARCH_SFX}/symsrv.dll")

  if (X64)
    set(symsrv_paths ${symsrv_paths}
      # For older versions of windbg, x64 symsrv.dll resides here.
      "${PROGFILES}/Debugging Tools for Windows (x64)/symsrv.dll")
  else (X64)
    set(symsrv_paths ${symsrv_paths}
      "${PROGFILES}/Microsoft Visual Studio */Common7/IDE/symsrv.dll"
      # Putting this last mainly b/c only older versions (like my 6.3) are here.
      "${PROGFILES}/Debugging Tools for Windows/symsrv.dll")
  endif (X64)
  file(GLOB symsrv_hint ${symsrv_paths})
  if (symsrv_hint)
    list(GET symsrv_hint 0 symsrv_default)
    list(LENGTH symsrv_hint symsrv_max)
    math(EXPR symsrv_max "${symsrv_max} - 1")
    set(symsrv_index 0)
    while (${symsrv_index} LESS ${symsrv_max})
      if (X64 AND symsrv_default MATCHES "/x86/")
        # Keep looking.
      elseif (NOT X64 AND symsrv_default MATCHES "/x64/")
        # Keep looking.
      elseif (NOT X64 AND symsrv_default MATCHES "/amd64/")
        # Keep looking.
      else ()
        break ()
      endif ()
      math(EXPR symsrv_index "${symsrv_index} + 1")
      list(GET symsrv_hint ${symsrv_index} symsrv_default)
    endwhile()
  else ()
    set(symsrv_default "SYMSRV_DLL-NOTFOUND")
  endif ()
  set(SYMSRV_DLL "" CACHE STRING
    "location of symsrv.dll from recent Debugging Tools for Windows")
  if ("${SYMSRV_DLL}" STREQUAL "")
    set(SYMSRV_DLL ${symsrv_default})
  endif()
  if (SYMSRV_DLL-NOTFOUND OR NOT EXISTS "${SYMSRV_DLL}")
    message(FATAL_ERROR "symsrv.dll required and not found")
  else ()
    message(STATUS "Using ${SYMSRV_DLL}")
  endif ()

endif (WIN32)

if (BUILDING_SUB_PACKAGE)
  set(INSTALL_PREFIX "drmemory/")
else ()
  set(INSTALL_PREFIX "")
endif()

# To run out of build dir we put libs and scripts in dirs that match install layout
# except minus the toolname prefix dir.
# The CPack NSIS interface requires a bin/ dir, so for the Windows package
# we prefix bin/
# XXX: should clean all this up and normalize across platforms now
# that we have drsyms on Linux and once we're sure we don't need to
# support the old layout.
if (WIN32 AND USE_DRSYMS AND TOOL_DR_MEMORY)
  set(INSTALL_BIN_PREFIX "${INSTALL_PREFIX}.")
  set(BUILD_BIN_PREFIX ".")
elseif (PERL_TO_EXE)
  # We are only releasing Dr. Memory so no toolnames: would need to create
  # shortcut or .bat file to run from right dir
  if (X64)
    set(INSTALL_BIN_PREFIX "${INSTALL_PREFIX}bin64")
    set(BUILD_BIN_PREFIX "bin64")
  else (X64)
    set(INSTALL_BIN_PREFIX "${INSTALL_PREFIX}bin")
    set(BUILD_BIN_PREFIX "bin")
  endif (X64)
else (PERL_TO_EXE)
  # Unified layout: match Windows since we're moving toward C-based frontends
  # that won't have auxiliary scripts we want to hide.
  set(INSTALL_BIN_PREFIX "${INSTALL_PREFIX}.")
  set(BUILD_BIN_PREFIX ".")
endif (WIN32 AND USE_DRSYMS AND TOOL_DR_MEMORY)
# For NSIS we have everything in top-level bin/
# Once we have x64 we'll need to address: fix CPack?
if (X64)
  set(INSTALL_BIN "${INSTALL_BIN_PREFIX}/bin64")
  set(BUILD_BIN "${BUILD_BIN_PREFIX}/bin64")
else (X64)
  set(INSTALL_BIN "${INSTALL_BIN_PREFIX}/bin")
  set(BUILD_BIN "${BUILD_BIN_PREFIX}/bin")
endif (X64)
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

set(CPP_IGNORE_EMPTY "")
if (UNIX)
  if (APPLE)
    # /usr/bin/cpp is broken and won't honor -B flags
    set(CMAKE_CPP_FOR_OPS ${CMAKE_C_COMPILER})
    set(CPP_INC -Wp,-I,)
    # Avoid clang warning on perl ''
    set(CPP_IGNORE_EMPTY -Wno-invalid-pp-token)
  else (APPLE)
    # "gcc -E" on a non-.c-extension file gives message:
    #   "linker input file unused because linking not done"
    # and doesn't produce any output, so we must use cpp for our .asm files.
    # we assume it's in the same dir.
    get_filename_component(compiler_path ${CMAKE_C_COMPILER} PATH)
    find_program(CMAKE_CPP_FOR_OPS cpp HINTS "${compiler_path}"
      DOC "path to C preprocessor")
    if (cpp-NOTFOUND OR NOT EXISTS "${CMAKE_CPP_FOR_OPS}")
      message(FATAL_ERROR "cpp is required to build")
    endif (cpp-NOTFOUND OR NOT EXISTS "${CMAKE_CPP_FOR_OPS}")
    mark_as_advanced(CMAKE_CPP_FOR_OPS)
    set(CPP_INC -I)
  endif (APPLE)
  set(CPP_NO_LINENUM -P)
else (UNIX)
  set(CMAKE_CPP_FOR_OPS ${CMAKE_C_COMPILER})
  set(CPP_NO_LINENUM /EP)
  set(CPP_INC /I)
endif (UNIX)

# I would share this name w/ drmemory.pl but it's a pain to configure_file
# or generate the perl script as we also have to compile it for pp.
set(options_for_perl "${PROJECT_BINARY_DIR}/${BUILD_BIN}/options-perl.pl")
add_custom_target(options_perl ALL DEPENDS "${options_for_perl}")
add_custom_command(
  OUTPUT "${options_for_perl}"
  DEPENDS "${PROJECT_SOURCE_DIR}/common/options-perl.c"
  "${PROJECT_SOURCE_DIR}/${tooldir}/optionsx.h"
  COMMAND ${CMAKE_CPP_FOR_OPS}
  ARGS -E ${CPP_NO_LINENUM} "${PROJECT_SOURCE_DIR}/common/options-perl.c"
  ${CPP_INC}${PROJECT_SOURCE_DIR}/${tooldir} ${DEFINES}
  ${CPP_IGNORE_EMPTY} > "${options_for_perl}"
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

# DR clobbers the global cflags, so we save and then restore them for
# our tests (and ourselves for non-pre-built DR).
# configure_DynamoRIO_client() also does so we do this even for pre-built DR
# for tests.
foreach (config "" ${CMAKE_BUILD_TYPE} ${CMAKE_CONFIGURATION_TYPES})
  if ("${config}" STREQUAL "")
    set(config_upper "")
  else ("${config}" STREQUAL "")
    string(TOUPPER "_${config}" config_upper)
  endif ("${config}" STREQUAL "")
  foreach (var CMAKE_C_FLAGS${config_upper};CMAKE_CXX_FLAGS${config_upper})
    set(SAVE_${var} "${${var}}")
  endforeach (var)
endforeach (config)

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

# when updating this, also update the git submodule
set(DynamoRIO_VERSION_REQUIRED "7.1.17958")

set(DR_install_dir "dynamorio")

set(DynamoRIO_PAGE_SIZE_COMPATIBILITY ON)

set(DynamoRIO_LOG_COMPATIBILITY ON)

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

  if (BUILDING_SUB_PACKAGE)
    message(FATAL_ERROR "Sub-package not supported with pre-built DR")
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
  # Build from our local copy of the sources, coming from a git submodule: i#74.
  set(DynamoRIO_DIR "${LOCAL_DynamoRIO_DIR}" CACHE PATH "Path to DynamoRIO.")
  message(STATUS "Building DynamoRIO from local sources ${DynamoRIO_DIR}")

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
  if (DRM_COPY_TO_DEVICE)
    set(DR_COPY_TO_DEVICE ON CACHE BOOL "DynamoRIO option: copy to Android")
    get_filename_component(builddir ${PROJECT_BINARY_DIR} NAME)
    set(DR_DEVICE_BASEDIR "${DRM_DEVICE_BASEDIR}/${builddir}" CACHE STRING
      "DynamoRIO option: Android path")
  endif ()
  # We do not want DR install, except for the targets we need for our
  # multi-export-set install of the DRMF.  We need those targets
  # even for BUILDING_SUB_PACKAGE.
  set(DO_DR_INSTALL OFF)
  set(DO_DR_INSTALL_TARGETS ON)
  # Stick the binaries somewhere outside of the install dir.
  # However, NSIS won't allow an absolute path (i#1099).
  # So for an automated package.cmake build via cpack, we use .. which
  # is fine in the package dir structure.  We don't want .. for a
  # user-specified destination of course.  We simply don't
  # support creating a package manually outside of package.cmake.
  if (BUILDING_PACKAGE)
    set(DR_INSTALL_TARGETS_DEST ../ignored-installs)
  else ()
    set(DR_INSTALL_TARGETS_DEST ${PROJECT_BINARY_DIR}/dynamorio/installs)
  endif ()
  # i#1449: we need cmake to remove the absolute path from the LC_LOAD_DYLIB
  # entries, which only happens on install.  We can't easily do a two-step
  # install b/c subdirs go after the main dir -- so we have DR cooperation.
  set(DR_INSTALL_DEPLOY_BIN_DEST ${DR_install_dir}/${BIN_ARCH})

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
      set(${var} "${SAVE_${var}}")
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

# Shrink binaries and pdbs (/Gy should already be there)
if (WIN32)
  foreach (var CMAKE_EXE_LINKER_FLAGS_${CMAKE_BUILD_TYPE_UPPER};
      CMAKE_MODULE_LINKER_FLAGS_${CMAKE_BUILD_TYPE_UPPER};
      CMAKE_SHARED_LINKER_FLAGS_${CMAKE_BUILD_TYPE_UPPER})
    set(${var} "${${var}} /opt:ref /opt:icf /pdbcompress")
  endforeach ()
endif ()

if (APPLE)
  # install_name_tool needs write access (i#1372)
  set(owner_access OWNER_READ OWNER_WRITE)
else (APPLE)
  set(owner_access OWNER_READ)
endif (APPLE)

##################################################
# now that we have ${DynamoRIO_DIR} we can configure docs

find_package(Doxygen)
if (NOT DOXYGEN_FOUND)
  # We'd like to require doxygen for Windows pre-commit suite but it's not
  # installed on our bots so we live with just Linux catching docs errors.
  # Ditto for Mac.
  if (TEST_SUITE AND UNIX AND NOT APPLE)
    message(FATAL_ERROR "doxygen is required to build the documentation")
  else ()
    # Non-fatal for a single, un-official build, or on Windows
    message(WARNING "doxygen not found: documentation will NOT be built")
  endif ()
else ()
  add_subdirectory(docs)
endif ()

##################################################
# assembly support

# set up assembly support and CMAKE_CPP
set(old_debug ${DEBUG})
set(DEBUG ON) # ensure we get debug info
include(${DynamoRIO_DIR}/cpp2asm_support.cmake)
set(DEBUG ${old_debug})

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
  if (APPLE)
    set(DEFINES ${DEFINES} -DASSEMBLE_WITH_NASM)
  else (APPLE)
    set(DEFINES ${DEFINES} -DASSEMBLE_WITH_GAS)
  endif (APPLE)
else (UNIX)
  set(DEFINES ${DEFINES} -DASSEMBLE_WITH_MASM)
endif (UNIX)
get_DynamoRIO_defines(DR_DEFINES OFF)
# We need defines to be a list to pass as separate args to custom command.
# We assume none have spaces inside them which seems reasonable.
string(REPLACE " " ";" DR_DEFINES "${DR_DEFINES}")
set(asm_defs ${DR_DEFINES} ${DEFINES} -I "${DynamoRIO_DIR}")

set(asm_deps "${DynamoRIO_DIR}/cpp2asm_defines.h")

if (ARM)
  set(asm_file "asm_utils_arm.asm")
else ()
  set(asm_file "asm_utils_x86.asm")
endif ()
add_asm_target(common/${asm_file} asm_utils_src asm_utils_tgt ""
  "${asm_defs}" "${asm_deps}")

##################################################

if (ANDROID)
  # We cache this for us in sub-projects like framework/samples/
  set(TOP_BINARY_DIR ${PROJECT_BINARY_DIR})
  get_filename_component(builddir ${TOP_BINARY_DIR} NAME)
  set(DRM_DEVICE_BINARY_DIR ${DRM_DEVICE_BASEDIR}/${builddir})
endif ()

function (copy_target_to_device target)
  if (DRM_COPY_TO_DEVICE)
    DynamoRIO_copy_target_to_device(${target} ${DRM_DEVICE_BASEDIR} "${_DR_location_suffix}")
  endif ()
endfunction (copy_target_to_device)

function (copy_file_to_device local_path)
  if (DRM_COPY_TO_DEVICE)
    file(RELATIVE_PATH relpath "${TOP_BINARY_DIR}" "${local_path}")
    execute_process(
      COMMAND ${ADB} push ${local_path} ${DRM_DEVICE_BINARY_DIR}/${relpath}
      RESULT_VARIABLE adb_result ERROR_VARIABLE adb_err OUTPUT_QUIET)
    if (adb_result)
      message(FATAL_ERROR "*** Failed to adb push ${local_path}: ${adb_err} ***\n")
    endif ()
  endif ()
endfunction (copy_file_to_device)

function (get_target_path_for_execution out target)
  if (ANDROID)
    DynamoRIO_get_target_path_for_execution(local ${target} ${DRM_DEVICE_BASEDIR} "${_DR_location_suffix}")
  else ()
    DynamoRIO_get_target_path_for_execution(local ${target} "" "${_DR_location_suffix}")
  endif ()
  set(${out} ${local} PARENT_SCOPE)
endfunction (get_target_path_for_execution)

function (convert_local_path_to_device_path out local_path)
  if (ANDROID)
    file(RELATIVE_PATH relpath "${TOP_BINARY_DIR}" "${local_path}")
    set(local ${DRM_DEVICE_BINARY_DIR}/${relpath})
  else ()
    set(local ${local_path})
  endif ()
  set(${out} ${local} PARENT_SCOPE)
endfunction (convert_local_path_to_device_path)

function (prefix_cmd_if_necessary cmd_out use_ats cmd_in)
  DynamoRIO_prefix_cmd_if_necessary(local ${use_ats} ${cmd_in} ${ARGN})
  set(${cmd_out} ${local} PARENT_SCOPE)
endfunction (prefix_cmd_if_necessary)

function (copy_and_adjust_drpaths basedir target)
  if (ANDROID AND DRM_COPY_TO_DEVICE)
    file(GLOB drpaths ${target}/*${target}*.drpath)
    foreach(drpath ${drpaths}) # we only expect one though
      file(READ ${drpath} contents)
      string(REPLACE "${PROJECT_BINARY_DIR}" "${DRM_DEVICE_BINARY_DIR}"
        contents ${contents})
      file(WRITE ${drpath} ${contents})
      copy_file_to_device(${drpath})
    endforeach ()
  endif ()
endfunction ()

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
    common/utils_shared.c
    ${asm_utils_src}
    common/redblack.c
    common/crypto.c
    # For leak checking we need stack.c but it pulls in the inter-dependent
    # slowpath, fastpath, and shadow: we'll want those for staleness anyway.
    # Looking more and more like Dr. Memory!
    drmemory/annotations.c
    drmemory/leak.c
    drmemory/options.c
    drmemory/stack.c
    drmemory/instru.c
    drmemory/spill.c
    drmemory/slowpath.c
    drmemory/fastpath.c
    drmemory/shadow.c
    drmemory/perturb.c)
else (TOOL_DR_HEAPSTAT)
  # Dr. Memory
  set(srcs
    drmemory/annotations.c
    drmemory/drmemory.c
    drmemory/instru.c
    drmemory/spill.c
    drmemory/slowpath.c
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
    common/utils_shared.c
    ${asm_utils_src}
    common/redblack.c
    common/crypto.c
    drmemory/fuzzer.c)
  if (UNIX)
    if (APPLE)
      set(srcs ${srcs} drmemory/syscall_macos.c)
    else (APPLE)
      set(srcs ${srcs} drmemory/syscall_linux.c)
    endif (APPLE)
  else (UNIX)
    set(srcs ${srcs} drmemory/syscall_windows.c)
    set(srcs ${srcs} drmemory/syscall_wingdi.c)
    set(srcs ${srcs} drmemory/gdicheck.c)
    set(srcs ${srcs} drmemory/handlecheck.c)
  endif (UNIX)
  set(scripts ${toolname}.pl)
endif (TOOL_DR_HEAPSTAT)

if (X86)
  set(srcs ${srcs} drmemory/slowpath_x86.c)
  set(srcs ${srcs} drmemory/stack_x86.c)
  set(srcs ${srcs} drmemory/fastpath_x86.c)
else ()
  set(srcs ${srcs} drmemory/slowpath_arm.c)
  set(srcs ${srcs} drmemory/stack_arm.c)
  set(srcs ${srcs} drmemory/fastpath_arm.c)
endif ()

if (WIN32)
  set(srcs ${srcs} make/resources.rc)
endif ()

if (NOT USE_DRSYMS)
  set(scripts ${scripts} postprocess.pl)
endif (NOT USE_DRSYMS)

if (USE_DRSYMS)
  # front-end needs to be named ${toolname}.exe and thus has ${toolsname}.pdb, so
  # we rename client lib (plus cmake best w/o same-name targets)
  set(client_target "${toolname}lib")
  if (TOOL_DR_MEMORY)
    set(frontend_srcs drmemory/frontend.c drmemory/options.c)
  else (TOOL_DR_MEMORY)
    set(frontend_srcs drheapstat/drheapstat_frontend.c)
  endif (TOOL_DR_MEMORY)
  if (WIN32)
    set(frontend_srcs ${frontend_srcs} make/resources.rc)
  endif ()
  add_executable(${toolname} ${frontend_srcs})
  if (ANDROID AND TOOL_DR_MEMORY)
    # There's no DT_RPATH support so we have a script set the load path.
    # To avoid confusion we rename the exe.
    set(frontend_name "launcher")
    set_target_properties(${toolname} PROPERTIES OUTPUT_NAME "${frontend_name}")
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/${tooldir}/launcher_android.sh"
      "${PROJECT_BINARY_DIR}/${BUILD_BIN}/${toolname}" @ONLY)
    copy_file_to_device("${PROJECT_BINARY_DIR}/${BUILD_BIN}/${toolname}")
  endif ()
  if (WIN32)
    target_link_libraries(${toolname} dbghelp)
  endif (WIN32)
  copy_target_to_device(${toolname})
else (USE_DRSYMS)
  set(client_target ${toolname})
endif (USE_DRSYMS)

macro(set_library_version target number)
  # We only set the version/soversion on Windows to avoid many
  # negatives (DRi#1374, DRi#2127, Android "adb push" not supporting
  # symlinks, etc.) and very few positives on UNIX platforms.  DR's
  # loader and the DRMF init code perform their own version checks for
  # client compatibility.
  if (WINDOWS)
    set_target_properties(${target} PROPERTIES VERSION ${number})
  endif ()
endmacro()

add_library(${client_target} SHARED ${srcs})
set_library_version(${client_target} ${TOOL_VERSION_NUMBER})
set_property(TARGET ${client_target} PROPERTY COMPILE_DEFINITIONS
  # If we end up wanting this for other DEFINES uses above we'll have to set
  # client_target earlier.  For now we only need for the C code.
  "${DEFINES_NO_D};CLIENT_LIBNAME=${client_target};RC_IS_TOOLLIB")
if ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
  # ensure race-free parallel builds
  add_dependencies(${client_target} ${asm_utils_tgt})
endif ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
copy_target_to_device(${client_target})

# We require frames in our replacement routines in order to reliably include
# the allocator routines in the callstack for i#639.  Xref i#958.
append_src_compile_flags(common/alloc_replace.c ${FLAG_DISABLE_FPO})

if (WIN32)
  # our addr2line for Windows
  add_executable(winsyms tools/winsyms.c make/resources.rc)
  target_link_libraries(winsyms dbghelp)
  set_property(TARGET winsyms PROPERTY COMPILE_DEFINITIONS
    # We need full defines to get version values for resources
    "${DEFINES_NO_D};RC_IS_WINSYMS")
  # configure_DynamoRIO_client clears global flags so add as additional
  # request static libc to avoid manifest files and libc portability issues
  string(REGEX REPLACE "/MD" "/MT" CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}
    "${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")
  set_source_files_properties(tools/winsyms.c PROPERTIES
    COMPILE_FLAGS "${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")

  # Helper tool to ensure we have version info in our binaries:
  add_executable(verinfo tools/verinfo.c make/resources.rc)
  target_link_libraries(verinfo version)
  set_property(TARGET verinfo PROPERTY COMPILE_DEFINITIONS
    "${DEFINES_NO_D};RC_IS_VERINFO")

  # i#1009c#4: auto-register Dr. Memory as a Visual Studio External Tool
  add_executable(vs_external_tool tools/vs_external_tool.c make/resources.rc)
  set_property(TARGET vs_external_tool PROPERTY COMPILE_DEFINITIONS
    "${DEFINES_NO_D};RC_IS_VS_EXTERNAL_TOOL")
endif (WIN32)

# we want a preferred base to avoid patching pcaches
set(DynamoRIO_SET_PREFERRED_BASE ON)
if (ANDROID)
  # i#1881: 0x73800000 seems to conflict w/ hardcoded Android mmaps.
  set(PREFERRED_BASE 0x17000000)
else ()
  set(PREFERRED_BASE 0x73800000)
endif ()

# we can handle being tied to a particular DR version (we already are)
set(DynamoRIO_FAST_IR ON)

set(DynamoRIO_REG_COMPATIBILITY ON)
if (NOT STATIC_DRSYMS)
  set(DynamoRIO_USE_LIBC OFF)
endif (NOT STATIC_DRSYMS)
configure_DynamoRIO_client(${client_target})
# i#277/PR 540817: features split into DynamoRIO Extensions
use_DynamoRIO_extension(${client_target} drcontainers)
# For efficiency, we use the static versions of DR's extensions.  We have the same
# LGPL license as drutil and drwrap so it works out.
use_DynamoRIO_extension(${client_target} drmgr_static)
use_DynamoRIO_extension(${client_target} drx_static)
use_DynamoRIO_extension(${client_target} drutil_static)
use_DynamoRIO_extension(${client_target} drwrap_static)
use_DynamoRIO_extension(${client_target} drreg_static)
# DRi#1829: we discussed invoking drcov as a separate client, which would require using
# all shared ext libs.  We ended up making drcovlib.
use_DynamoRIO_extension(${client_target} drcovlib_static)
set_target_properties(${client_target} PROPERTIES
  # dlls are put in runtime dir but we want lib dir
  RUNTIME_OUTPUT_DIRECTORY${location_suffix} "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
if (WIN32)
  # annoying to have ASLR and not on module list
  # plus, now we require the same base for pcache
  set(new_flags "/dynamicbase:no")

  # This flag is added by VS generators so we may as well add for Ninja
  set(new_flags "/nxcompat")

  # Reduce size by stripping out unused code (we don't seem to need /Gy for this,
  # and VS generators seem to set it already, so we add here for Ninja).
  # XXX: DRi#2167 is adding this for all clients so we can remove this once
  # we update to a recent DR.
  set(new_flags "${new_flags} /opt:ref")
  if (NOT DEBUG_BUILD)
    # Match DR's settings, though again it's not clear the benefit w/o /Gy.
    set(new_flags "${new_flags} /opt:icf")
  endif()

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
if (USE_DRSYMS)
  if (DEFINED DynamoRIO_RPATH)
    set(old_rpath ${DynamoRIO_RPATH})
  else ()
    set(old_rpath OFF)
  endif ()
  set(DynamoRIO_RPATH ON)
  configure_DynamoRIO_standalone(${toolname})
  set(DynamoRIO_RPATH ${old_rpath})
  target_link_libraries(${toolname} drinjectlib drconfiglib drfrontendlib
    drsyscall_static)
  if (WIN32)
    set_target_properties(${toolname} PROPERTIES
      VERSION ${TOOL_VERSION_NUMBER}
      COMPILE_DEFINITIONS "${DEFINES_NO_D};RC_IS_FRONTEND")
  else (WIN32)
    DynamoRIO_add_rel_rpaths(${toolname} drinjectlib)
    DynamoRIO_add_rel_rpaths(${toolname} drconfiglib)
    set_property(TARGET ${toolname} PROPERTY COMPILE_DEFINITIONS ${DEFINES_NO_D})
  endif (WIN32)
  if (STATIC_DRSYMS)
    use_DynamoRIO_extension(${client_target} drsyms_static)
  else ()
    # N.B.: static drsyms gives us kernel32 imports from elftoolchain
    # libc use.  If we end up needing late kernel32 use for early
    # injection we may want to go back to dynamic drsyms (and delayed
    # dr_enable_console_printing()).
    use_DynamoRIO_extension(${client_target} drsyms)
  endif ()
endif (USE_DRSYMS)
if (WIN32)
  # We need to link with ntdll.lib and dbghelp.lib which we get from DR
  if (USER_SPECIFIED_DynamoRIO_DIR)
    get_target_property(libbase drinjectlib LOCATION)
    get_filename_component(libpath ${libbase} PATH)
    set(ntimp_lib "${libpath}/ntdll_imports.lib")
    set(dbghelp_lib "${libpath}/dbghelp_imports.lib")
  else ()
    # DR now has ntdll_imports as a normal lib target
    set(ntimp_lib ntdll_imports)
    # XXX: This relies on knowing where DR puts it.
    # One option is ExternalProject to install the local DR first: xref i#1061.
    set(dbghelp_lib "${PROJECT_BINARY_DIR}/dynamorio/ext/drsyms/dbghelp_imports.lib")
    if ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
      # for parallel build correctness we need a target dependence
      add_dependencies(${client_target} ntdll_imports)
      if (TOOL_DR_MEMORY)
        add_dependencies(${toolname} dbghelp_tgt)
      endif ()
    endif ()
  endif ()

  # Front-end uses dbghelp routines not in VS2005 so we link w/ DR's import lib.
  target_link_libraries(${toolname} ${dbghelp_lib})

  # we have to link with ntdll AFTER any libcmt.lib from configure_DynamoRIO_client
  # or use_DynamoRIO_extension (w/ static libs)
  target_link_libraries(${client_target} ${ntimp_lib})
  # we used to statically link with msvcrt.lib for vc /O2's use of __aulldvrm,
  # and it didn't add any dynamic dependence on libc, except now that we
  # use static extension libraries it does add msvcr*.dll imports!
  # so I removed "msvcrt" from target_link_libraries() and so far haven't
  # hit the __aulldvrm issue.
endif (WIN32)

# Build Qt Visualizer
if (TOOL_DR_HEAPSTAT)
  find_package(Qt5Widgets QUIET)
  if (NOT Qt5Widgets_FOUND)
    message(STATUS "Could NOT find Qt 5: Dr. Heapstat visualizer will not be built")
    message(STATUS
      "Point CMake variable Qt5Widgets_DIR at the Qt5WidgetsConfig.cmake directory")
  else (NOT Qt5Widgets_FOUND)
    message(STATUS "Found Qt 5: Dr. Heapstat visualizer will be built")
    add_subdirectory(drheapstat/visualizer)
  endif (NOT Qt5Widgets_FOUND)
endif (TOOL_DR_HEAPSTAT)

#
##################################################

# must be AFTER DR local build since affects subdirs
include_directories(common ${tooldir} "third_party/valgrind")

if (UNIX)
  set(DISABLE_OPTS "-O0")
else (UNIX)
  set(DISABLE_OPTS "/Od")
endif (UNIX)
append_src_compile_flags(common/alloc_unopt.c "${DISABLE_OPTS}")
if (UNIX)
  # i#1776: avoid an infinite loop in replace_memset.
  # We have no per-function optimization so we apply to the whole file.
  append_src_compile_flags(drmemory/replace.c "${DISABLE_OPTS}")
endif ()

# symbol query tool
set(symquery_srcs tools/symquery.c)
if (WIN32)
  set(symquery_srcs ${symquery_srcs} make/resources.rc)
endif ()
add_executable(symquery ${symquery_srcs})
if (DEFINED DynamoRIO_RPATH)
  set(old_rpath ${DynamoRIO_RPATH})
else ()
  set(old_rpath OFF)
endif ()
set(DynamoRIO_RPATH ON)
configure_DynamoRIO_standalone(symquery)
use_DynamoRIO_extension(symquery drsyms_static)
set(DynamoRIO_RPATH ${old_rpath})
# drfrontendlib depends on drinjectlib, DR-i#1409 should be the solution
target_link_libraries(symquery drinjectlib drfrontendlib)
if (WIN32)
  set_target_properties(symquery PROPERTIES VERSION ${TOOL_VERSION_NUMBER}
    COMPILE_DEFINITIONS
    # We need full defines to get version values for resources
    "${DEFINES_NO_D};RC_IS_SYMQUERY")
else (WIN32)
  DynamoRIO_add_rel_rpaths(symquery drinjectlib)
endif (WIN32)

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
file(WRITE "${PROJECT_BINARY_DIR}/logs/README" "Directory for logs") # for adb push
copy_file_to_device("${PROJECT_BINARY_DIR}/logs")
if (NOT PERL_TO_EXE AND NOT USE_DRSYMS)
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/${tooldir}/${toolname}.pl"
    "${PROJECT_BINARY_DIR}/${BUILD_BIN}/${toolname}.pl" @ONLY)
  if (NOT USE_DRSYMS)
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/${tooldir}/postprocess.pl"
      "${PROJECT_BINARY_DIR}/${BUILD_BIN}/postprocess.pl" COPYONLY)
    set(script_aux "${CMAKE_CURRENT_SOURCE_DIR}/${tooldir}/postprocess.pl")
  endif ()
  set(script_main "${PROJECT_BINARY_DIR}/${BUILD_BIN}/${toolname}.pl"
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
    if (USE_DRSYMS)
      configure_file("${DynamoRIO_DIR}/../${BIN_ARCH}/drconfig.exe"
        "${PROJECT_BINARY_DIR}/${BUILD_BIN}/drconfig.exe" COPYONLY)
      if (NOT STATIC_DRSYMS AND TOOL_DR_MEMORY)
        # symquery needs drsyms.dll in same dir
        configure_file("${DynamoRIO_DIR}/../ext/${LIB_ARCH}/${build_type}/drsyms.dll"
          "${PROJECT_BINARY_DIR}/${BUILD_BIN}/drsyms.dll" COPYONLY)
      endif (NOT STATIC_DRSYMS AND TOOL_DR_MEMORY)
      # symquery needs dynamorio.dll in same dir
      # frontend now imports from DR (i#885)
      configure_file("${DynamoRIO_DIR}/../${LIB_ARCH}/${build_type}/dynamorio.dll"
        "${PROJECT_BINARY_DIR}/${BUILD_BIN}/dynamorio.dll" COPYONLY)
    endif (USE_DRSYMS)
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
    if (USE_DRSYMS)
      set(drconfigexe_copy "${PROJECT_BINARY_DIR}/${BUILD_BIN}/drconfig.exe")
      add_custom_target(drconfigexe_copy_tgt ALL DEPENDS "${drconfigexe_copy}")
      add_custom_command(OUTPUT "${drconfigexe_copy}" DEPENDS drconfig
        COMMAND ${CMAKE_COMMAND}
        ARGS -E copy "${DynamoRIO_DIR}/../${BIN_ARCH}/drconfig.exe"
        "${drconfigexe_copy}" VERBATIM)
      if (NOT STATIC_DRSYMS AND TOOL_DR_MEMORY)
        # symquery needs drsyms.dll in same dir
        set(drsymsdll_copy "${PROJECT_BINARY_DIR}/${BUILD_BIN}/drsyms.dll")
        add_custom_target(drsymsdll_copy_tgt ALL DEPENDS "${drsymsdll_copy}")
        add_custom_command(OUTPUT "${drsymsdll_copy}" DEPENDS drsyms
          COMMAND ${CMAKE_COMMAND}
          ARGS -E copy "${DynamoRIO_DIR}/../ext/${LIB_ARCH}/${build_type}/drsyms.dll"
        "${drsymsdll_copy}" VERBATIM)
      endif (NOT STATIC_DRSYMS AND TOOL_DR_MEMORY)
      # symquery needs dynamorio.dll in same dir
      # frontend now imports from DR (i#885)
      set(drdll_copy "${PROJECT_BINARY_DIR}/${BUILD_BIN}/dynamorio.dll")
      add_custom_target(drdll_copy_tgt ALL DEPENDS "${drdll_copy}")
      add_custom_command(OUTPUT "${drdll_copy}" DEPENDS dynamorio
        COMMAND ${CMAKE_COMMAND}
        ARGS -E copy "${DynamoRIO_DIR}/../${LIB_ARCH}/${build_type}/dynamorio.dll"
        "${drdll_copy}" VERBATIM)
    endif (USE_DRSYMS)
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
      "${PROJECT_BINARY_DIR}/${BUILD_BIN}/drconfig" COPYONLY)
  else (USER_SPECIFIED_DynamoRIO_DIR)
    set(drconfig_copy "${PROJECT_BINARY_DIR}/${BUILD_BIN}/drconfig")
    add_custom_target(drconfig_copy_tgt ALL DEPENDS "${drconfig_copy}")
    add_custom_command(OUTPUT "${drconfig_copy}"
      DEPENDS drconfig
      COMMAND ${CMAKE_COMMAND}
      ARGS -E copy "${DynamoRIO_DIR}/../${BIN_ARCH}/drconfig"
      "${drconfig_copy}" VERBATIM)
  endif (USER_SPECIFIED_DynamoRIO_DIR)
  if (TOOL_DR_MEMORY)
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/tools/valgrind2drmemory.pl"
      "${PROJECT_BINARY_DIR}/${BUILD_BIN}/valgrind2drmemory.pl" COPYONLY)
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
  if (APPLE)
    set(defsupp_in "${CMAKE_CURRENT_SOURCE_DIR}/drmemory/suppress-default.mac.txt")
  else (APPLE)
    set(defsupp_in "${CMAKE_CURRENT_SOURCE_DIR}/drmemory/suppress-default.lin.txt")
  endif (APPLE)
  file(READ "${defsupp_in}" txt)
  file(WRITE "${defsupp_out}" "${txt}")
endif (WIN32)
copy_file_to_device("${defsupp_out}")

###########################################################################
# Tests

# We need to add_subdirectory after we know where ntdll_imports.lib is.
# That means we've messed with global things like include dirs already,
# for configure_DynamoRIO_client(), but having the extension include
# dirs in there should be harmless to the tests.
if (BUILD_TOOL_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif (BUILD_TOOL_TESTS)

###########################################################################
# Create tool config files for running with "drrun -t"

set(DRRUN_DIR "${PROJECT_BINARY_DIR}/drrun")
file(MAKE_DIRECTORY "${DRRUN_DIR}")

if (X64)
  set(BIT_SFX "64")
else ()
  set(BIT_SFX "32")
endif ()
set(DRRUN_SFX ".drrun${BIT_SFX}")
if (BUILDING_SUB_PACKAGE)
  set(DRRUN_INSTALL "tools/")
else ()
  set(DRRUN_INSTALL "${DR_install_dir}/tools/")
endif ()

function (create_drrun_file frontend file_out name) # option list follows name
  get_target_property(frontend_path ${frontend} LOCATION${location_suffix})
  get_filename_component(frontend_name ${frontend_path} NAME)
  if (ANDROID AND TOOL_DR_MEMORY)
    set(frontend_name ${toolname}) # point at script, not launcher
  endif ()
  if (BUILDING_SUB_PACKAGE)
    set(DRRUN_TOP "FRONTEND_REL=${INSTALL_PREFIX}/${BUILD_BIN}/${frontend_name}")
  else ()
    set(DRRUN_TOP "FRONTEND_REL=../${BUILD_BIN}/${frontend_name}")
  endif ()
  set(DRRUN_FILE "${DRRUN_DIR}/${name}${DRRUN_SFX}")
  file(WRITE  ${DRRUN_FILE} "# Dr. Memory tool config file\n")
  file(APPEND ${DRRUN_FILE} "${DRRUN_TOP}\n")
  file(APPEND ${DRRUN_FILE} "TOOL_OP=-dr\n")
  file(APPEND ${DRRUN_FILE} "TOOL_OP_DR_PATH\n")
  file(APPEND ${DRRUN_FILE} "TOOL_OP_DR_BUNDLE=-dr_ops\n")
  foreach (op ${ARGN})
    file(APPEND ${DRRUN_FILE} "TOOL_OP=${op}\n")
  endforeach ()
  if (X64)
    file(APPEND ${DRRUN_FILE}
      "USER_NOTICE=Support for 64-bit applications under this tool is experimental.  Please report issues to http://drmemory.org/issues.\n")
  endif ()
  install(FILES "${DRRUN_FILE}" DESTINATION "${DRRUN_INSTALL}/")
  set(${file_out} ${DRRUN_FILE} PARENT_SCOPE)

  # DRi#1509: generate a list of tools for drrun usage messages
  if (NOT DEBUG_BUILD) # avoid dups
    install(CODE "file(APPEND \"\${CMAKE_INSTALL_PREFIX}/tools/list${BIT_SFX}\" \"${name}\\n\")")
  endif ()
endfunction (create_drrun_file)

create_drrun_file(${toolname} unused "drmemory")
if (NOT X64)
  create_drrun_file(${toolname} unused "drmemory_light" "-light")
endif ()
if (WIN32)
  create_drrun_file(${toolname} unused "handle_leaks" "-handle_leaks_only")
endif ()

###########################################################################
# Dr. Memory Framework (DRMF)

# We decided against putting the extension inside frameworks/, so
# framework-shared code goes here.  Things that should be global we
# put into functions for invocation inside extension subdirs.

set(DRMF_BASEDIR "drmf")
set(DRMF_BINBASE "${LIB_ARCH}/${build_type}")
set(DRMF_INSTALL "${INSTALL_PREFIX}${DRMF_BASEDIR}")
set(DRMF_INSTALL_BIN "${DRMF_INSTALL}/${DRMF_BINBASE}")
set(DRMF_INSTALL_INC "${DRMF_INSTALL}/include")
set(framework_dir "${PROJECT_BINARY_DIR}/${DRMF_BASEDIR}")
set(framework_incdir "${framework_dir}/include")
set(framework_bindir "${framework_dir}/${DRMF_BINBASE}")

# Versioning: we use separate versioning for DRMF from the tool versioning.
# This is major*100 + minor.
set(DRMF_VERSION_DEFAULT "1.0.${VERSION_NUMBER_PATCHLEVEL}")
set(DRMF_VERSION "" CACHE STRING "DRMF version number: leave empty for default")
if ("${DRMF_VERSION}" STREQUAL "")
  set(DRMF_VERSION ${DRMF_VERSION_DEFAULT})
endif()
message(STATUS "DRMF version number: ${DRMF_VERSION}")
string(REGEX REPLACE "^([0-9]+)\\..*" "\\1" DRMF_VERSION_MAJOR "${DRMF_VERSION}")
string(REGEX REPLACE "^[0-9]+\\.([0-9]+)\\..*" "\\1" DRMF_VERSION_MINOR "${DRMF_VERSION}")
# We use just major.minor for .so versioning (and no, SOVERSION is not sufficient
# here: we have to set VERSION to control the file name and import dependence).
string(REGEX REPLACE "^([0-9]+\\.[0-9]+)\\..*" "\\1"
  DRMF_VERSION_MAJOR_MINOR "${DRMF_VERSION}")
math(EXPR DRMF_VERSION_INTEGER "${DRMF_VERSION_MAJOR}*100 + ${DRMF_VERSION_MINOR}")
set(DRMF_VERSION_COMPAT 9)                # Oldest compatible version
set(DRMF_VERSION_CUR ${DRMF_VERSION_INTEGER}) # Current version

configure_file(framework/public.h
  ${framework_incdir}/drmemory_framework.h)
include_directories(${framework_incdir})

configure_file(framework/drmf.cmake.in
  ${framework_dir}/DrMemoryFrameworkConfig.cmake
  @ONLY)
foreach (ext drsyscall umbra drfuzz)
  file(APPEND ${framework_dir}/DrMemoryFrameworkConfig.cmake "
set(DynamoRIO_EXT_${ext}_INC \${drmf_cwd}/include)
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

# DRi#948: we need to map Release and RelMinSize to RelWithDebInfo
file(WRITE ${framework_dir}/${exported_targets_name}.cmake "")
set(exported_targets_append "")
macro(export_target)
  if ("${CMAKE_VERSION}" VERSION_EQUAL "3.0" OR
      "${CMAKE_VERSION}" VERSION_GREATER "3.0")
    set(tgt_args "")
  else ()
    # We use a prefix primarily to make it easy to test the imported targets,
    # and to give a better "bundled extensions" feel.
    set(tgt_args NAMESPACE drmf_)
  endif ()
  export(TARGETS ${ARGV} ${tgt_args} FILE ${framework_dir}/${exported_targets_name}.cmake
    APPEND)
  set(toadd "
SET_PROPERTY(TARGET ${ARGV0} PROPERTY MAP_IMPORTED_CONFIG_RELEASE RelWithDebInfo)
SET_PROPERTY(TARGET ${ARGV0} PROPERTY MAP_IMPORTED_CONFIG_RELMINSIZE RelWithDebInfo)
")
  if (NOT DEBUG_BUILD)
    file(APPEND ${framework_dir}/${exported_targets_name}.cmake ${toadd})
  endif (NOT DEBUG_BUILD)
  # For install we want both debug and release:
  set(exported_targets_append "${exported_targets_append}${toadd}")
  set(exported_targets_append "${exported_targets_append}" PARENT_SCOPE)
endmacro(export_target)

# Included prior to add_subdirectory() for building version.c which
# includes utils.h which includes drsyscall.h.
include_directories(drsyscall)

add_subdirectory(drsyscall)

# XXX: change this and include_directories above to
# find_package() + use_DynamoRIO_extension(drsyscall)
target_link_libraries(${client_target} drsyscall_int)

if (USE_DRSYMS)
  add_subdirectory(drsymcache)
  include_directories(drsymcache)
  target_link_libraries(${client_target} drsymcache_int)
endif (USE_DRSYMS)

# Add Umbra
add_subdirectory(umbra)

# XXX: change this to find_package() + use_DynamoRIO_extension(umbra)
include_directories(umbra)
target_link_libraries(${client_target} umbra_int)

# Add drfuzz
add_subdirectory(drfuzz)

# XXX: change this to find_package() + use_DynamoRIO_extension(drfuzz)
include_directories(drfuzz)
if (TOOL_DR_MEMORY)
  target_link_libraries(${client_target} drfuzz_int)
endif (TOOL_DR_MEMORY)

if (BUILD_TOOL_TESTS)
  add_subdirectory(tests/framework)

  if (TOOL_DR_MEMORY)
    # unit tests
    add_executable(unit_tests ${srcs})
    set_property(TARGET unit_tests PROPERTY COMPILE_DEFINITIONS
      "${DEFINES_NO_D};BUILD_UNIT_TESTS;RC_IS_UNITTESTS")
    if ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
      # ensure race-free parallel builds
      add_dependencies(unit_tests ${asm_utils_tgt})
    endif ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
    if (DEFINED DynamoRIO_RPATH)
      set(old_rpath ${DynamoRIO_RPATH})
    else ()
      set(old_rpath OFF)
    endif ()
    set(DynamoRIO_RPATH ON)
    configure_DynamoRIO_standalone(unit_tests)
    use_DynamoRIO_extension(unit_tests drmgr_static)
    use_DynamoRIO_extension(unit_tests drcontainers)
    use_DynamoRIO_extension(unit_tests drmgr_static)
    use_DynamoRIO_extension(unit_tests drx_static)
    use_DynamoRIO_extension(unit_tests drutil_static)
    use_DynamoRIO_extension(unit_tests drwrap_static)
    use_DynamoRIO_extension(unit_tests drsyms_static)
    use_DynamoRIO_extension(unit_tests drcovlib_static)
    target_link_libraries(unit_tests drsyscall_int)
    target_link_libraries(unit_tests umbra_int)
    target_link_libraries(unit_tests drsymcache_int)
    target_link_libraries(unit_tests drfuzz_int)
    set(DynamoRIO_RPATH ${old_rpath})
    get_target_path_for_execution(unit_relpath unit_tests)
    prefix_cmd_if_necessary(unit_relpath OFF ${unit_relpath})
    if (NOT ANDROID) # FIXME i#: not working on Android
      add_test(unit_tests ${unit_relpath})
    endif ()
    copy_target_to_device(unit_tests)
  endif (TOOL_DR_MEMORY)

endif (BUILD_TOOL_TESTS)

# XXX i#1497, i#1498: the drstrace front-end now uses drfrontendlib
# but there's a bunch of work getting the client to be cross-platform.
if (TOOL_DR_MEMORY AND WIN32)
  # We only build for Dr. Memory b/c we'd need extra work to deal w/
  # drheapstat's bin/bin32 different subdir.
  add_subdirectory(drstrace)
endif (TOOL_DR_MEMORY AND WIN32)

# FIXME i#1987: enable support of drltrace under MacOS
if (NOT APPLE)
  add_subdirectory(drltrace)
endif()

add_subdirectory(framework/samples)

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

install(TARGETS ${client_target}
  RUNTIME DESTINATION "${INSTALL_LIB}" # dll
  LIBRARY DESTINATION "${INSTALL_LIB}" # .so
  PERMISSIONS ${owner_access} OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
  WORLD_READ WORLD_EXECUTE)
install(TARGETS symquery DESTINATION "${INSTALL_BIN}"
  PERMISSIONS ${owner_access} OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
  WORLD_READ WORLD_EXECUTE)
if (WIN32)
  # XXX i#926: remove winsyms once we remove postleaks.pl.
  # Also removed its pdb below via: PATTERN "winsyms.pdb" EXCLUDE
  install(TARGETS winsyms DESTINATION "${INSTALL_BIN}"
    PERMISSIONS ${owner_access} OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)
  install(FILES
    ${PROJECT_BINARY_DIR}/${BUILD_BIN}/dbghelp.dll
    ${PROJECT_BINARY_DIR}/${BUILD_BIN}/symsrv.dll
    DESTINATION "${INSTALL_BIN}"
    PERMISSIONS ${owner_access} OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)
  install(FILES
    ${PROJECT_BINARY_DIR}/${BUILD_BIN}/symsrv.yes
    DESTINATION "${INSTALL_BIN}")
  if (USE_DRSYMS)
    install(FILES
      ${PROJECT_BINARY_DIR}/${BUILD_BIN}/dbghelp.dll
      DESTINATION "${INSTALL_LIB}"
      PERMISSIONS ${owner_access} OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
      WORLD_READ WORLD_EXECUTE)
  endif (USE_DRSYMS)
  if (USE_DRSYMS)
    install(FILES
      ${PROJECT_BINARY_DIR}/${BUILD_BIN}/drconfiglib.dll
      ${PROJECT_BINARY_DIR}/${BUILD_BIN}/drinjectlib.dll
      # frontend now imports from DR (i#885)
      ${PROJECT_BINARY_DIR}/${BUILD_BIN}/dynamorio.dll
      ${PROJECT_BINARY_DIR}/${BUILD_BIN}/drconfig.exe
      DESTINATION "${INSTALL_BIN}"
      PERMISSIONS ${owner_access} OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
      WORLD_READ WORLD_EXECUTE)
  endif (USE_DRSYMS)
  # We want carriage returns for nice viewing in Notepad, etc.:
  file(READ ${CMAKE_CURRENT_SOURCE_DIR}/README readme_content)
  string(REPLACE "\n" "\r\n" readme_content ${readme_content})
  file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/README.txt ${readme_content})
   install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/README.txt
    DESTINATION "${INSTALL_PREFIX}.")
else (WIN32)
  install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/README
    DESTINATION "${INSTALL_PREFIX}.")
endif (WIN32)
install(FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/license.txt
  DESTINATION "${INSTALL_PREFIX}.")
if (USE_DRSYMS)
  install(TARGETS ${toolname} DESTINATION "${INSTALL_BIN}"
    PERMISSIONS ${owner_access} OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)
else (USE_DRSYMS)
  install(FILES
    ${script_main}
    DESTINATION "${INSTALL_BIN}"
    PERMISSIONS ${owner_access} OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)
endif (USE_DRSYMS)
# We put "helper" files inside ${BIN_ARCH}/ so only top-level script is visible
if (NOT "${script_aux}" STREQUAL "")
  install(FILES
    ${script_aux}
    DESTINATION "${INSTALL_BIN}"
    PERMISSIONS ${owner_access} OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)
endif ()
if (ANDROID AND TOOL_DR_MEMORY)
  install(FILES
    "${PROJECT_BINARY_DIR}/${BUILD_BIN}/${toolname}"
    DESTINATION "${INSTALL_BIN}"
    PERMISSIONS ${owner_access} OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)
endif ()

if (TOOL_DR_MEMORY)
  install(FILES
    ${PROJECT_BINARY_DIR}/${BUILD_BIN}/suppress-default.txt
    DESTINATION "${INSTALL_BIN}"
    PERMISSIONS ${owner_access} GROUP_READ WORLD_READ)
  if (UNIX)
    install(FILES
      ${PROJECT_BINARY_DIR}/${BUILD_BIN}/valgrind2drmemory.pl
      DESTINATION "${INSTALL_PREFIX}bin"
      PERMISSIONS ${owner_access} OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
      WORLD_READ WORLD_EXECUTE)
  endif (UNIX)
endif (TOOL_DR_MEMORY)

set(install_pdb_exclude
  # We don't want unit test pdb's, or internal tool pdb's.
  # XXX: it would be better to exclude these in the subdirs that own them,
  # which will be much easier once cmake supports auto-installing pdb's.
  PATTERN verinfo.pdb EXCLUDE
  PATTERN unit_tests.pdb EXCLUDE
  # symfetch is a fake dll so don't imply it's more by supplying a pdb.
  PATTERN symfetch.pdb EXCLUDE
  PATTERN drstrace_unit_tests.pdb EXCLUDE)
if (X64)
  install(CODE "file(WRITE \"\${CMAKE_INSTALL_PREFIX}/${INSTALL_BIN}/README.txt\" \"Dr. Memory has preliminary 64-bit support that does not yet include detecting uninitialized reads.  The drstrace tool and the Dr. Syscall and Umbra libraries are fully supported for 64-bit.\n\")")
endif (X64)
install(DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/
  DESTINATION "${INSTALL_LIB}"
  FILE_PERMISSIONS ${owner_access} OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
  WORLD_READ WORLD_EXECUTE
  FILES_MATCHING
  PATTERN "*.debug"
  PATTERN "*.pdb"
  REGEX ".*.dSYM/.*DWARF/.*" # too painful to get right # of backslash for literal .
  ${install_pdb_exclude}
  )

install(DIRECTORY ${PROJECT_BINARY_DIR}/${BUILD_BIN}/
  DESTINATION "${INSTALL_BIN}"
  FILE_PERMISSIONS ${owner_access} OWNER_EXECUTE
  GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
  FILES_MATCHING
  PATTERN "*.debug"
  PATTERN "*.pdb"
  REGEX ".*.dSYM/.*DWARF/.*" # too painful to get right # of backslash for literal .
  ${install_pdb_exclude}
  )

# create empty logs dir for release package
# be sure to escape ",$ since evaluated at install time not configure time
install(CODE "file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/${INSTALL_PREFIX}${toolname}/logs\")")
# CPack seems to ignore empty dirs so add a README file
install(CODE "file(WRITE \"\${CMAKE_INSTALL_PREFIX}/${INSTALL_PREFIX}${toolname}/logs/README.txt\" \"Default destination for log files.\n\")")
# ditto for pcaches
install(CODE "file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/${INSTALL_PREFIX}${toolname}/logs/codecache\")")
install(CODE "file(WRITE \"\${CMAKE_INSTALL_PREFIX}/${INSTALL_PREFIX}${toolname}/logs/codecache/README.txt\" \"Default destination for code cache files.\n\")")
# ditto for DR logdir
install(CODE "file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/${INSTALL_PREFIX}${toolname}/logs/dynamorio\")")
install(CODE "file(WRITE \"\${CMAKE_INSTALL_PREFIX}/${INSTALL_PREFIX}${toolname}/logs/codecache/README.txt\" \"Default destination for DynamoRIO log files (for diagnostics only).\n\")")

if (UNIX)
  if (APPLE)
    set(LIB_SFX ".dylib")
  else (APPLE)
    set(LIB_SFX ".so")
  endif (APPLE)
endif (UNIX)

if (BUILDING_SUB_PACKAGE)
  # We're being included in another package (DR's).
  # Our rpaths assumed we had a dynamorio/ subdir, but now that's the upper dir.
  # Easier to add a symlink than to change rpaths.
  # XXX i#1855: this symlink makes "adb push" of our tarball's contents not work,
  # but presumably most users will untar on the Android device.
  # Fixing would require changing the script and the frontend binary.
  install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink .. dynamorio WORKING_DIRECTORY \${CMAKE_INSTALL_PREFIX}/${INSTALL_PREFIX})")

  # Add a docs link in the top-level docs/ dir
  install(CODE "file(WRITE \"\${CMAKE_INSTALL_PREFIX}/docs/DrMemory.html\" \"<html>\n<head>\n<meta http-equiv=\\\"refresh\\\" content=\\\"0; URL=../drmemory/drmemory/docs/html/index.html\\\">\n</head><body></body>\")")

else (BUILDING_SUB_PACKAGE)
  # Include DR so user doesn't have to download separately (PR 457417).
  # We don't need docs/ or include/.
  install(CODE "file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}\")")

  if (UNIX)
    # CPACK_INSTALLED_DIRECTORIES since 2.8.3 now properly preserves symlinks
    # (http://www.itk.org/Bug/view.php?id=10096) so we can just copy the dir.
    install(DIRECTORY ${DynamoRIO_DIR}/../${LIB_ARCH}/${build_type}
      DESTINATION ${INSTALL_PREFIX}${DR_install_dir}/${LIB_ARCH}
      FILE_PERMISSIONS ${owner_access} OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
      WORLD_READ WORLD_EXECUTE
      PATTERN "libdrdecode*" EXCLUDE
      # Static DR is large and we do not need it.
      PATTERN "libdynamorio_static*" EXCLUDE)
    # ext dir is currently empty but we need it to avoid drrun error (i#427)
    install(CODE "file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/ext/${LIB_ARCH}/${build_type}\")")
    # CPack seems to ignore empty dirs so add a README file
    install(CODE "file(WRITE \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/ext/${LIB_ARCH}/${build_type}/README.txt\" \"Currently empty.\n\")")
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
  install(CODE "file(WRITE \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/README.txt\" \"This is a copy of the parts of DynamoRIO needed to run ${toolname_cap_spc}.  See http://dynamorio.org for more information.\n\")")
  # on Windows we don't need all the ${BIN_ARCH}/ tools, and they take up space
  install(CODE "file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/${BIN_ARCH}\")")
  if (UNIX)
    if (USER_SPECIFIED_DynamoRIO_DIR) # else DR installs straight there (i#1449)
      install(CODE "configure_file(\"${DynamoRIO_DIR}/../${BIN_ARCH}/drrun\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/${BIN_ARCH}/drrun\" COPYONLY)")
    endif ()
    if (NOT APPLE) # FIXME DRi#1286: no nudge support yet on MacOS
      install(CODE "configure_file(\"${DynamoRIO_DIR}/../${BIN_ARCH}/nudgeunix\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/${BIN_ARCH}/nudgeunix\" COPYONLY)")
    endif (NOT APPLE)
    # drconfiglib and drinjectlib are now static libs so no need to install
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

  if (TOOL_DR_MEMORY)
    # For the new -coverage feature, we include a copy of drcov2lcov.
    # We keep it inside the dynamorio/ subdir so its rpath will still work.
    # XXX: a debug build of drmem pointing at an external DR will pull in a
    # release-build drcov2lcov whose rpath will point at a release DR yet
    # we only copy debug DR so it will fail -- we just live with this though
    # as a full RC package will work fine.
    if (USER_SPECIFIED_DynamoRIO_DIR)
      set(covdir tools)
    else ()
      set(covdir clients)
    endif ()
    if (UNIX)
      # We can't use get_target_property() for USER_SPECIFIED_DynamoRIO_DIR
      set(covhelper drcov2lcov)
    else ()
      set(covhelper drcov2lcov.exe)
    endif ()
    install(CODE "configure_file(\"${DynamoRIO_DIR}/../${covdir}/${BIN_ARCH}/${covhelper}\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/tools/${BIN_ARCH}/${covhelper}\" COPYONLY)")
    if (WIN32)
      install(CODE "configure_file(\"${DynamoRIO_DIR}/../${LIB_ARCH}/${build_type}/dynamorio.dll\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/tools/${BIN_ARCH}/dynamorio.dll\" COPYONLY)")
    endif ()
  endif ()
endif (BUILDING_SUB_PACKAGE)

# DRMF install rules
install(FILES ${framework_incdir}/drmemory_framework.h DESTINATION ${DRMF_INSTALL_INC})
install(FILES ${framework_dir}/DrMemoryFrameworkConfigVersion.cmake
  ${framework_dir}/DrMemoryFrameworkConfig.cmake
  DESTINATION ${DRMF_INSTALL})
# These cover all subdirs
install(DIRECTORY ${framework_bindir}/
  DESTINATION ${DRMF_INSTALL_BIN}
  FILE_PERMISSIONS ${owner_access} OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
  WORLD_READ WORLD_EXECUTE
  FILES_MATCHING
  PATTERN "*.debug"
  PATTERN "*.pdb"
  REGEX ".*.dSYM/.*DWARF/.*" # too painful to get right # of backslash for literal .
  PATTERN "*_int.pdb" EXCLUDE
  )

# We must append to this file to avoid cmake_install.cmake's diff from thinking
# the exports have changed and thus clobbering the other config's files.
install(CODE "file(APPEND \"${PROJECT_BINARY_DIR}/CMakeFiles/Export/cmake/${exported_targets_name}.cmake\" \"${exported_targets_append}\")")
# Create the exported targets file
# Note that we do not use the drmf_ NAMESPACE here: it's only needed for
# internal tests.
install(EXPORT ${exported_targets_name} DESTINATION ${DRMF_INSTALL})

# Check that we have version resources in all our binaries.
# We do this at install time once we have all binaries built, as it's a pain
# to individually add post-build commands.
if (WIN32)
  get_target_property(verinfo_path verinfo LOCATION${location_suffix})
  install(CODE "include(\"${PROJECT_SOURCE_DIR}/make/rccheck.cmake\")")
  install(CODE "check_version_resources(\"${PROJECT_BINARY_DIR}\" \"${verinfo_path}\")")
endif ()

###########################################################################
# packaging

# "make package package_source"

if (USER_SPECIFIED_DynamoRIO_DIR)
  set(favicon_path "${DynamoRIO_DIR}/../docs/html/favicon.ico")
else (USER_SPECIFIED_DynamoRIO_DIR)
  set(favicon_path "${DynamoRIO_SOURCE_DIR}/api/docs/images/favicon.ico")
endif (USER_SPECIFIED_DynamoRIO_DIR)

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
    if (APPLE)
      set(CPACK_SYSTEM_NAME "MacOS")
    else (APPLE)
      set(CPACK_SYSTEM_NAME "Linux")
    endif (APPLE)
  endif (VMKERNEL)
else (UNIX)
  # We don't require NSIS or WIX since we do "make package" as part of test suite
  set(WIX "WIX-NOTFOUND")
  set(NSIS "NSIS-NOTFOUND")
  # Our WIX config requires recent features
  if ("${CMAKE_VERSION}" VERSION_EQUAL "3.3" OR
      "${CMAKE_VERSION}" VERSION_GREATER "3.3")
    # WIX's candle.exe must be on the path for cpack to run it, so hints don't help
    find_program(WIX candle DOC "WIX for creating installer")
  endif ()
  # Prefer WIX
  if (NOT WIX)
    find_program(NSIS nsis HINT "$ENV{PROGRAMFILES}/NSIS" DOC
      "NSIS for creating installer")
  endif ()
  if (NSIS)
    message(STATUS "NSIS found: will build NSIS-based installer")
    set(CPACK_GENERATOR "ZIP;NSIS")
    # Ensure we have the NSIS with an 8192 PATH limit (i#1029)
    get_filename_component(nsis_path "${NSIS}" PATH)
    if (NOT EXISTS "${nsis_path}/makensis.exe")
      message(FATAL_ERROR "NSIS check needs to be updated")
    endif ()
    # we may have already run find_program on strings up above
    if (NOT strings)
      find_program(strings strings)
    endif ()
    if (strings)
      execute_process(COMMAND ${strings} "${nsis_path}/makensis.exe"
        RESULT_VARIABLE strings_result
        ERROR_QUIET
        OUTPUT_VARIABLE strings_out)
      if (strings_result)
        message(FATAL_ERROR "*** ${strings} failed to run ***\n")
      endif (strings_result)
      # The default has "NSIS_MAX_STRLEN\n1024": make sure we have 8192.
      string(REGEX MATCH "NSIS_MAX_STRLEN\n8192" big_limit "${strings_out}")
      if (big_limit)
        message(STATUS "NSIS has larger 8192 path limit")
      else ()
        message(FATAL_ERROR "Installed NSIS has a too-small path limit.  See i#1029.")
      endif ()
    endif (strings)
  elseif (WIX)
    message(STATUS "WIX found: will build WIX-based .msi installer")
    # Make sure to specify BUILDING_PACKAGE. See i#1099 about absolute path.
    set(CPACK_GENERATOR "ZIP;WIX")
    # Variables below are set to allow for upgrade but prevent
    # reinstalling the same version. See i#1620.
    set(CPACK_WIX_UPGRADE_GUID 1A8D7CEE-2ABA-4462-B0D6-86F26715128E)
    set(CPACK_WIX_PRODUCT_GUID 67675AD6-1FB0-4DE1-9ECF-84997515025E)
    set(CPACK_WIX_PATCH_FILE "${CMAKE_CURRENT_SOURCE_DIR}/make/WIX.patches.in")
    set(CPACK_WIX_EXTRA_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/make/WIX.extra.in")
    # This is required for the util:InternetShortcut in WIX.extra.in
    set(CPACK_WIX_EXTENSIONS "WiXUtilExtension")
    # This should show up in Add/Remove Programs:
    set(CPACK_WIX_PROPERTY_ARPURLINFOABOUT "http://drmemory.org")
    set(CPACK_WIX_PRODUCT_ICON "${favicon_path}")
  else ()
    message(STATUS "Neither NSIS nor WIX found (please install and add to path if desired).  Creating only a zip package.")
    set(CPACK_GENERATOR "ZIP")
  endif ()
  set(CPACK_SOURCE_GENERATOR "ZIP")
  set(CPACK_SYSTEM_NAME "Windows")
  if (USE_DRSYMS)
    set(CPACK_SYSTEM_NAME "Windows")
  else (USE_DRSYMS)
    set(CPACK_SYSTEM_NAME "Cygwin")
  endif (USE_DRSYMS)
endif (UNIX)

set(CPACK_PACKAGE_NAME "${toolname_cap_spc}")
set(CPACK_PACKAGE_VENDOR "Google")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/README")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${toolname_cap_spc} Memory Debugging Tool")
set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/license.txt")
set(CPACK_RESOURCE_FILE_README "${PROJECT_SOURCE_DIR}/README")

set(CPACK_SOURCE_IGNORE_FILES "~$" "/.svn" "/.git")

set(CPACK_PACKAGE_VERSION "${TOOL_VERSION_NUMBER}")
string(REGEX REPLACE
  "^([0-9]+)\\..*" "\\1" CPACK_PACKAGE_VERSION_MAJOR "${TOOL_VERSION_NUMBER}")
string(REGEX REPLACE
  "^[0-9]+\\.([0-9]+)\\..*" "\\1" CPACK_PACKAGE_VERSION_MINOR "${TOOL_VERSION_NUMBER}")
string(REGEX REPLACE
  "^[0-9]+\\.[0-9]+\\.([0-9]+)" "\\1" CPACK_PACKAGE_VERSION_PATCH "${TOOL_VERSION_NUMBER}")

if (WIN32 AND NOT BUILDING_SUB_PACKAGE)
  # Include DR so user doesn't have to download separately (PR 457417).
  # For Unix we do this file-by-file above b/c here we'd get duplicate
  # files due to cpack not preserving symlinks (filed as
  # http://www.itk.org/Bug/view.php?id=10096)
  # We don't need docs/, include/, or 64-bit.
  # We do include the debug lib (and default DR log dir) for
  # debugging in the field: it does take space but we'd probably regret
  # not supplying it.
  if (NOT USER_SPECIFIED_DynamoRIO_DIR)
    # install to drmemory exports dir
    install(DIRECTORY "${DynamoRIO_DIR}/../${LIB_ARCH}"
      DESTINATION "${DR_install_dir}"
      # Static DR is large and we do not need it.
      PATTERN "dynamorio_static*" EXCLUDE)
    # we don't need ext/ at all b/c we use static libs
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
endif (WIN32 AND NOT BUILDING_SUB_PACKAGE)

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
  "${toolname_cap}-${CPACK_PACKAGE_VERSION}-${TOOL_BUILD_NUMBER}-Source")

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
  "http://drmemory.org/" "${toolname_cap_spc} web page")
set(CPACK_NSIS_MUI_ICON "${favicon_path}")
# XXX: CPACK_PACKAGE_ICON: need a .bmp

# i#1009c#4: auto-register Dr. Memory as a Visual Studio External Tool
if (WIN32)
  install(TARGETS vs_external_tool DESTINATION "${INSTALL_BIN}"
    PERMISSIONS ${owner_access}
    OWNER_EXECUTE GROUP_READ GROUP_EXECUTE  WORLD_READ WORLD_EXECUTE)
  set(CPACK_NSIS_EXTRA_INSTALL_COMMANDS "ExecWait  '\\\"$INSTDIR\\\\bin\\\\vs_external_tool.exe\\\" \\\"$INSTDIR\\\\bin\\\\drmemory.exe'")
  set(CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS "ExecWait  '\\\"$INSTDIR\\\\bin\\\\vs_external_tool.exe\\\" -uninstall'")
endif (WIN32)

# Let external build file override all settings, but before CPack reads them
set(AUX_MAKEFILE "" CACHE FILEPATH "Path to an auxiliary CMakeLists.txt file.")
if (AUX_MAKEFILE)
  include("${AUX_MAKEFILE}")
endif (AUX_MAKEFILE)

include(CPack)
