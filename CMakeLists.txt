# **********************************************************
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

cmake_minimum_required(VERSION 2.6)

project(DrMemory)

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
if (TOOL_DR_HEAPSTAT)
  # Dr. Heapstat
  set(toolname drheapstat)
  set(tooldir ${toolname})
  set(toolname_cap DrHeapstat)
  set(toolname_cap_spc "Dr. Heapstat")
  set(DEFINES ${DEFINES} -DTOOL_DR_HEAPSTAT)
  # Note that for our combined multi-tool package (PR 470927) we use the DrMem
  # version number so this is essentially unused
  set(VERSION_NUMBER "1.0.0")

  # Flex building is done only for Dr. HeapStat visualization tool.  So Java
  # is needed only for that too.
  if (NOT DEFINED JAVA)     # Not using toolchain then
    include(FindJava)
    if (DEFINED JAVA_RUNTIME)
      set(JAVA "${JAVA_RUNTIME}")
    else (DEFINED JAVA_RUNTIME)
      message(FATAL_ERROR "Can't find Java VM.")
    endif (DEFINED JAVA_RUNTIME)
  endif (NOT DEFINED JAVA)

  # There is no standard install path so the user must tell us where they
  # installed the Flex SDK.
  set(FLEX_SDK "" CACHE PATH "Path to Flex SDK.")
  set(FLEX_MXMLC "${FLEX_SDK}/lib/mxmlc.jar"
      CACHE FILEPATH "Path to Flex MXML compiler.")
  if (NOT EXISTS "${FLEX_MXMLC}")
      message(FATAL_ERROR "Flex compiler ${FLEX_MXMLC} not found.")
  endif ()

  set(FLEX_FRAMEWORKS "${FLEX_SDK}/frameworks"
      CACHE PATH "Path to Flex frameworks, i.e., standard libraries.")
  if (NOT EXISTS "${FLEX_FRAMEWORKS}")
      message(FATAL_ERROR "Flex frameworks path ${FLEX_FRAMEWORKS} not found.")
  endif ()
  set(DRSYMS_DEFAULT OFF)
else (TOOL_DR_HEAPSTAT)
  # Dr. Memory
  set(toolname drmemory)
  set(tooldir ${toolname})
  set(toolname_cap DrMemory)
  set(toolname_cap_spc "Dr. Memory")
  set(DEFINES ${DEFINES} -DTOOL_DR_MEMORY)
  # should we have a real .rc file instead?
  set(VERSION_NUMBER "1.3.1")
  set(DRSYMS_DEFAULT ON)
endif (TOOL_DR_HEAPSTAT)

set(BUILD_NUMBER "1" CACHE STRING "Build number (must be <64K)")

set(DEFINES ${DEFINES}
  -DBUILD_NUMBER=${BUILD_NUMBER}
  -DVERSION_NUMBER=${VERSION_NUMBER}
  -DVERSION_STRING="${VERSION_NUMBER}")

if (WIN32)
  # i#44/PR 243532: online symbol access
  option(USE_DRSYMS "use drsyms DR Extension online symbols instead of post-processing"
    ${DRSYMS_DEFAULT})
  if (USE_DRSYMS)
    set(DEFINES ${DEFINES} -DUSE_DRSYMS)
  endif (USE_DRSYMS)

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

  # With the new drinjectlib-based front end we do not use perl or perl2exe
  # at all on Windows (xref i#265/PR 486139)
  if (OFF) # disabling
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
  endif (OFF)
endif (WIN32)

# Dr. Memory only supports 32-bit today
set(SUPPORT_64BIT OFF)
if (CMAKE_C_SIZEOF_DATA_PTR EQUAL 8 OR CMAKE_CXX_SIZEOF_DATA_PTR EQUAL 8)
  if (NOT SUPPORT_64BIT)
    message(FATAL_ERROR "64-bit not supported (on Linux, set CFLAGS=-m32 CXXFLAGS=-m32)")
  endif (NOT SUPPORT_64BIT)
  set(X64 ON)
else()
  set(X64 OFF)
endif ()

if ("${CMAKE_BUILD_TYPE}" MATCHES "Debug")
  # FIXME: use a configure.h
  set(DEFINES ${DEFINES} -DDEBUG -DSTATISTICS)
  set(DEBUG ON)
else ()
  if (UNIX)
    # has enough debug info
    set(CMAKE_BUILD_TYPE "Release")
  else (UNIX)
    # we want pdb for release build
    set(CMAKE_BUILD_TYPE "RelWithDebInfo")
  endif (UNIX)
  set(DEBUG OFF)
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
  # default from cmake has /W3 so remove to avoid warning about overriding
  string(REGEX REPLACE "/W[0-9]" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
  string(REGEX REPLACE "/W[0-9]" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
  string(REGEX REPLACE "/W[0-9]" "" CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}
    "${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")
  string(REGEX REPLACE "/W[0-9]" "" CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER}
    "${CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")
  # disable stack protection: "unresolved external symbol ___security_cookie"
  set(CL_CFLAGS "/GS-")
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
  # The 2003 DDK (3790.1830) or Vista WDK (6000) both have these paths:
  if (X64)
    set(NTDLL_LIB_SUBPATH lib/wnet/amd64)
  else (X64)
    set(NTDLL_LIB_SUBPATH lib/w2k/i386)
  endif (X64)
  # Use convention of DynamoRIO sources: DDKROOT env var
  if (NOT "$ENV{DDKROOT}" STREQUAL "")
    set(DDK_ROOT "$ENV{DDKROOT}")
    # Check default install path
  elseif (EXISTS "$ENV{SYSTEMDRIVE}/WINDDK/3790.1830/")
    set(DDK_ROOT "$ENV{SYSTEMDRIVE}/WINDDK/3790.1830/")
  elseif (EXISTS "$ENV{SYSTEMDRIVE}/WINDDK/6000/")
    set(DDK_ROOT "$ENV{SYSTEMDRIVE}/WINDDK/6000/")
  endif (NOT "$ENV{DDKROOT}" STREQUAL "")
  # Use find_library() and not find_path() in case on LIB env var or sthg
  find_library(NTDLL_LIBPATH ntdll.lib HINTS "${DDK_ROOT}/${NTDLL_LIB_SUBPATH}"
    DOC "Path to ntdll.lib from either 2003 DDK (3790.1830) or Vista WDK (6000)")
  if (NTDLL_LIBPATH-NOTFOUND OR NOT EXISTS "${NTDLL_LIBPATH}")
    message(FATAL_ERROR "ntdll.lib not found: required to build")
  endif (NTDLL_LIBPATH-NOTFOUND OR NOT EXISTS "${NTDLL_LIBPATH}")
  message(STATUS "Found ntdll.lib: ${NTDLL_LIBPATH}")
  get_filename_component(NTDLL_LIBPATH "${NTDLL_LIBPATH}" PATH)
  link_directories(${NTDLL_LIBPATH})

  # We need a newer version of dbghelp.dll than is in system32/ on 2K or XP.
  # It is redistributable: "you can distribute the DLL with your application".
  # 6.3+ works, 5.2 does not, haven't tested in between.
  # WINDDK/3790.1830/bin/x86/dbghelp.dll is 6.3.
  if (EXISTS "${DDK_ROOT}/bin/x86/dbghelp.dll")
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

endif (WIN32)

# To run out of build dir we put libs and scripts in dirs that match install layout
# except minus the toolname prefix dir.
# The CPack NSIS interface requires a bin/ dir, so for the Windows package
# we prefix bin/
if (USE_DRSYMS)
  set(INSTALL_BIN_PREFIX ".")
  set(BUILD_BIN_PREFIX ".")
elseif (PERL_TO_EXE)
  # We are only releasing Dr. Memory so no toolnames: would need to create
  # shortcut or .bat file to run from right dir
  set(INSTALL_BIN_PREFIX "bin")
  set(BUILD_BIN_PREFIX "bin")
else (PERL_TO_EXE)
  # When installed we now use a bin dir for scripts
  set(INSTALL_BIN_PREFIX "${toolname}/bin")
  set(BUILD_BIN_PREFIX "bin")
endif (USE_DRSYMS)
if (USE_DRSYMS)
  # For NSIS we have everything in top-level bin/
  # Once we have x64 we'll need to address: fix CPack?
  if (X64)
    set(INSTALL_BIN "${INSTALL_BIN_PREFIX}/bin64")
    set(BUILD_BIN "${BUILD_BIN_PREFIX}/bin64")
  else (X64)
    set(INSTALL_BIN "${INSTALL_BIN_PREFIX}/bin")
    set(BUILD_BIN "${BUILD_BIN_PREFIX}/bin")
  endif (X64)
else (USE_DRSYMS)
  if (X64)
    set(INSTALL_BIN "${INSTALL_BIN_PREFIX}/bin64")
    set(BUILD_BIN "${BUILD_BIN_PREFIX}/bin64")
  else (X64)
    set(INSTALL_BIN "${INSTALL_BIN_PREFIX}/bin32")
    set(BUILD_BIN "${BUILD_BIN_PREFIX}/bin32")
  endif (X64)
endif (USE_DRSYMS)
if (DEBUG)
  set(INSTALL_LIB "${INSTALL_BIN}/debug")
  set(BUILD_LIB "${BUILD_BIN}/debug")
else (DEBUG)
  set(INSTALL_LIB "${INSTALL_BIN}/release")
  set(BUILD_LIB "${BUILD_BIN}/release")
endif (DEBUG)
set(LIBRARY_OUTPUT_PATH "${PROJECT_BINARY_DIR}/${BUILD_LIB}")
set(EXECUTABLE_OUTPUT_PATH "${PROJECT_BINARY_DIR}/${BUILD_BIN}")

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

find_package(Doxygen)
if (NOT DOXYGEN_FOUND)
  message("doxygen is required to build the documentation")
else ()
  add_subdirectory(docs)
endif ()

# configure tests before configure_DynamoRIO_client clears global cflags
enable_testing()
add_subdirectory(tests)

if (DEFINED DynamoRIO_DIR)
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
else (DEFINED DynamoRIO_DIR)
  # default value
  set(DynamoRIO_DIR "${PROJECT_BINARY_DIR}/../exports/cmake" CACHE PATH
    "DynamoRIO installation's cmake directory")
endif (DEFINED DynamoRIO_DIR)

set(DynamoRIO_REG_COMPATIBILITY ON)
find_package(DynamoRIO 2.1)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)
# from here on use what was found, not what was passed in
get_filename_component(DynamoRIO_DIR "${DynamoRIO_CONFIG}" PATH)
# preserve it in the cache so it's easy to tell
set(DynamoRIO_DIR "${DynamoRIO_DIR}" CACHE PATH "Path to DynamoRIO.")
message(STATUS "Found DynamoRIO: ${DynamoRIO_DIR}")

if (TOOL_DR_HEAPSTAT)
  # Dr. Heapstat
  set(srcs
    drheapstat/drheapstat.c
    drheapstat/staleness.c
    common/alloc.c
    common/alloc_unopt.c
    common/heap.c
    common/callstack.c
    common/utils.c
    common/redblack.c
    common/crypto.c
    # For leak checking we need stack.c but it pulls in the inter-dependent
    # readwrite, fastpath, and shadow: we'll want those for staleness anyway.
    # Looking more and more like Dr. Memory!
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
    drmemory/drmemory.c
    drmemory/readwrite.c
    drmemory/fastpath.c
    drmemory/stack.c
    drmemory/shadow.c
    drmemory/options.c
    common/alloc.c
    common/alloc_unopt.c
    common/heap.c
    common/callstack.c
    drmemory/alloc_drmem.c
    drmemory/syscall.c
    drmemory/report.c
    drmemory/replace.c
    drmemory/leak.c
    drmemory/perturb.c
    common/utils.c
    common/redblack.c
    common/crypto.c)
  if (UNIX)
    set(srcs ${srcs} drmemory/syscall_linux.c)
  else (UNIX)
    set(srcs ${srcs} drmemory/syscall_windows.c)
  endif (UNIX)
endif (TOOL_DR_HEAPSTAT)
set(scripts ${toolname}.pl postprocess.pl)

include_directories(common ${tooldir})

# new set_property() doesn't want -D but our cpp invocation above does
string(REGEX REPLACE "-D" "" DEFINES_NO_D "${DEFINES}")

if (WIN32 AND USE_DRSYMS)
  # front-end needs to be name drmemory.exe and thus has drmemory.pdb, so
  # we rename client lib (plus cmake best w/o same-name targets)
  set(client_target "${toolname}lib")

  # assuming only DrMem for now
  add_executable(${toolname} drmemory/frontend.c)
  configure_DynamoRIO_standalone(${toolname})
  target_link_libraries(${toolname} drinjectlib drconfiglib)
  set_target_properties(${toolname} PROPERTIES
    VERSION ${VERSION_NUMBER})
  set_property(TARGET ${toolname} PROPERTY COMPILE_DEFINITIONS ${DEFINES_NO_D})
else (WIN32 AND USE_DRSYMS)
  set(client_target ${toolname})
endif (WIN32 AND USE_DRSYMS)

add_library(${client_target} SHARED ${srcs})
configure_DynamoRIO_client(${client_target})
# i#277/PR 540817: features split into DynamoRIO Extensions
use_DynamoRIO_extension(${client_target} drcontainers)
if (WIN32 AND USE_DRSYMS)
  use_DynamoRIO_extension(${client_target} drsyms)
endif (WIN32 AND USE_DRSYMS)

if (UNIX)
  set(DISABLE_OPTS "-O0")
else (UNIX)
  set(DISABLE_OPTS "/Od")
endif (UNIX)
set_property(SOURCE common/alloc_unopt.c APPEND PROPERTY COMPILE_FLAGS "${DISABLE_OPTS}")

# Though the swf file isn't an executable it is in bin32 because it isn't 
# exposed to the users; it isn't in lib because, well, it isn't a lib.
if (TOOL_DR_HEAPSTAT)
  add_custom_target(vistool ALL DEPENDS "${EXECUTABLE_OUTPUT_PATH}/${toolname}.swf")
  add_custom_command(
    OUTPUT ${EXECUTABLE_OUTPUT_PATH}/${toolname}.swf
    DEPENDS ${PROJECT_SOURCE_DIR}/${tooldir}/${toolname}.mxml
    COMMAND ${JAVA}
    ARGS -jar ${FLEX_MXMLC} "+flexlib=${FLEX_FRAMEWORKS}"
      ${PROJECT_SOURCE_DIR}/${tooldir}/${toolname}.mxml
      -o ${EXECUTABLE_OUTPUT_PATH}/${toolname}.swf
    VERBATIM)
endif (TOOL_DR_HEAPSTAT)

if (WIN32)
  # we statically link with msvcrt.lib for vc /O2's use of __aulldvrm
  # this does NOT add any dynamic dependence on libc
  target_link_libraries(${client_target} ntdll msvcrt)

  # our addr2line for Windows
  add_executable(winsyms tools/winsyms.c)
  target_link_libraries(winsyms dbghelp)
  # configure_DynamoRIO_client clear global flags so use the saved version
  #   (putting the add_executable earlier doesn't help)
  # request static libc to avoid manifest files and libc portability issues
  string(REGEX REPLACE "/MD" "/MT" ORIG_CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}
    "${ORIG_CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")
  set_source_files_properties(tools/winsyms.c PROPERTIES
    COMPILE_FLAGS "${ORIG_CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")
endif (WIN32)

set_target_properties(${client_target} PROPERTIES
  VERSION ${VERSION_NUMBER})
set_property(TARGET ${client_target} PROPERTY COMPILE_DEFINITIONS ${DEFINES_NO_D})

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
if (NOT PERL_TO_EXE AND NOT USE_DRSYMS)
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/${tooldir}/${toolname}.pl"
    "${PROJECT_BINARY_DIR}/${BUILD_BIN_PREFIX}/${toolname}.pl" @ONLY)
  if (NOT USE_DRSYMS)
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/${tooldir}/postprocess.pl"
      "${PROJECT_BINARY_DIR}/${BUILD_BIN}/postprocess.pl" COPYONLY)
    set(script_aux "${CMAKE_CURRENT_SOURCE_DIR}/${tooldir}/postprocess.pl")
  endif (NOT USE_DRSYMS)
  set(script_main "${PROJECT_BINARY_DIR}/${BUILD_BIN_PREFIX}/${toolname}.pl"
    "${options_for_perl}")
endif (NOT PERL_TO_EXE AND NOT USE_DRSYMS)
if (WIN32)
  configure_file("${DBGHELP_DLL}"
    "${PROJECT_BINARY_DIR}/${BUILD_BIN}/dbghelp.dll" COPYONLY)
  if (USE_DRSYMS)
    configure_file("${DynamoRIO_DIR}/../lib32/drconfiglib.dll"
      "${PROJECT_BINARY_DIR}/${BUILD_BIN}/drconfiglib.dll" COPYONLY)
    configure_file("${DynamoRIO_DIR}/../lib32/drinjectlib.dll"
      "${PROJECT_BINARY_DIR}/${BUILD_BIN}/drinjectlib.dll" COPYONLY)
    # above copy is for winsyms.exe, this is for drmemorylib
    configure_file("${DBGHELP_DLL}"
      "${PROJECT_BINARY_DIR}/${BUILD_LIB}/dbghelp.dll" COPYONLY)
  endif (USE_DRSYMS)
endif (WIN32)
if (TOOL_DR_HEAPSTAT)
  # we need a copy of Dr. Memory's postprocess for leaks (PR 536878)
  if (PERL_TO_EXE)
    message(FATAL_ERROR "perl2exe for Dr. Heapstat not supported")
  endif (PERL_TO_EXE)
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/drmemory/postprocess.pl"
    "${PROJECT_BINARY_DIR}/${BUILD_BIN}/postleaks.pl" COPYONLY)
  set(script_aux ${script_aux} "${PROJECT_BINARY_DIR}/${BUILD_BIN}/postleaks.pl")
else (TOOL_DR_HEAPSTAT)
  set(defsupp_out "${PROJECT_BINARY_DIR}/${BUILD_BIN}/suppress-default.txt")
  if (WIN32)
    set(defsupp_in "${CMAKE_CURRENT_SOURCE_DIR}/${tooldir}/suppress-default.win.txt")
    configure_file("${defsupp_in}" "${defsupp_out}" COPYONLY)
  else (WIN32)
    set(defsupp_in "${CMAKE_CURRENT_SOURCE_DIR}/${tooldir}/suppress-default.lin.txt")
    file(READ "${defsupp_in}" txt)
    file(WRITE "${defsupp_out}" "${txt}")
  endif (WIN32)
endif (TOOL_DR_HEAPSTAT)

###########################################################################
# installation

# I want to override the default CMAKE_INSTALL_PREFIX, but keep
# the name of the var so CPack and other standard tools work.
# The best I can come up with is to disallow installing to the
# default location, which seems reasonable.
# If we didn't use standard tools we could set CMAKE_INSTALL_PREFIX
# to be CACHE INTERNAL FORCE to INSTALL_PREFIX.
if (UNIX)
  set(default_install "/usr/local")
else (UNIX)
  set(default_install "$ENV{SYSTEMDRIVE}/Program Files")
endif (UNIX)
if ("${CMAKE_INSTALL_PREFIX}" MATCHES "^${default_install}")
  if (X64)
    set(EXP_DIR exports64)
  else (X64)
    set(EXP_DIR exports32)
  endif (X64)
  set(CMAKE_INSTALL_PREFIX "${PROJECT_BINARY_DIR}/../${EXP_DIR}" 
    CACHE PATH "install path" FORCE)
endif ("${CMAKE_INSTALL_PREFIX}" MATCHES "^${default_install}")
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
    DESTINATION "${INSTALL_BIN}"
    PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)
  if (USE_DRSYMS)
    install(FILES
      ${PROJECT_BINARY_DIR}/${BUILD_BIN}/dbghelp.dll
      DESTINATION "${INSTALL_LIB}"
      PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
      WORLD_READ WORLD_EXECUTE)
    install(FILES
      ${PROJECT_BINARY_DIR}/${BUILD_BIN}/drconfiglib.dll
      ${PROJECT_BINARY_DIR}/${BUILD_BIN}/drinjectlib.dll
      DESTINATION "${INSTALL_BIN}"
      PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
      WORLD_READ WORLD_EXECUTE)
  endif (USE_DRSYMS)
  install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/README
    DESTINATION "."
    RENAME "README.txt")
else (WIN32)
  install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/README
    DESTINATION ".")
endif (WIN32)
if (USE_DRSYMS)
  install(TARGETS ${toolname} DESTINATION "${INSTALL_BIN}"
    PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)
else (USE_DRSYMS)
  install(FILES
    ${script_main}
    DESTINATION "${INSTALL_BIN_PREFIX}"
    PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)
endif (USE_DRSYMS)
# We put "helper" files inside bin32/ so only top-level script is visible
if (NOT "${script_aux}" STREQUAL "")
  install(FILES
    ${script_aux}
    DESTINATION "${INSTALL_BIN}"
    PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE)
endif ()
if (TOOL_DR_HEAPSTAT)
  install(FILES
    ${EXECUTABLE_OUTPUT_PATH}/${toolname}.swf
    DESTINATION "${INSTALL_BIN}"
    PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)
else (TOOL_DR_HEAPSTAT)
  install(FILES
    ${PROJECT_BINARY_DIR}/${BUILD_BIN}/suppress-default.txt
    DESTINATION "${INSTALL_BIN}"
    PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)
endif (TOOL_DR_HEAPSTAT)
install(DIRECTORY ${LIBRARY_OUTPUT_PATH}/
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
if (NOT PERL_TO_EXE AND NOT USE_DRSYMS)
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
        "\"%~dp0..\\drmemory\\bin32\\drmemory.exe\" %*\n")
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
endif (NOT PERL_TO_EXE AND NOT USE_DRSYMS)

# create empty logs dir for release package
# be sure to escape ",$ since evaluated at install time not configure time
install(CODE "file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/${toolname}/logs\")")
# CPack seems to ignore empty dirs so add a README file
install(CODE "file(WRITE \"\${CMAKE_INSTALL_PREFIX}/${toolname}/logs/README\" \"Default destination for log files.\n\")")

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
  install(CODE "file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/logs\")")
  # CPack seems to ignore empty dirs so add a README file
  install(CODE "file(WRITE \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/logs/README\" \"Default destination for DynamoRIO log files.\n\")")
  
  install(CODE "file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/lib32/release\")")
  install(CODE "configure_file(\"${DynamoRIO_DIR}/../lib32/release/libdrpreload.so\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/lib32/release/\" COPYONLY)")
  install(CODE "configure_file(\"${DynamoRIO_DIR}/../lib32/release/libdynamorio.so\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/lib32/release/\" COPYONLY)")
  # Include both .debug files.  These have version #s so we glob.
  # Note that addr2line/gdb will still find the 1.x.debug since the name is
  # stored in the library.
  install(CODE "file(GLOB debugfiles \"${DynamoRIO_DIR}/../lib32/release/*.debug\")\nforeach (dbg \${debugfiles})\n  configure_file(\"\${dbg}\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/lib32/release/\" COPYONLY)\nendforeach()")
  if (DEBUG)
    install(CODE "file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/lib32/debug\")")
    install(CODE "configure_file(\"${DynamoRIO_DIR}/../lib32/debug/libdrpreload.so\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/lib32/debug/\" COPYONLY)")
    install(CODE "configure_file(\"${DynamoRIO_DIR}/../lib32/debug/libdynamorio.so\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/lib32/debug/\" COPYONLY)")
    # Include both .debug files.  These have version #s so we glob.
    install(CODE "file(GLOB debugfiles \"${DynamoRIO_DIR}/../lib32/debug/*.debug\")\nforeach (dbg \${debugfiles})\n  configure_file(\"\${dbg}\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/lib32/debug/\" COPYONLY)\nendforeach()")
  endif (DEBUG)
endif (UNIX)

# can't find way to package external individual files (can do whole dir)
# and we don't need entire DR docs/, include/, etc. so we do these
# files individually
install(CODE "configure_file(\"${DynamoRIO_DIR}/../License.txt\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/License.txt\" COPYONLY)")
# rather whan whole README, which talks about running samples, etc.:
install(CODE "file(WRITE \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/README\" \"This is a copy of the parts of DynamoRIO needed to run ${toolname_cap_spc}.  See http://dynamorio.org for more information.\n\")")
install(CODE "configure_file(\"${DynamoRIO_DIR}/../ACKNOWLEDGEMENTS\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/ACKNOWLEDGEMENTS\" COPYONLY)")
# on Windows we don't need all the bin32/ tools, and they take up space
install(CODE "file(MAKE_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/bin32\")")
if (UNIX)
  install(CODE "configure_file(\"${DynamoRIO_DIR}/../bin32/drrun\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/bin32/drrun\" COPYONLY)")
  install(CODE "configure_file(\"${DynamoRIO_DIR}/../bin32/nudgeunix\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/bin32/nudgeunix\" COPYONLY)")
else (UNIX)
  if (NOT USE_DRSYMS)
    install(CODE "configure_file(\"${DynamoRIO_DIR}/../bin32/drconfig.exe\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/bin32/drconfig.exe\" COPYONLY)")
    install(CODE "configure_file(\"${DynamoRIO_DIR}/../bin32/drinject.exe\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/bin32/drinject.exe\" COPYONLY)")
    install(CODE "configure_file(\"${DynamoRIO_DIR}/../bin32/drrun.exe\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/bin32/drrun.exe\" COPYONLY)")
  endif (NOT USE_DRSYMS)
  install(CODE "configure_file(\"${DynamoRIO_DIR}/../bin32/drconfiglib.dll\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/bin32/drconfiglib.dll\" COPYONLY)")
  install(CODE "configure_file(\"${DynamoRIO_DIR}/../bin32/drinjectlib.dll\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/bin32/drinjectlib.dll\" COPYONLY)")
  install(CODE "configure_file(\"${DynamoRIO_DIR}/../bin32/DRcontrol.exe\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/bin32/DRcontrol.exe\" COPYONLY)")
  install(CODE "configure_file(\"${DynamoRIO_DIR}/../bin32/DRview.exe\" \"\${CMAKE_INSTALL_PREFIX}/${DR_install_dir}/bin32/DRview.exe\" COPYONLY)")
endif (UNIX)

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
  set(CPACK_GENERATOR "ZIP;NSIS")
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

set(CPACK_PACKAGE_VERSION "${VERSION_NUMBER}")
string(REGEX REPLACE 
  "^([0-9]+)\\..*" "\\1" CPACK_PACKAGE_VERSION_MAJOR "${VERSION_NUMBER}")
string(REGEX REPLACE 
  "^[0-9]+\\.([0-9]+)\\..*" "\\1" CPACK_PACKAGE_VERSION_MINOR "${VERSION_NUMBER}")
string(REGEX REPLACE 
  "^[0-9]+\\.[0-9]+\\.([0-9]+)" "\\1" CPACK_PACKAGE_VERSION_PATCH "${VERSION_NUMBER}")

if (WIN32)
  # Include DR so user doesn't have to download separately (PR 457417).
  # For Unix we do this file-by-file above b/c here we'd get duplicate
  # files due to cpack not preserving symlinks (filed as
  # http://www.itk.org/Bug/view.php?id=10096)
  # We don't need docs/, include/, or 64-bit.
  # We do include 32-bit debug lib (and default DR log dir) for
  # debugging in the field: it does take space but we'd probably regret
  # not supplying it.
  if (DEBUG)
    set(CPACK_INSTALLED_DIRECTORIES 
      "${DynamoRIO_DIR}/../lib32;${DR_install_dir}/lib32"
      "${DynamoRIO_DIR}/../ext/lib32;${DR_install_dir}/ext/lib32"
      "${DynamoRIO_DIR}/../logs;${DR_install_dir}/logs")
  else (DEBUG)
    set(CPACK_INSTALLED_DIRECTORIES 
      "${DynamoRIO_DIR}/../lib32/release;${DR_install_dir}/lib32/release"
      "${DynamoRIO_DIR}/../ext/lib32/release;${DR_install_dir}/ext/lib32/release")
  endif (DEBUG)
endif (WIN32)

# CPack tarballs do not allow setting a different name for the base
# directory and the file: I tried a ton of CPack variables for "install
# dir" and looked at the source code.  Most of the variables are for the
# other installers (rpm, nsis).  I can hack it via
# CPACK_TEMPORARY_PACKAGE_FILE_NAME if I hardcode the exentsion: but maybe
# having the full version in the base dir is a good thing, though I'm not
# sure about the caps.
set(CPACK_PACKAGE_FILE_NAME
  "${toolname_cap}-${CPACK_SYSTEM_NAME}-${CPACK_PACKAGE_VERSION}-${BUILD_NUMBER}")
set(CPACK_SOURCE_PACKAGE_FILE_NAME
  "${toolname_cap}-${CPACK_SYSTEM_NAME}-${CPACK_PACKAGE_VERSION}-${BUILD_NUMBER}-Source")

# NSIS settings
set(CPACK_PACKAGE_INSTALL_DIRECTORY "${toolname_cap_spc}")
set(CPACK_PACKAGE_INSTALL_REGISTRY_KEY "${toolname_cap_spc}")
set(CPACK_PACKAGE_RELOCATABLE "true")
set(CPACK_NSIS_MODIFY_PATH ON)
if (PERL_TO_EXE OR USE_DRSYMS)
  # CMake hardcodes bin/ for desktop links (CMake bug #7828) so
  # we rearranged our dirs since we really need one.
  set(CPACK_PACKAGE_EXECUTABLES "${toolname}" "${toolname_cap_spc} (drag your app here)")
  set(CPACK_CREATE_DESKTOP_LINKS "${toolname}")
endif (PERL_TO_EXE OR USE_DRSYMS)
set(CPACK_NSIS_MENU_LINKS 
  # We automatically get an entry for ${toolname}.exe since it's in the
  # CPACK_PACKAGE_EXECUTABLES list, even though we don't want one.
  "${toolname}/bin32/" "Explore ${toolname_cap_spc} (drag your app onto ${toolname}.exe)"
  "${toolname}/docs/html/index.html" "${toolname_cap_spc} documentation"
  "http://dynamorio.org/${toolname}.html" "${toolname_cap_spc} web page")
set(CPACK_NSIS_MUI_ICON "${DynamoRIO_DIR}/../docs/html/favicon.ico")
set(CPACK_NSIS_MUI_UNIICON "${DynamoRIO_DIR}/../docs/html/favicon.ico")
# FIXME: CPACK_PACKAGE_ICON: need a .bmp

# Let external build file override all settings, but before CPack reads them
set(AUX_MAKEFILE "" CACHE FILEPATH "Path to an auxiliary CMakeLists.txt file.")
if (AUX_MAKEFILE)
  include("${AUX_MAKEFILE}")
endif (AUX_MAKEFILE)

include(CPack)
