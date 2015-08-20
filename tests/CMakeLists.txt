# **********************************************************
# Copyright (c) 2010-2014 Google, Inc.  All rights reserved.
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

# Restore global flags after all configure_DynamoRIO_client() calls.
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

include(CheckCCompilerFlag)

if (UNIX)
  CHECK_C_COMPILER_FLAG("-Wno-unused-but-set-variable" nounused_avail)
endif(UNIX)

# tests are always built w/o optimizations and with symbols,
# regardless of DrMem library settings
set(CMAKE_BUILD_TYPE "Debug")

set_output_dirs("${PROJECT_BINARY_DIR}/tests")

# For their annotations.
include_directories("../third_party/valgrind")

# Restore original flags from before configure_DynamoRIO_client plus
# add_subdirectory(dynamorio) cleared global cflags.

if (WIN32)
  # if MinGW gcc is available, we do some extra tests
  # (we do not yet support Cygwin)
  # Look for version installed with Cygwin first just b/c my machines have a
  # more recent MinGW there.
  find_program(GCC i686-pc-mingw32-g++.exe DOC "path to MinGW g++.exe"
    PATHS "c:/cygwin/bin")
  if (NOT GCC)
    find_program(GCC mingw32-g++.exe DOC "path to MinGW g++.exe" PATHS "c:/mingw/bin")
  endif (NOT GCC)
  if (NOT GCC)
    message(STATUS "MinGW gcc not found: some tests will be disabled")
  else (NOT GCC)
    message(STATUS "Found MinGW gcc at ${GCC}")
  endif (NOT GCC)
  find_program(mingwlib libstdc++-6.dll
    HINTS "c:/cygwin/usr/i686-pc-mingw32/sys-root/mingw/bin" "c:/mingw/bin"
    DOC "path to MinGW libstdc++-6.dll")
  if (mingwlib)
    get_filename_component(mingw_path ${mingwlib} PATH)
    message(STATUS "Found ${mingwlib}, enabling shared lib MinGW test")
  endif ()
endif (WIN32)

function(append_compile_flags target newflags)
  get_target_property(cur_flags ${target} COMPILE_FLAGS)
  # cmake should add an APPEND option
  if (NOT cur_flags)
    set(cur_flags "")
  endif (NOT cur_flags)
  set_target_properties(${target} PROPERTIES
    COMPILE_FLAGS "${cur_flags} ${newflags}")
endfunction(append_compile_flags)

function(set_props target)
  if (UNIX)
    if (HAVE_FVISIBILITY)
      set(defs ${defs} USE_VISIBILITY_ATTRIBUTES)
    endif (HAVE_FVISIBILITY)
  endif (UNIX)
  if (VMKERNEL)
    set(defs ${defs} VMX86_SERVER)
  endif (VMKERNEL)
  set_property(TARGET ${target} PROPERTY COMPILE_DEFINITIONS
    ${defs} ${DEFINES_NO_D} ${DR_DEFINES_NO_D})
  # enough tests need this (malloc, free, registers, cs2bug, float, etc.)
  # that we add to all tests
  if (nounused_avail)
    append_compile_flags(${target} "-Wno-unused-but-set-variable")
  endif (nounused_avail)
endfunction(set_props)

function(tobuild name source)
  set(srcs ${source})

  # support same-file asm code
  if (NOT DEFINED ${name}_disable_asm)
    file(READ "${CMAKE_CURRENT_SOURCE_DIR}/${source}" srccode)
    if ("${srccode}" MATCHES "ifndef ASM_CODE_ONLY")
      add_split_asm_target("${CMAKE_CURRENT_SOURCE_DIR}/${source}" asm_source gen_asm_tgt
        "_asm" "${asm_defs}" "${asm_deps}")
      set(srcs ${srcs} ${asm_source})
    endif ("${srccode}" MATCHES "ifndef ASM_CODE_ONLY")
  endif ()

  add_executable(${name} ${srcs})
  set_props(${name})

  if ("${srccode}" MATCHES "ifndef ASM_CODE_ONLY")
    if (WIN32)
      # DRi#893: asm code is producing safeseh compilation failures w/ VS2012.
      # I believe I have the proper prologue+epilogue but I still the error, so:
      append_property_string(TARGET ${name} LINK_FLAGS "/safeseh:no")
    endif ()
    if ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
      add_dependencies(${name} ${gen_asm_tgt})
    endif ()
  endif ()
endfunction(tobuild)

function(append_link_flags target newflags)
  get_target_property(cur_ldflags ${target} LINK_FLAGS)
  # cmake should add an APPEND option
  if (NOT cur_ldflags)
    set(cur_ldflags "")
  endif (NOT cur_ldflags)
  set_target_properties(${target} PROPERTIES
    LINK_FLAGS "${cur_ldflags} ${newflags}")
endfunction(append_link_flags)

function(tobuild_lib name source cust_flags cust_link)
  add_library(${name} SHARED ${source})
  set_props(${name})
  get_target_property(cur_flags ${name} COMPILE_FLAGS)
  if (NOT cur_flags)
    set(cur_flags "")
  endif (NOT cur_flags)
  set_target_properties(${name} PROPERTIES COMPILE_FLAGS "${cur_flags} ${cust_flags}")
  append_link_flags(${name} "${cust_link}")
endfunction(tobuild_lib)

# tools for nudge tests
# to avoid conflict w/ DR's run_in_bg target we use a different target name
tobuild(run_in_bg_tgt run_in_bg.c)
set_target_properties(run_in_bg_tgt PROPERTIES OUTPUT_NAME run_in_bg)
if (WIN32)
  target_link_libraries(run_in_bg_tgt ${ntimp_lib})
  if (NOT USER_SPECIFIED_DynamoRIO_DIR AND "${CMAKE_GENERATOR}" MATCHES "Visual Studio")
    # for parallel build correctness we need a target dependence
    add_dependencies(run_in_bg_tgt ntimp_tgt)
  endif ()
endif (WIN32)

# For more portable testing (PR 544430):
# 1) use relative dirs within parent build dir
if (X64)
  set(BIN_ARCH "bin64")
else ()
  set(BIN_ARCH "bin")
endif ()
file(RELATIVE_PATH bin_relative "${CMAKE_CURRENT_BINARY_DIR}"
  "${PROJECT_BINARY_DIR}/${BUILD_BIN_PREFIX}/${BIN_ARCH}")
# 2) parameterize dirs outside of build dir
set(src_param_pattern "{DRMEMORY_CTEST_SRC_DIR}")
set(DR_param_pattern "{DRMEMORY_CTEST_DR_DIR}")

function (get_relative_location target outvar)
  get_target_property(tgtpath ${target} LOCATION${location_suffix})
  # For more portable testing (PR 544430) use relative dirs within parent build dir
  file(RELATIVE_PATH relpath "${CMAKE_CURRENT_BINARY_DIR}" "${tgtpath}")
  if (NOT "${relpath}" MATCHES "^\\.\\.")
    set(relpath "./${relpath}")
  endif()
  set(${outvar} "${relpath}" PARENT_SCOPE)
endfunction (get_relative_location)

if (UNIX)
  set(cmd_shell ${bin_relative}/${toolname})
else (UNIX)
  set(cmd_shell ${bin_relative}/${toolname}.exe)

  # XXX i#143: we now support /MDd but need symbols for full support.
  # Also, /MTd results in the debug heap code throwing an exception
  # when malloc.exe does free(0x1230).
  # We also avoid msvcrt*.dll differences by using static libc (/MT).
  # But for cygwin to find operators we need /MD (until we have online
  # syms)
  if (USE_DRSYMS)
    set(LIBC_FLAG "/MT")
  else (USE_DRSYMS)
    set(LIBC_FLAG "/MD")
  endif (USE_DRSYMS)
  string(TOUPPER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_UPPER)
  string(REGEX REPLACE "/MDd?" "${LIBC_FLAG}" CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}
    "${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")
  string(REGEX REPLACE "/MDd?" "${LIBC_FLAG}" CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER}
    "${CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")
  # With /MT, cs2bug.cpp gets link errors with libcpmtd.lib so we remove _DEBUG:
  string(REGEX REPLACE "/D_DEBUG" "" CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER}
    "${CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")
  string(REGEX REPLACE "/O2" "/Od" CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}
    "${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")
  # removing RTC initially just for tests/unloadtest but on app_suite it's thwarting
  # drmem's checks while not detecting many simple uninits through its own checks
  string(REGEX REPLACE "/RTC." "" CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}
    "${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")
  string(REGEX REPLACE "/RTC." "" CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER}
    "${CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}")
  if (NOT DEBUG_BUILD)
    if ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
      foreach (var C;CXX;EXE_LINKER;MODULE_LINKER;SHARED_LINKER)
        set(CMAKE_${var}_FLAGS_RELEASE ${CMAKE_${var}_FLAGS_DEBUG})
        set(CMAKE_${var}_FLAGS_RELWITHDEBINFO ${CMAKE_${var}_FLAGS_DEBUG})
      endforeach ()
    endif ()
  endif (NOT DEBUG_BUILD)
endif (UNIX)
if (DEBUG_BUILD)
  # use debug DR as well to catch asserts there
  set(dbg_args "-debug;-dr_debug")
else (DEBUG_BUILD)
  set(dbg_args "")
endif (DEBUG_BUILD)
if (WIN32)
  # we need the nudge notification msgs
  # we want core dumps on asserts, etc.
  set(default_dr_ops "-dumpcore_mask 0x87fd -stderr_mask 15 -msgbox_mask 0")
else (WIN32)
  # stderr_mask 15 is the default for debug build, and we don't want to go
  # over option buffer limit on esxi
  set(default_dr_ops "-dumpcore_mask 0")
endif (WIN32)
set(cmd_base ${cmd_shell} ${dbg_args} -dr ${DR_param_pattern}/..)
if (TOOL_DR_MEMORY)
  set(cmd_base ${cmd_base} -batch)
endif (TOOL_DR_MEMORY)
# there's no easy way to set a cmake or env var for running
# from build dir to make runtest.cmake have a relative path so we
# copy to build dir
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/runtest.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/runtest.cmake" COPYONLY)
set(cmd_script -P "./runtest.cmake")

# test_ops and drmem_ops should have words separated by ; so they'll
# be separate arguments on the cmdline, while dr_ops should be
# separated by spaces and will remain a single arg.
# be wary of trailing spaces or extra spaces: could cause problems.
# Note: For args with spaces (or multiple args) passed via drmem_ops a ;
# should be used instead of each space.  Otherwise, the whole of
# drmem_ops is passed in as a single argument, which results in
# options parsing errors in the frontend and drmem client.
# The postprocess arg is a bool that applies only for Dr. Memory:
# whether to run the front-end with -results after the app is run.
# The resbase arg support specifying a different .res and .out name
# to use.
function(newtest_nobuild_ex test exe test_ops drmem_ops dr_ops postprocess resbase
    exit_code path_append)
  if (${exe} MATCHES ".exe$")
    set(exepath ${exe})
  else ()
    get_relative_location(${exe} exepath)
  endif ()

  set(cmd ${cmd_base})
  if (NOT "${dr_ops}" STREQUAL "")
    set(cmd ${cmd} -dr_ops "${default_dr_ops} ${dr_ops}")
  else()
    set(cmd ${cmd} -dr_ops "${default_dr_ops}")
  endif ()
  # script ops last since using as hack for nudge test app
  # we request callstacks w/ file:line on separate line for matching our templates
  # we include absaddr and mod+offs for easier debugging of problems
  if (USE_DRSYMS)
    set(drmem_ops -callstack_style 0x27 -no_results_to_stderr ${drmem_ops})
  else (USE_DRSYMS)
    set(drmem_ops -callstack_style 0x27 ${drmem_ops})
  endif (USE_DRSYMS)
  if (NOT "${drmem_ops}" STREQUAL "")
    set(cmd ${cmd} ${drmem_ops})
  endif ()
  if ("${exepath}" MATCHES "run_in_bg")
    # unfortunately we have to hardcode support here: if we run drmemory.pl
    # as the command, cmake waits for its direct children to exit (including
    # postprocess.pl): instead we run run_in_bg as the primary app, which
    # makes it much easier to run drmemory.pl in the background.
    set(cmd ${exepath} ${test_ops} ${cmd})
    if (WIN32)
      # run_in_bg spawns perl.exe and perl then re-parses the args, so we need
      # extra quotes.  '' works for cygwin perl but not ActiveState: "" works
      # for both (PR 506111)
      string(REGEX REPLACE ";-dr_ops;([^;]+);" ";-dr_ops;\"\\1\";" cmd "${cmd}")
    endif (WIN32)
  else ()
    set(cmd ${cmd} -- ${exepath})
    if (NOT "${test_ops}" STREQUAL "")
      set(cmd ${cmd} ${test_ops})
    endif ()
  endif ()
  # pass intra-arg spaces via @@ and inter-arg via @
  # to get around the pain of trying to quote everything just right:
  # much simpler this way.
  string(REGEX REPLACE " " "@@" cmd "${cmd}")
  string(REGEX REPLACE ";" "@" cmd "${cmd}")
  string(REGEX REPLACE " " "@@" nudge "${cmd_base}")
  string(REGEX REPLACE ";" "@" nudge "${nudge}")
  if (TOOL_DR_HEAPSTAT)
    # XXX: this works manually but doesn't seem to get through ctest: but
    # the test is passing so not taking the time to figure it out
    set(postcmd "${cmd_base};-view_leaks;-no_callstack_exe_hide;-callstack_modname_hide '';-callstack_style 0x21;-x;${exepath};-profdir")
  else (TOOL_DR_HEAPSTAT)
    if (postprocess)
      # test -skip_results + -results (PR 575481)
      set(postcmd "${cmd_base};-results")
    else (postprocess)
      set(postcmd "")
    endif (postprocess)
  endif (TOOL_DR_HEAPSTAT)
  string(REGEX REPLACE " " "@@" postcmd "${postcmd}")
  string(REGEX REPLACE ";" "@" postcmd "${postcmd}")
  if ("${resbase}" STREQUAL "")
    set(resbase "${test}")
    string(REGEX REPLACE "_FLAKY$" "" resbase "${resbase}")
  endif ("${resbase}" STREQUAL "")
  if (X64)
    set(TOOL_BIN "bin64")
  else (X64)
    set(TOOL_BIN "bin32")
  endif (X64)
  add_test(${test} ${CMAKE_COMMAND}
    -D cmd:STRING=${cmd}
    -D TOOL_DR_HEAPSTAT:BOOL=${TOOL_DR_HEAPSTAT}
    -D outpat:STRING=${src_param_pattern}/${resbase}.out
    -D respat:STRING=${src_param_pattern}/${resbase}.res
    -D nudge:STRING=${nudge}
    -D VMKERNEL:BOOL=${VMKERNEL}
    -D USE_DRSYMS:BOOL=${USE_DRSYMS}
    -D X64:BOOL=${X64}
    -D toolbindir:STRING=${DR_param_pattern}/../${TOOL_BIN}
    -D DRMEMORY_CTEST_SRC_DIR:STRING=${CMAKE_CURRENT_SOURCE_DIR}
    -D DRMEMORY_CTEST_DR_DIR:STRING=${DynamoRIO_DIR}
    -D CMAKE_SYSTEM_VERSION:STRING=${CMAKE_SYSTEM_VERSION}
    -D exit_code:STRING=${exit_code}
    -D path_append:STRING=${path_append}
    # runtest.cmake will add the -profdir arg
    -D postcmd:STRING=${postcmd}
    ${cmd_script})
endfunction(newtest_nobuild_ex)

function(newtest_nobuild test exe test_ops drmem_ops dr_ops postprocess resbase)
  newtest_nobuild_ex(${test} ${exe} "${test_ops}" "${drmem_ops}" "${dr_ops}"
    "${postprocess}" "${resbase}" 0 "")
endfunction(newtest_nobuild)

function(newtest_ex test source test_ops drmem_ops dr_ops postprocess resbase
    exit_code)
  tobuild(${test} ${source})
  newtest_nobuild_ex(${test} ${test} "${test_ops}" "${drmem_ops}" "${dr_ops}"
    "${postprocess}" "${resbase}" ${exit_code} "")
endfunction(newtest_ex)

function(newtest test source)
  newtest_ex(${test} ${source} "" "" "" OFF "" 0)
endfunction(newtest)

function(append_test_compile_flags test cust_flags)
  get_target_property(cur_flags ${test} COMPILE_FLAGS)
  if (NOT cur_flags)
    set(cur_flags "")
  endif (NOT cur_flags)
  set_target_properties(${test} PROPERTIES COMPILE_FLAGS "${cur_flags} ${cust_flags}")
endfunction(append_test_compile_flags)

function(newtest_custbuild test source cust_flags resbase)
  newtest_ex(${test} ${source} "" "" "" OFF "${resbase}" 0)
  append_test_compile_flags(${test} ${cust_flags})
endfunction(newtest_custbuild)

function(newtest_gcc test source depender gcc_ops test_ops drmem_ops dr_ops
    postprocess resbase path_append)
  add_custom_target(target_${test} DEPENDS ${test}.exe)
  set(exepath ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${test}.exe)
  add_custom_command(OUTPUT ${test}.exe
    DEPENDS ${source} ${CMAKE_CURRENT_SOURCE_DIR}/rungcc.cmake
    COMMAND ${CMAKE_COMMAND}
    # to work around i#84 be sure to put a space after -D for 1st arg at least
    ARGS -D exename=${exepath}
       -D gcc=${GCC}
       -D source=${CMAKE_CURRENT_SOURCE_DIR}/${source}
       -D args=${gcc_ops}
       -P ${CMAKE_CURRENT_SOURCE_DIR}/rungcc.cmake
    VERBATIM # recommended: p260
    )
  newtest_nobuild_ex(${test} ${exepath} "${test_ops}" "${drmem_ops}" "${dr_ops}"
    "${postprocess}" "${resbase}" 0 "${path_append}")
  add_dependencies(${depender} target_${test})
endfunction(newtest_gcc)

if (NOT X64)
# FIXME i#111, i#217: 64-bit is only supported in pattern mode
# Leaving indentation as-is to avoid code churn
newtest(hello hello.c)
newtest(malloc malloc.c)
newtest(free free.c)
newtest(registers registers.c)
newtest(asmtest asmtest.c)
if (TOOL_DR_MEMORY)
  # Doesn't make sense for DrHeapstat
  newtest(multierror multierror.cpp)
endif (TOOL_DR_MEMORY)
newtest_custbuild(bitfield bitfield.cpp "-DBITFIELD_ASM" bitfield)
if (WIN32)
  # i#489: building /GL results in a double-xor sequence
  set(bitfieldGL_disable_asm ON)
  newtest_custbuild(bitfieldGL bitfield.cpp "/O2 /GL" bitfield)
endif (WIN32)

if (UNIX OR "${CMAKE_SYSTEM_VERSION}" STRLESS "6.2")
  set(cs2bug_res "cs2bug")
  set(cs2bug_flags "")
else ()
  # For /MTd and /MDd, or if on win8 (i#1161), we skip the
  # destructor mismatches, as they end up raising heap assertions
  # that we can't recover from.
  set(cs2bug_res "cs2bugMTd")
  set(cs2bug_flags "/DSKIP_MISMATCH_DTR")
endif ()
newtest_ex(cs2bug cs2bug.cpp "" "" "" OFF ${cs2bug_res} 0)
append_property_string(TARGET cs2bug COMPILE_FLAGS "${cs2bug_flags}")

newtest_ex(operators operators.cpp "" "" "" OFF ""
  # ignore exit code (b/c -replace_malloc calls dr_exit_process(1) in lieu of exception)
  "ANY")
newtest(float float.c)
newtest(selfmod selfmod.c)
newtest(patterns patterns.c)
newtest_ex(state state.c "" "" "" OFF "" "ANY")

if (UNIX)
  newtest(signal signal.c)
  newtest(syscalls_unix syscalls_unix.c)

  if (NOT APPLE)
    ##################################################
    # kernel module
    set(kernel_dir "/lib/modules/${CMAKE_SYSTEM_VERSION}/build" )
    if (NOT EXISTS ${kernel_dir})
      message(STATUS "Disabling kernel module build as ${kernel_dir} does not exist")
    else ()
      set(kmod_name kernel_module)
      set(kmod_bin_dir "${CMAKE_CURRENT_BINARY_DIR}/${kmod_name}")
      set(kmod_src_dir "${CMAKE_CURRENT_SOURCE_DIR}")
      set(kmod_bin "${kmod_name}.ko")
      set(kmod_src "${kmod_name}.c")
      set(kbuild_cmd ${CMAKE_MAKE_PROGRAM}
          -C ${kernel_dir}
          M=${kmod_bin_dir}
          modules)
      # Creates the dir automatically
      file(WRITE ${kmod_bin_dir}/Kbuild
          "obj-m += ${kmod_name}.o")

      add_custom_command(OUTPUT "${kmod_bin_dir}/${kmod_src}"
          COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${kmod_src_dir}/${kmod_src}"
          "${kmod_bin_dir}")
      add_custom_command(OUTPUT "${kmod_bin}"
          COMMAND ${kbuild_cmd}
          WORKING_DIRECTORY "${kmod_bin_dir}"
          DEPENDS "${kmod_bin_dir}/${kmod_src}"
          "${kmod_bin_dir}/Kbuild"
          VERBATIM)
      add_custom_target("${kmod_name}"
          DEPENDS "${kmod_bin}")
      add_dependencies(syscalls_unix "${kmod_name}")
      set(kmod_build_files "${kmod_bin_dir}/modules.order"
          "${kmod_bin_dir}/Module.symvers"
          "${kmod_bin_dir}/${kmod_name}.c"
          "${kmod_bin_dir}/${kmod_name}.o"
          "${kmod_bin_dir}/${kmod_name}.ko"
          "${kmod_bin_dir}/${kmod_name}.mod.c"
          "${kmod_bin_dir}/${kmod_name}.mod.o")
      set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES
        "${kmod_build_files}")
    endif ()
    ##################################################
  endif (NOT APPLE)

  target_link_libraries(signal m)
  if (NOT VMKERNEL AND NOT APPLE)
    # PR 468352: SYS_clone w/o CLONE_SETTLS not supported on ESXi
    newtest(clone clone.c)
  endif ()
  get_relative_location(malloc malloc_path)
  newtest_ex(execve execve.c "${malloc_path}" "" "" OFF "" 0)
  # i#1264: the name "pthreads" on an executable breaks 2.8.11 find_package(Threads)
  # so we use "pthread_test".  The compare files are still "pthreads.*".
  newtest_ex(pthread_test pthreads.c "" "" "" OFF "pthreads" 0)
  target_link_libraries(pthread_test pthread)
  if (APPLE)
    set(loaderlib_flags "-Wl,-U,_import_does_not_exist")
  else (APPLE)
    set(loaderlib_flags "")
  endif (APPLE)
  tobuild_lib(loaderlib loader.lib.c "" "${loaderlib_flags}")
  get_relative_location(loaderlib loaderlib_path)
  newtest_ex(loader loader.c "${loaderlib_path}" "" "" OFF "" 0)
  target_link_libraries(loader dl)
else (UNIX)
  newtest(winthreads winthreads.c)
endif (UNIX)

if (TOOL_DR_MEMORY)
  # We turn off blacklist b/c it results in potential errors in the child,
  # causing runtest.cmake to pick the child's log instead of parent's
  # (it does it by size)!
  newtest_ex(procterm procterm.c "" "-lib_blacklist_frames;0" "" OFF "" 0)
  if (WIN32)
    newtest_nobuild(procterm.nativeparent procterm "" "-native_parent" ""
      OFF "procterm.nativeparent")
    # these tests share a temp file so they can't run in parallel
    set_property(TEST procterm.nativeparent APPEND PROPERTY DEPENDS procterm)
  endif (WIN32)
endif (TOOL_DR_MEMORY)

if (UNIX)
  tobuild_lib(unloadlib unload.lib.c "-fno-builtin" "")
else (UNIX)
  tobuild_lib(unloadlib unload.lib.c "/DUSE_CUSTOM_MALLOC" "/nodefaultlib /noentry")
endif (UNIX)
get_relative_location(unloadlib unloadlib_path)
# We need 50 iters to hit i#545.
# We name it "unloadtest" to avoid security software issues with "unload.exe".
newtest_ex(unloadtest unload.c "${unloadlib_path};50" "" "" OFF "unload" 0)
if (UNIX)
  target_link_libraries(unloadtest dl)
endif (UNIX)
if (WIN32)
  tobuild_lib(unloadlibMTd unload.lib.c "/D_DEBUG /MTd" "")
  get_relative_location(unloadlibMTd unloadlibMTd_path)
  newtest_nobuild(unloadMTd unloadtest "${unloadlibMTd_path};2" "" "" OFF "unload")

  if (TOOL_DR_MEMORY) # XXX; not working in drheapstat: figure out why
    tobuild_lib(unloadlibMD unload.lib.c "/MD" "")
    get_relative_location(unloadlibMD unloadlibMD_path)
    # Turning off leaks to avoid libc globals like environ ptr that
    # show up as possible leaks.  XXX: may be worth investigating further.
    newtest_nobuild(unloadMD unloadtest "${unloadlibMD_path};2" "-no_count_leaks"
      "" OFF "unloadMD")

    tobuild_lib(unloadlibMDd unload.lib.c "/D_DEBUG /MDd" "")
    get_relative_location(unloadlibMDd unloadlibMDd_path)
    # Turning off leaks to avoid libc globals like environ ptr that
    # show up as possible leaks.  XXX: may be worth investigating further.
    newtest_nobuild(unloadMDd unloadtest "${unloadlibMDd_path};2" "-no_count_leaks"
      "" OFF "unloadMD")
  endif (TOOL_DR_MEMORY)
endif (WIN32)

if (TOOL_DR_MEMORY)
  # PR 525807: test malloc stacks
  newtest(varstack varstack.c)

  # PR 464804: test runtime options
  # FIXME: we should set up a suite like DR uses.  For now hand-picking
  # a few to run w/ options.
  newtest_nobuild(leaks-only malloc "" "-leaks_only" "" OFF "")
  newtest_nobuild(slowpath registers "" "-no_fastpath" "" OFF "registers")
  newtest_nobuild(slowesp registers "" "-no_esp_fastpath" "" OFF "registers")
  newtest_nobuild(addronly free "" "-light" "" OFF "")
  newtest_nobuild(addronly-reg registers "" "-no_check_uninitialized" "" OFF "")
  newtest_nobuild(reachable cs2bug "" "-show_reachable" "" OFF ${cs2bug_res})
  if (USE_DRSYMS)
    newtest_nobuild(nosymcache malloc "" "-no_use_symcache" "" OFF malloc)
  endif (USE_DRSYMS)
  newtest_nobuild(strict_bitops bitfield "" "-strict_bitops" "" OFF "bitfield.strict")
  # test this option to exercise the realloc handling code.
  # note that we can't run the realloc test b/c the races will result in unaddrs.
  newtest_nobuild(noreplace_realloc malloc "" "-no_replace_realloc" "" OFF "malloc")
  # test redzone sizes
  newtest_nobuild(redzone8 malloc "" "-redzone_size;8" "" OFF "malloc")
  newtest_nobuild(redzone1024 malloc "" "-redzone_size;1024" "" OFF "malloc")
  newtest_nobuild_ex(free.exitcode free "" "-exit_code_if_errors;42" "" OFF "free" 42 "")
  newtest_nobuild_ex(hello.exitcode hello "" "-exit_code_if_errors;4" "" OFF "hello" 0 "")
  newtest_nobuild_ex(blacklist_uninit.op registers ""
    "-check_uninit_blacklist;registers*" "" OFF "registers.blacklist" 0 "")
  newtest_nobuild_ex(blacklist_uninit.supp registers ""
    "-suppress;{DRMEMORY_CTEST_SRC_DIR}/registers.blacklist.suppress"
    "" OFF "registers.blacklist" 0 "")

  # -replace_malloc is now the default, so test wrapping
  newtest_nobuild(wrap_malloc malloc "" "-no_replace_malloc" "" OFF "malloc")
  if ("${CMAKE_SYSTEM_VERSION}" STRLESS "6.2")
    # this test crashes on win8 so we only run it on older Windows
    if (cs2bug_flags STREQUAL "")
      newtest_nobuild(wrap_cs2bug cs2bug "" "-no_replace_malloc" "" OFF "cs2bug.wrap")
    else ()
      # -no_replace_malloc raises unrecoverable heap errors (i#1161)
      newtest_ex(wrap_cs2bug cs2bug.cpp "" "-no_replace_malloc" "" OFF ${cs2bug_res} 0)
    endif ()
  endif ()
  newtest_nobuild_ex(wrap_operators operators "" "-no_replace_malloc"
    "" OFF "operators" 0 "")

  # shared by all suppress tests
  tobuild(suppress suppress.c)
  if (APPLE)
    append_test_compile_flags(suppress "-Wno-uninitialized")
  endif ()
  if (WIN32)
    tobuild_lib(suppress-mod-foo suppress-mod-foo.c "" "/nodefaultlib /noentry")
    tobuild_lib(suppress-mod-bar suppress-mod-bar.c "" "/nodefaultlib /noentry")
  else ()
    tobuild_lib(suppress-mod-foo suppress-mod-foo.c "" "")
    tobuild_lib(suppress-mod-bar suppress-mod-bar.c "" "")
    target_link_libraries(suppress dl)  # Needed for dlopen.
  endif ()

  # test suppress wildcards
  if (UNIX)
    if (VMKERNEL)
      set(supp_fileA "{DRMEMORY_CTEST_SRC_DIR}/suppress.vmk.suppress")
      set(supp_fileB "{DRMEMORY_CTEST_SRC_DIR}/suppress.vmk.suppress")
    else (VMKERNEL)
      set(supp_fileA "{DRMEMORY_CTEST_SRC_DIR}/suppress.lin.suppress")
      set(supp_fileB "{DRMEMORY_CTEST_SRC_DIR}/suppressB.lin.suppress")
    endif (VMKERNEL)
  else (UNIX)
    set(supp_fileA "{DRMEMORY_CTEST_SRC_DIR}/suppress.win.suppress")
    set(supp_fileB "{DRMEMORY_CTEST_SRC_DIR}/suppressB.win.suppress")
  endif (UNIX)
  # test multiple supp files (i#574)
  if (USE_DRSYMS)
    newtest_nobuild(suppress suppress ""
      "-suppress;${supp_fileA};-suppress;${supp_fileB};-no_callstack_exe_hide;-callstack_modname_hide;;"
      "" OFF "")
  else (USE_DRSYMS)
    newtest_nobuild(suppress suppress ""
      "-suppress;${supp_fileA};-suppress;${supp_fileB}" "" OFF "")
  endif (USE_DRSYMS)

  # i#80: test suppression file generation and use via multiple runs
  # since we need the name of the suppress file, runtest.cmake must do
  # the second run.  it looks for "suppress" with no "-suppress" option,
  # rather than taking explicit params, and for the 2nd run uses the
  # suppress output files
  if (USE_DRSYMS)
    newtest_nobuild(suppress-genoffs suppress ""
      "-no_gen_suppress_syms;-no_callstack_exe_hide;-callstack_modname_hide;;" "" OFF "")
    newtest_nobuild(suppress-gensyms suppress ""
      "-no_gen_suppress_offs;-no_callstack_exe_hide;-callstack_modname_hide;;" "" OFF "")
  else (USE_DRSYMS)
    newtest_nobuild(suppress-genoffs suppress "" "-no_gen_suppress_syms" "" OFF "")
    newtest_nobuild(suppress-gensyms suppress "" "-no_gen_suppress_offs" "" OFF "")
  endif (USE_DRSYMS)

  set(nudge_test_args "")

  # FIXME i#446: no support yet for post-process w/ drsyms
  if (UNIX AND NOT USE_DRSYMS)
    # test -skip_results + -results (PR 575481)
    newtest_nobuild(skip-results malloc "" "-skip_results" "" ON "")
  endif ()

  # For -perturb_only we do not have a .res file so that runtest.cmake
  # won't wait for a message showing that results are ready
  # FIXME i#715: perturb is flaky on the bots.
  if (UNIX)
    newtest_nobuild(perturb_FLAKY pthread_test "" "-perturb_only" "" OFF "")
  else (UNIX)
    newtest_nobuild(perturb_FLAKY winthreads  "" "-perturb_only" "" OFF "")
  endif (UNIX)

  if (WIN32)
    # test i#1197.  With -replace_malloc default, we need to point at wincrt.replace.
    newtest_ex(wincrt wincrt.cpp "" "" "" OFF "wincrt.replace" 0)
    # i#1532: we only report C vs Win mismatches for /MD*
    append_test_compile_flags(wincrt "/MD")
    newtest_nobuild(wrap_wincrt wincrt "" "-no_replace_malloc" "" OFF "wincrt")

    # FIXME: Re-enable when it doesn't break the build.
    #newtest(rtl_memory_zones rtl_memory_zones.c)
    #target_link_libraries(rtl_memory_zones ${ntimp_lib})
    #if (NOT USER_SPECIFIED_DynamoRIO_DIR AND "${CMAKE_GENERATOR}" MATCHES "Visual Studio")
    #  # for parallel build correctness we need a target dependence
    #  add_dependencies(rtl_memory_zones ntimp_tgt)
    #endif ()

    if (USE_DRSYMS) # cygwin build can't see static malloc routines
      tobuild(wincrtdbg wincrt.cpp)
      append_test_compile_flags(wincrtdbg "/MTd")
      newtest_nobuild(wincrtdbg wincrtdbg "" "-redzone_size;64" "" OFF "")
      newtest_nobuild(wrap_wincrtdbg wincrtdbg "" "-no_replace_malloc" "" OFF "wincrtdbg")

      newtest_custbuild(mallocMTd malloc.c "/MTd" malloc)
      newtest_custbuild(mallocMD malloc.c "/MD" malloc)

      # C++ tests with other libc configs
      newtest_custbuild(cs2bugMTd cs2bug.cpp "/MTd /DSKIP_MISMATCH_DTR" cs2bugMTd)
      newtest_custbuild(cs2bugMTdZI cs2bug.cpp "/ZI /MTd /DSKIP_MISMATCH_DTR" cs2bugMTd)
      newtest_custbuild(cs2bugMD cs2bug.cpp "/MD ${cs2bug_flags}" ${cs2bug_res})
      newtest_custbuild(cs2bugMDd cs2bug.cpp "/MDd /DSKIP_MISMATCH_DTR" cs2bugMTd)
      newtest_nobuild(wrap_cs2bugMTd cs2bugMTd "" "-no_replace_malloc" "" OFF "cs2bugMTd")

      # Test i#607 part D
      tobuild(operatorsMDd operators.cpp)
      append_test_compile_flags(operatorsMDd "/MDd")
      newtest_nobuild_ex(operatorsMDd operatorsMDd "" "" "" OFF operators
        # ignore exit code (b/c -replace_malloc calls dr_exit_process(1))
        "ANY" "")
      newtest_nobuild_ex(wrap_operatorsMDd operatorsMDd ""
          "-no_replace_malloc" "" OFF operators 0 "")
    endif (USE_DRSYMS)

    if (GCC)
      # We have issues w/ static libstdc++ FPO so we ask for better callstacks (i#783)
      # With i#805, -no_callstack_use_top_fp is set automatically
      newtest_gcc(cs2bugMinGW cs2bug.cpp cs2bug "-static-libgcc\;-static-libstdc++"
        "" "" "" "" cs2bug "")
      if (mingwlib)
        newtest_gcc(cs2bugMinGW_shared cs2bug.cpp cs2bug "" "" "" "" "" cs2bug
          ${mingw_path})
      endif ()
    endif (GCC)

    # use -verify_sysnums to verify syscall numbers are correct
    newtest_ex(gdi gdi.cpp ""
      "-suppress;{DRMEMORY_CTEST_SRC_DIR}/gdi.suppress;-check_gdi_multithread;-verify_sysnums" ""
      OFF "" 0)
    newtest(syscalls_win syscalls_win.cpp)
    # the handle leaks also cause memory leak, so we use light to avoid leak report.
    newtest_ex(handle handle.cpp ""
      "-light;-check_handle_leaks;-verify_sysnums"
      "" OFF "" 0)
    newtest_nobuild(handle_only handle ""
      "-handle_leaks_only" "" OFF "handle_only")
    # XXX i#1320: have runtest.cmake check potential_errors.txt too
    newtest_ex(blacklist blacklist.cpp "" "-lib_blacklist_frames;1" "" OFF "" 0)
  endif (WIN32)

  newtest(realloc realloc.c)
  if (UNIX)
    target_link_libraries(realloc pthread)
  endif (UNIX)

  newtest(annotations annotations.c)

  if (UNIX)
    newtest(memalign memalign.c)
  endif (UNIX)

  # persistent cache tests: currently only light mode is supported
  # XXX: would be nice to ensure pcaches are actually generated and used,
  # but how?  annotations would be the cleanest way but that requires
  # a bunch of annotations that are only used for tests.
  # XXX: we use pattern mode as the default light mode, which does not work with
  # persistent cache (i#1184), so we use "-no_check_uninitialized -no_count_leaks"
  # instead.
  newtest_ex(pcache free.c "" "-no_check_uninitialized;-no_count_leaks;-persist_code"
    # do not load any stale pcaches from prior runs, in first run
    "-no_use_persisted -no_coarse_disk_merge -no_coarse_lone_merge" OFF "addronly" 0)
  if (WIN32)
    # we make a separate executable to avoid ASLR
    append_link_flags(pcache "/dynamicbase:no")
  endif ()
  newtest_nobuild(pcache-use pcache "" "-no_check_uninitialized;-no_count_leaks;-persist_code" "" OFF "addronly")
  # when running tests in parallel, have to generate pcaches first
  set_property(TEST pcache-use APPEND PROPERTY DEPENDS pcache)
  newtest_ex(track_origins track_origins.c "" "-light;-track_origins_unaddr" ""
    OFF "" 0)
  # pattern mode testing.
  newtest_nobuild(free.pattern free "" "-unaddr_only" "" OFF "addronly")
  newtest_nobuild(malloc.pattern malloc "" "-unaddr_only" "" OFF "")
  newtest_nobuild(registers.pattern registers "" "-unaddr_only" "" OFF "registers.pattern")
  newtest_nobuild(track_origins.pattern track_origins ""
    "-unaddr_only;-track_origins_unaddr" "" OFF "track_origins")
  newtest_nobuild_ex(state.pattern state "" "-unaddr_only" "" OFF "" "ANY" "")
else (TOOL_DR_MEMORY)
  newtest_ex(stale stale.c "" "-staleness;-stale_granularity;100" "" OFF "" 0)

  newtest_nobuild(time-allocs malloc "" "-time_allocs" "" OFF "")
  newtest_nobuild(time-bytes malloc "" "-time_bytes" "" OFF "")
  newtest_nobuild(time-instrs malloc "" "-time_instrs" "" OFF "")
  newtest_nobuild(dump malloc "" "-dump" "" OFF "")

  set(nudge_test_args "")
endif (TOOL_DR_MEMORY)

# nudge test: runs infloop in background and runtest.cmake nudges it
tobuild(infloop infloop.c)
get_relative_location(infloop infloop_path)
# we have special support to put run_in_bg and its args first, so we put
# the test to run as a final drmem arg
newtest_nobuild(nudge run_in_bg_tgt
  "-out;./nudge-out"
  "${nudge_test_args}--;${infloop_path}" "" OFF "")
if (TOOL_DR_MEMORY AND WIN32)
  # See above for why passing -lib_blacklist_frames 0.
  set(nudge_handle_test_args "-leaks_only;-no_count_leaks;-check_handle_leaks;")
  newtest_nobuild(nudge_handle run_in_bg_tgt
    "-out;./nudge-handle-out"
    "${nudge_handle_test_args}--;${infloop_path}" "" OFF "")
endif (TOOL_DR_MEMORY AND WIN32)

newtest(leakcycle leakcycle.cpp)
if (WIN32)
  # With -replace_malloc we have trouble allocating a low enough heap for the wide
  # char test, so we stick to wrapping for this test.
  # Wrapping doesn't work on win8 so we disable the test there.
  if ("${CMAKE_SYSTEM_VERSION}" STRLESS "6.2")
    newtest_ex(leak_string leak_string.cpp "" "-no_replace_malloc" "" OFF leak_string 0)
  endif ()

  # Ensure we don't spit out false positives when there are no symbols for the app
  newtest_custbuild(nosyms nosyms.cpp "/MD" "nosyms")
  # XXX: since cmake applies CMAKE_C_FLAGS_DEBUG and CMAKE_EXE_LINKER_FLAGS_DEBUG
  # only at the end of the file to all targets, and there's no /Zi- or /debug:no,
  # is there any better way to disable symbols than removing the pdb?
  append_property_string(TARGET nosyms LINK_FLAGS "/incremental:no")
  get_target_property(nosyms_pdb nosyms LOCATION${location_suffix})
  string(REGEX REPLACE "exe$" "pdb" nosyms_pdb ${nosyms_pdb})
  add_custom_command(TARGET nosyms POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E remove ${nosyms_pdb} VERBATIM)

endif (WIN32)

if (TOOL_DR_MEMORY)
  # We call this "whitelist_app" to more easily pattern-match vs its lib.
  # XXX i#1320: have runtest.cmake check potential_errors.txt too.
  newtest_ex(whitelist_app whitelist.cpp ""
    # Exclude the lib's errors
    "-lib_whitelist;*whitelist_app*;-lib_whitelist_frames;1"
    "" OFF "whitelist" 0)
  tobuild_lib(whitelist_lib whitelist_lib.cpp "" "")
  target_link_libraries(whitelist_app whitelist_lib)
  newtest_nobuild(whitelist_justlib whitelist_app ""
    # Exclude the app's errors
    "-lib_whitelist;*whitelist_lib*;-lib_whitelist_frames;1"
    "" OFF "whitelist_justlib")
  newtest_nobuild(whitelist_src whitelist_app ""
    # Test -src_whitelist
    "-src_whitelist;*whitelist.cpp;-src_whitelist_frames;1"
    "" OFF "whitelist")
  newtest_nobuild(whitelist_srclib whitelist_app ""
    # Test -src_whitelist in combination with -lib_whitelist.
    # Not a great test as the lib selects both errors anyway.
    "-lib_whitelist;*whitelist*;-lib_whitelist_frames;1;-src_whitelist;*whitelist.cpp;-src_whitelist_frames;1"
    "" OFF "whitelist")
endif (TOOL_DR_MEMORY)

# XXX i#1660: gtest is not building with clang 6.0
if (NOT APPLE)
  add_subdirectory(app_suite)
  if (TOOL_DR_HEAPSTAT)
    # i#1358: Dr. Heapstat currently can't handle code in the heap
    set(app_suite_ops "--gtest_filter=-MallocTests.Executable")
  else ()
    set(app_suite_ops "")
  endif ()
  newtest_nobuild(app_suite app_suite_tests "${app_suite_ops}"
    "-suppress;{DRMEMORY_CTEST_SRC_DIR}/app_suite/default-suppressions.txt"
    # i#1309: turn off some DR debug checking to speed up the test, as it times out
    # on Dr. Heapstat w/ online symbolization.
    "-checklevel 1" OFF "")
  # Ensure ctest itself doesn't time out app_suite (it can take >60s on the bots):
  set_tests_properties(app_suite PROPERTIES TIMEOUT 120)
  if (TOOL_DR_MEMORY)
    newtest_nobuild(app_suite.pattern app_suite_tests ""
      "-unaddr_only;-suppress;{DRMEMORY_CTEST_SRC_DIR}/app_suite/default-suppressions.txt"
      "" OFF "")
  endif ()
endif ()

# framework subdir is added at top level b/c wants DR cflags

else (NOT X64)
  # pattern mode testing.
  newtest_ex(free.pattern free.c "" "-unaddr_only" "" OFF "addronly" 0)
  newtest_ex(malloc.pattern malloc.c "" "-unaddr_only" "" OFF "" 0)
  newtest_ex(registers.pattern registers.c "" "-unaddr_only" "" OFF "registers.pattern" 0)
  newtest_ex(track_origins.pattern track_origins.c "" "-unaddr_only;-track_origins_unaddr"
    "" OFF "track_origins" 0)
  if (WIN32)
    newtest_ex(handle handle.cpp ""
      "-unaddr_only;-check_gdi;-check_handle_leaks;-lib_blacklist_frames;0" ""
      OFF "" 0)
    newtest_ex(procterm procterm.c "" "-unaddr_only;-lib_blacklist_frames;0" "" OFF
      "procterm.addronly" 0)
  endif (WIN32)

  # shadow light testing
  # XXX i#111: we'll eliminate this duplication once we have full mode working --
  # and when we do, be sure to remove the runtest.cmake auto-ignore of # uninits.
  newtest(hello hello.c)
  newtest(free free.c)
  newtest_custbuild(bitfield bitfield.cpp "-DBITFIELD_ASM" bitfield)
  newtest(patterns patterns.c)
  newtest_nobuild_ex(free.exitcode free "" "-exit_code_if_errors;42" "" OFF "free" 42 "")
  newtest_nobuild_ex(free.exitcode free "" "-exit_code_if_errors;42" "" OFF "free" 42 "")
  newtest_ex(track_origins track_origins.c "" "-light;-track_origins_unaddr" ""
    OFF "" 0)
endif (NOT X64)

if (TOOL_DR_MEMORY)
  if (UNIX)
    set(app_extension "")
    if (X64)
      set(fuzz_buffer_cpp_symbol "_ZN13BufferPrinter8repeatmeEPjm")
    else (X64)
      set(fuzz_buffer_cpp_symbol "_ZN13BufferPrinter8repeatmeEPjj")
    endif (X64)
    set(enable_mangled_names "")
  else (UNIX)
    set(app_extension ".exe")
    if (X64)
      set(fuzz_buffer_cpp_symbol "?repeatme-BufferPrinter--QEAAXPEAI_K-Z") # '-' for '@'
    else (X64)
      set(fuzz_buffer_cpp_symbol "?repeatme-BufferPrinter--QAEXPAII-Z") # '-' for '@'
    endif (X64)
    set(enable_mangled_names ";-fuzz_mangled_names")
  endif (UNIX)

  set(fuzz_buffer_ops "-fuzz_target;<main>!repeatme|2|0|1|10")
  newtest_ex(fuzz_buffer fuzz_buffer.c "" "${fuzz_buffer_ops}" "" OFF "" 0)
  set(fuzz_buffer_ops "-fuzz_target;fuzz_buffer${app_extension}!repeatme|2|0|1|10")
  newtest_nobuild_ex(fuzz_buffer.module_name fuzz_buffer
    "" "${fuzz_buffer_ops}" "" OFF "" 0 "")
  set(fuzz_buffer_ops
    "-fuzz_target;fuzz_buffer.cpp${app_extension}!${fuzz_buffer_cpp_symbol}|3|1|2|10${enable_mangled_names}")
  newtest_ex(fuzz_buffer.cpp fuzz_buffer.cpp "" "${fuzz_buffer_ops}" "" OFF "" 0)
  if (NOT UNIX)
    # demangled symbols can't be found on unix (elf table only has mangled)
    set(fuzz_buffer_ops
      "-fuzz_target;fuzz_buffer.cpp${app_extension}!BufferPrinter::repeatme|3|1|2|10")
    newtest_nobuild_ex(fuzz_buffer.cpp.mangled fuzz_buffer.cpp
      "" "${fuzz_buffer_ops}" "" OFF "" 0 "")

    append_property_string(TARGET fuzz_buffer COMPILE_FLAGS "/Ob0")
    append_property_string(TARGET fuzz_buffer.cpp COMPILE_FLAGS "/Ob0") # disable opt
  endif (NOT UNIX)
  # XXX i#1734: need a test for a fuzz target loaded after target registration
endif (TOOL_DR_MEMORY)

if (APPLE)
  # Enable a few tests for the test suite without perturbing
  # all the code above.
  # XXX: can we get this to automatically happen for a local "ctest" w/o
  # the user having to pass "-L OSX"?
  set_tests_properties(hello free malloc asmtest bitfield addronly
    float annotations free.pattern PROPERTIES LABELS OSX)
endif ()
