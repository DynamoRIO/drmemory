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

cmake_minimum_required(VERSION 2.6)

include(${PROJECT_SOURCE_DIR}/make/policies.cmake NO_POLICY_SCOPE)

# Passing long to runsuite auto-enables release build tests.
# It also sets this option, which we can use for test configurations
# that we do not want to fill pre-commit time with.
option(TEST_LONG "run long set of tests")

set(DEFAULT_TIMEOUT 120)

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

option(BUILD_MINGW "Build test with MinGW if present" ON)
if (WIN32 AND BUILD_MINGW)
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
else ()
  set(GCC OFF)
  message(STATUS "Disabling MinGW tests as requested")
endif ()

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
    if (HAVE_FVISIBILITY_INTERNAL OR HAVE_FVISIBILITY_HIDDEN)
      set(defs ${defs} USE_VISIBILITY_ATTRIBUTES)
    endif ()
  endif (UNIX)
  if (VMKERNEL)
    set(defs ${defs} VMX86_SERVER)
  endif (VMKERNEL)
  # DrMem itself gets ARM from dr_api.h but tests need it on their own:
  if (ARM)
    set(defs ${defs} ARM)
  endif ()
  if (X86)
    set(defs ${defs} X86)
  endif ()
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
    if ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
      add_dependencies(${name} ${gen_asm_tgt})
    endif ()
  endif ()
  copy_target_to_device(${name})
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
  copy_target_to_device(${name})
endfunction(tobuild_lib)

# tools for nudge tests
# to avoid conflict w/ DR's run_in_bg target we use a different target name
tobuild(run_app_in_bg run_in_bg.c)
if (WIN32)
  target_link_libraries(run_app_in_bg ${ntimp_lib})
  if (NOT USER_SPECIFIED_DynamoRIO_DIR AND "${CMAKE_GENERATOR}" MATCHES "Visual Studio")
    # for parallel build correctness we need a target dependence
    add_dependencies(run_app_in_bg ntdll_imports)
  endif ()
endif (WIN32)

if (X64)
  set(BIN_ARCH "bin64")
else ()
  set(BIN_ARCH "bin")
endif ()
# FIXME PR 544430: use relative dirs within parent build dir for more portable testing
set(bin_path "${PROJECT_BINARY_DIR}/${BUILD_BIN_PREFIX}/${BIN_ARCH}")
# parameterize dirs outside of build dir
set(src_param_pattern "{DRMEMORY_CTEST_SRC_DIR}")
set(DR_param_pattern "{DRMEMORY_CTEST_DR_DIR}")

get_target_path_for_execution(cmd_shell ${toolname})
if (ANDROID)
  string(REPLACE "${BIN_ARCH}/${frontend_name}" "${BIN_ARCH}/${toolname}"
    cmd_shell ${cmd_shell})
endif ()
if (NOT UNIX)
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
endif (NOT UNIX)
if (DEBUG_BUILD)
  # use debug DR as well to catch asserts there
  set(dbg_args "-debug;-dr_debug")
else (DEBUG_BUILD)
  set(dbg_args "")
endif (DEBUG_BUILD)
if (WIN32)
  # we need the nudge notification msgs
  # we want core dumps on asserts, etc.
  set(default_dr_ops -dumpcore_mask 0x87fd -stderr_mask 15 -msgbox_mask 0)
else (WIN32)
  # stderr_mask 15 is the default for debug build, and we don't want to go
  # over option buffer limit on esxi
  set(default_dr_ops -dumpcore_mask 0)
endif (WIN32)
set(cmd_base ${cmd_shell} ${dbg_args} -dr ${DR_param_pattern}/..)
prefix_cmd_if_necessary(cmd_base OFF ${cmd_base})
if (TOOL_DR_MEMORY)
  set(cmd_base ${cmd_base} -batch)
endif (TOOL_DR_MEMORY)
# there's no easy way to set a cmake or env var for running
# from build dir to make runtest.cmake have a relative path so we
# copy to build dir
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/runtest.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/runtest.cmake" COPYONLY)
set(cmd_script -P "${PROJECT_BINARY_DIR}/tests/runtest.cmake")

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
function(newtest_nobuild_allparams test exe test_ops drmem_ops dr_ops postprocess resbase
    exit_code path_append timeout)
  if (${exe} MATCHES ".exe$")
    set(exepath ${exe})
  else ()
    get_target_path_for_execution(exepath ${exe})
  endif ()

  set(cmd ${cmd_base})
  # We avoid requiring spaces and quoting as it's non-trivial to get through
  # adb shell to Android.
  foreach (drop ${default_dr_ops} ${dr_ops})
    set(cmd ${cmd} -dr_ops ${drop})
  endforeach ()
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
  if ("${exepath}" MATCHES "run_app_in_bg")
    # unfortunately we have to hardcode support here: if we run drmemory.pl
    # as the command, cmake waits for its direct children to exit (including
    # postprocess.pl): instead we run run_app_in_bg as the primary app, which
    # makes it much easier to run drmemory.pl in the background.
    set(cmd ${exepath} ${test_ops} ${cmd})
    if (WIN32)
      # run_app_in_bg spawns perl.exe and perl then re-parses the args, so we need
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
  convert_local_path_to_device_path(dr_device_path ${DynamoRIO_DIR})
  add_test(${test} ${CMAKE_COMMAND}
    -D cmd:STRING=${cmd}
    -D TOOL_DR_HEAPSTAT:BOOL=${TOOL_DR_HEAPSTAT}
    -D outpat:STRING=${src_param_pattern}/${resbase}.out
    -D respat:STRING=${src_param_pattern}/${resbase}.res
    -D nudge:STRING=${nudge}
    -D VMKERNEL:BOOL=${VMKERNEL}
    -D USE_DRSYMS:BOOL=${USE_DRSYMS}
    -D X64:BOOL=${X64}
    -D ARM:BOOL=${ARM}
    -D ANDROID:BOOL=${ANDROID}
    -D ADB:FILEPATH=${ADB}
    -D toolbindir:STRING=${DR_param_pattern}/../${TOOL_BIN}
    -D DRMEMORY_CTEST_SRC_DIR:STRING=${CMAKE_CURRENT_SOURCE_DIR}
    -D DRMEMORY_CTEST_DR_DIR:STRING=${dr_device_path}
    -D CMAKE_SYSTEM_VERSION:STRING=${CMAKE_SYSTEM_VERSION}
    -D exit_code:STRING=${exit_code}
    -D path_append:STRING=${path_append}
    -D timeout:STRING=${timeout}
    # runtest.cmake will add the -profdir arg
    -D postcmd:STRING=${postcmd}
    ${cmd_script})
  set_tests_properties(${test} PROPERTIES TIMEOUT ${timeout})
endfunction(newtest_nobuild_allparams)

function(newtest_nobuild_ex test exe test_ops drmem_ops dr_ops postprocess resbase
    exit_code path_append)
  newtest_nobuild_allparams(${test} ${exe} "${test_ops}" "${drmem_ops}" "${dr_ops}"
    "${postprocess}" "${resbase}" ${exit_code} "${path_append}" ${DEFAULT_TIMEOUT})
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

# i#1726: ARM is only supported in pattern mode.
if (NOT ARM)
# Leaving indentation as-is to avoid code churn
newtest(hello hello.c)
newtest(malloc malloc.c)
newtest(leak_indirect leak_indirect.c)
newtest(free free.c)
if (ARM)
  newtest_ex(free_arm free.c "" "" "" OFF "free" 0)
  append_test_compile_flags(free_arm "-marm")
endif (ARM)
newtest(badjmp badjmp.c)
if (NOT ARM) # XXX i#1726: port to ARM
  newtest(registers registers.c)
endif ()
if (ARM)
  newtest(asmtest asmtest_arm.c)
else ()
  newtest(asmtest asmtest_x86.c)
endif ()
if (TOOL_DR_MEMORY)
  # Doesn't make sense for DrHeapstat
  newtest(multierror multierror.cpp)
endif (TOOL_DR_MEMORY)
if (NOT ARM) # XXX i#1726: port to ARM
  newtest_custbuild(bitfield bitfield.cpp "-DBITFIELD_ASM" bitfield)
  if (WIN32)
    # i#489: building /GL results in a double-xor sequence
    set(bitfieldGL_disable_asm ON)
    newtest_custbuild(bitfieldGL bitfield.cpp "/O2 /GL" bitfield)
  endif (WIN32)
endif ()

if (UNIX OR "${CMAKE_SYSTEM_VERSION}" STRLESS "6.2")
  set(cs2bug_res "cs2bug")
  # Avoid warnings on our deliberate errors
  set(cs2bug_flags "")
  if (UNIX)
    CHECK_C_COMPILER_FLAG("-Wno-mismatched-new-delete" mismatch_flag_avail)
    if (mismatch_flag_avail)
      set(cs2bug_flags "-Wno-mismatched-new-delete")
    endif ()
  endif ()
else ()
  # For /MTd and /MDd, or if on win8 (i#1161), we skip the
  # destructor mismatches, as they end up raising heap assertions
  # that we can't recover from.
  set(cs2bug_res "cs2bugMTd")
  set(cs2bug_flags "/DSKIP_MISMATCH_DTR")
endif ()
newtest_ex(cs2bug cs2bug.cpp "" "" ""  OFF ${cs2bug_res} 0)
append_property_string(TARGET cs2bug COMPILE_FLAGS "${cs2bug_flags}")

# On Linux this test is very slow trying to hit OOM and then leak checking.
# We tweak the options to try and speed it up and not timeout on Travis.
if (UNIX)
  set(operators_dr_ops "-checklevel 0 -no_enable_reset -vm_size 64M")
  set(operators_drm_ops "-no_count_leaks")
else ()
  set(operators_dr_ops "")
  set(operators_drm_ops "")
endif()
newtest_ex(operators operators.cpp "" "${operators_drm_ops}" "${operators_dr_ops}" OFF ""
  # ignore exit code (b/c -replace_malloc calls dr_exit_process(1) in lieu of exception)
  "ANY")
newtest(float float.c)
newtest(selfmod selfmod.c)
newtest(patterns patterns.c)
newtest_ex(state state.c "" "" "" OFF "" "ANY")

if (UNIX)
  newtest(signal signal.c)
  if (NOT X64) # FIXME i#111: failing on Travis
    newtest(syscalls_unix syscalls_unix.c)
  endif ()

  if (NOT APPLE
      AND "${CMAKE_GENERATOR}" MATCHES "Unix Makefiles") # i#2019: fails w/ Ninja
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
      if (NOT X64) # FIXME i#111: failing on Travis
        add_dependencies(syscalls_unix "${kmod_name}")
      endif ()
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
  endif ()

  target_link_libraries(signal m)
  if (NOT VMKERNEL AND NOT APPLE)
    # PR 468352: SYS_clone w/o CLONE_SETTLS not supported on ESXi
    newtest(clone clone.c)
  endif ()
  get_target_path_for_execution(malloc_path malloc)
  newtest_ex(execve execve.c "${malloc_path}" "" "" OFF "" 0)
  # i#1264: the name "pthreads" on an executable breaks 2.8.11 find_package(Threads)
  # so we use "pthread_test".  The compare files are still "pthreads.*".
  newtest_ex(pthread_test pthreads.c "" "" "" OFF "pthreads" 0)
  append_test_compile_flags(pthread_test "-Wno-uninitialized")
  if (NOT ANDROID) # pthread is built in to Bionic
    target_link_libraries(pthread_test pthread)
  endif ()
  if (APPLE)
    set(loaderlib_flags "-Wl,-U,_import_does_not_exist")
  else (APPLE)
    set(loaderlib_flags "")
  endif (APPLE)
  tobuild_lib(loaderlib loader.lib.c "" "${loaderlib_flags}")
  get_target_path_for_execution(loaderlib_path loaderlib)
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
get_target_path_for_execution(unloadlib_path unloadlib)
# We need 50 iters to hit i#545.
# We name it "unloadtest" to avoid security software issues with "unload.exe".
newtest_ex(unloadtest unload.c "${unloadlib_path};50" "" "" OFF "unload" 0)
if (UNIX)
  target_link_libraries(unloadtest dl)
endif (UNIX)
if (WIN32)
  tobuild_lib(unloadlibMTd unload.lib.c "/D_DEBUG /MTd" "")
  get_target_path_for_execution(unloadlibMTd_path unloadlibMTd)
  newtest_nobuild(unloadMTd unloadtest "${unloadlibMTd_path};2" "" "" OFF "unload")

  if (TOOL_DR_MEMORY) # XXX; not working in drheapstat: figure out why
    tobuild_lib(unloadlibMD unload.lib.c "/MD" "")
    get_target_path_for_execution(unloadlibMD_path unloadlibMD)
    # Turning off leaks to avoid libc globals like environ ptr that
    # show up as possible leaks.  XXX: may be worth investigating further.
    newtest_nobuild(unloadMD unloadtest "${unloadlibMD_path};2" "-no_count_leaks"
      "" OFF "unloadMD")

    tobuild_lib(unloadlibMDd unload.lib.c "/D_DEBUG /MDd" "")
    get_target_path_for_execution(unloadlibMDd_path unloadlibMDd)
    # Turning off leaks to avoid libc globals like environ ptr that
    # show up as possible leaks.  XXX: may be worth investigating further.
    newtest_nobuild(unloadMDd unloadtest "${unloadlibMDd_path};2" "-no_count_leaks"
      "" OFF "unloadMD")
  endif (TOOL_DR_MEMORY)
endif (WIN32)

# The docs claim plain "-Wno-alloc-size-larger-than" should disable but it doesn't.
CHECK_C_COMPILER_FLAG("-Wno-alloc-size-larger-than=4294967295"
  HAVE_ALLOC_SIZE_WARNING_INTERNAL)

if (TOOL_DR_MEMORY)
  if (NOT ARM) # XXX i#1726: port to ARM
    # PR 525807: test malloc stacks
    newtest(varstack varstack.c)
  endif ()

  # PR 464804: test runtime options
  # FIXME: we should set up a suite like DR uses.  For now hand-picking
  # a few to run w/ options.
  if (NOT X64) # XXX i#111: -esp_fastpath not supported yet
    newtest_nobuild(leaks-only malloc "" "-leaks_only" "" OFF "")
  endif ()
  if (NOT ARM) # XXX i#1726: port to ARM
    if (NOT X64) # FIXME i#111: failing on Travis
      newtest_nobuild(slowpath registers "" "-no_fastpath" "" OFF "registers")
    endif ()
    newtest_nobuild(slowesp registers "" "-no_esp_fastpath" "" OFF "registers")
    newtest_nobuild(addronly-reg registers "" "-no_check_uninitialized" "" OFF "")
  endif ()
  newtest_nobuild(addronly free "" "-light" "" OFF "")
  newtest_nobuild(reachable cs2bug "" "-show_reachable" "" OFF ${cs2bug_res})
  newtest_nobuild(malloc_callstacks cs2bug "" "-light;-malloc_callstacks" ""
    OFF "cs2bug.light")
  if (USE_DRSYMS)
    if (NOT X64) # FIXME i#111: failing on Travis
      newtest_nobuild(nosymcache malloc "" "-no_use_symcache" "" OFF malloc)
    endif ()
  endif (USE_DRSYMS)
  if (NOT ARM) # XXX i#1726: port to ARM
    newtest_nobuild(strict_bitops bitfield "" "-strict_bitops" "" OFF "bitfield.strict")
  endif ()
  # test this option to exercise the realloc handling code.
  # note that we can't run the realloc test b/c the races will result in unaddrs.
  newtest_nobuild(noreplace_realloc malloc "" "-no_replace_realloc" "" OFF "malloc")
  # test redzone sizes
  if (X64)
    newtest_nobuild(redzone16 malloc "" "-redzone_size;16" "" OFF "malloc")
  else ()
    newtest_nobuild(redzone8 malloc "" "-redzone_size;8" "" OFF "malloc")
  endif ()
  newtest_nobuild(redzone1024 malloc "" "-redzone_size;1024" "" OFF "malloc")
  newtest_nobuild_ex(free.exitcode free "" "-exit_code_if_errors;42" "" OFF "free" 42 "")
  newtest_nobuild_ex(hello.exitcode hello "" "-exit_code_if_errors;4" "" OFF "hello" 0 "")
  if (NOT ARM) # XXX i#1726: port to ARM
    newtest_nobuild_ex(blacklist_uninit.op registers ""
      "-check_uninit_blacklist;registers*" "" OFF "registers.blacklist" 0 "")
    newtest_nobuild_ex(blacklist_uninit.supp registers ""
      "-suppress;{DRMEMORY_CTEST_SRC_DIR}/registers.blacklist.suppress"
      "" OFF "registers.blacklist" 0 "")
  endif ()
  # XXX: ideally we'd run drcov2lcov and test the output too.  For now this
  # is just a test of the coverage data line output.
  newtest_nobuild(coverage free "" "-coverage" "" OFF "")

  # -replace_malloc is now the default, so test wrapping
  if (WIN32) # i#1781: fails on many Linux machines so disabling there
    # i#2030: we do not support wrap tests on x64
    if (NOT X64)
      newtest_nobuild(wrap_malloc malloc "" "-no_replace_malloc" "" OFF "malloc")
    endif ()
  endif ()
  # i#2030: we do not support wrap tests on x64
  if (NOT X64)
    if (UNIX OR "${CMAKE_SYSTEM_VERSION}" STRLESS "6.2")
      # this test crashes on win8 so we only run it on older Windows
      if (NOT cs2bug_flags MATCHES "SKIP_MISMATCH_DTR")
        newtest_nobuild(wrap_cs2bug cs2bug "" "-no_replace_malloc" "" OFF "cs2bug.wrap")
      else ()
        # -no_replace_malloc raises unrecoverable heap errors (i#1161)
        newtest_ex(wrap_cs2bug cs2bug.cpp "" "-no_replace_malloc" "" OFF ${cs2bug_res} 0)
      endif ()
    endif ()
    newtest_nobuild_ex(wrap_operators operators ""
      "-no_replace_malloc;${operators_drm_ops}" "${operators_dr_ops}"
      OFF "operators" 0 "")
  endif ()

  # shared by all suppress tests
  tobuild(suppress suppress.c)
  if (UNIX)
    append_test_compile_flags(suppress "-Wno-uninitialized")
    if (HAVE_ALLOC_SIZE_WARNING_INTERNAL)
      # XXX: I can't get gcc 7.3.0 to not warn on the CallocOverflow test no matter
      # what -Wno-alloc-size-larger-than* I try.  The only solution I came up with is
      # to live with warnings :(
      append_test_compile_flags(suppress "-Wno-error")
    endif ()
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
    # i#2030: we do not support wrap tests on x64
    if (NOT X64)
      newtest_nobuild(wrap_wincrt wincrt "" "-no_replace_malloc" "" OFF "wincrt")
    endif ()

    # FIXME: Re-enable when it doesn't break the build.
    #newtest(rtl_memory_zones rtl_memory_zones.c)
    #target_link_libraries(rtl_memory_zones ${ntimp_lib})
    #if (NOT USER_SPECIFIED_DynamoRIO_DIR AND "${CMAKE_GENERATOR}" MATCHES "Visual Studio")
    #  # for parallel build correctness we need a target dependence
    #  add_dependencies(rtl_memory_zones ntdll_imports)
    #endif ()

    if (USE_DRSYMS) # cygwin build can't see static malloc routines
      tobuild(wincrtdbg wincrt.cpp)
      append_test_compile_flags(wincrtdbg "/MTd")
      newtest_nobuild(wincrtdbg wincrtdbg "" "-redzone_size;64" "" OFF "")
      # i#2030: we do not support wrap tests on x64
      if (NOT X64)
        newtest_nobuild(wrap_wincrtdbg wincrtdbg "" "-no_replace_malloc" "" OFF
          "wincrtdbg")
      endif ()

      newtest_custbuild(mallocMTd malloc.c "/MTd" malloc)
      newtest_custbuild(mallocMD malloc.c "/MD" malloc)

      # C++ tests with other libc configs
      newtest_custbuild(cs2bugMTd cs2bug.cpp "/MTd /DSKIP_MISMATCH_DTR" cs2bugMTd)
      newtest_custbuild(cs2bugMTdZI cs2bug.cpp "/ZI /MTd /DSKIP_MISMATCH_DTR" cs2bugMTd)
      newtest_custbuild(cs2bugMD cs2bug.cpp "/MD ${cs2bug_flags}" ${cs2bug_res})
      newtest_custbuild(cs2bugMDd cs2bug.cpp "/MDd /DSKIP_MISMATCH_DTR" cs2bugMTd)
      # i#2030: we do not support wrap tests on x64
      if (NOT X64)
        newtest_nobuild(wrap_cs2bugMTd cs2bugMTd "" "-no_replace_malloc" "" OFF
          "cs2bugMTd")
      endif ()

      # Test i#607 part D
      tobuild(operatorsMDd operators.cpp)
      append_test_compile_flags(operatorsMDd "/MDd")
      newtest_nobuild_ex(operatorsMDd operatorsMDd "" "" "" OFF operators
        # ignore exit code (b/c -replace_malloc calls dr_exit_process(1))
        "ANY" "")
      # i#2030: we do not support wrap tests on x64
      if (NOT X64)
        newtest_nobuild_ex(wrap_operatorsMDd operatorsMDd ""
          "-no_replace_malloc" "" OFF operators 0 "")
      endif ()
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
  if (UNIX AND NOT ANDROID) # pthread is built in to Bionic
    target_link_libraries(realloc pthread)
  endif ()

  if (WIN32 AND X64)
    # Valgrind annotations are not available for 64-bit Windows. */
  else ()
    newtest(annotations annotations.c)
  endif ()

  if (UNIX AND NOT ANDROID) # Android doesn't seem to support these alloc routines
    newtest(memalign memalign.c)
    newtest_nobuild(memalign.nodelay memalign "" "-delay_frees;0" "" OFF "memalign")
    newtest_nobuild(memalign.pattern memalign "" "-light" "" OFF "")
  endif ()

  # persistent cache tests: currently only light mode is supported
  # XXX: would be nice to ensure pcaches are actually generated and used,
  # but how?  annotations would be the cleanest way but that requires
  # a bunch of annotations that are only used for tests.
  # XXX: we use pattern mode as the default light mode, which does not work with
  # persistent cache (i#1184), so we use "-no_check_uninitialized -no_count_leaks"
  # instead.
  newtest_ex(pcache free.c "" "-no_check_uninitialized;-no_count_leaks;-persist_code"
    # do not load any stale pcaches from prior runs, in first run
    "-no_use_persisted;-no_coarse_disk_merge;-no_coarse_lone_merge" OFF "addronly" 0)
  if (WIN32)
    # we make a separate executable to avoid ASLR
    append_link_flags(pcache "/dynamicbase:no")
  endif ()
  if (NOT X64) # XXX i#2034: add x64 support
    newtest_nobuild(pcache-use pcache "" "-no_check_uninitialized;-no_count_leaks;-persist_code" "" OFF "addronly")
    # when running tests in parallel, have to generate pcaches first
    set_property(TEST pcache-use APPEND PROPERTY DEPENDS pcache)
  endif ()
  newtest_ex(track_origins track_origins.c "" "-light;-track_origins_unaddr" ""
    OFF "" 0)
  # pattern mode testing.
  newtest_nobuild(free.pattern free "" "-unaddr_only" "" OFF "addronly")
  newtest_nobuild(malloc.pattern malloc "" "-unaddr_only" "" OFF "")
  if (NOT ARM) # XXX i#1726: port to ARM
    newtest_nobuild(registers.pattern registers "" "-unaddr_only" "" OFF
      "registers.pattern")
  endif ()
  newtest_nobuild(track_origins.pattern track_origins ""
    "-unaddr_only;-track_origins_unaddr" "" OFF "track_origins")
  if (NOT ARM) # XXX i#1726: port to ARM
    newtest_nobuild_ex(state.pattern state "" "-unaddr_only" "" OFF "" "ANY" "")
  endif ()
else (TOOL_DR_MEMORY)
  newtest_ex(stale stale.c "" "-staleness;-stale_granularity;100" "" OFF "" 0)

  newtest_nobuild(time-allocs malloc "" "-time_allocs" "" OFF "")
  newtest_nobuild(time-bytes malloc "" "-time_bytes" "" OFF "")
  newtest_nobuild(time-instrs malloc "" "-time_instrs" "" OFF "")
  newtest_nobuild(dump malloc "" "-dump" "" OFF "")

  set(nudge_test_args "")
endif (TOOL_DR_MEMORY)

if (NOT ARM) # XXX i#1726: port to ARM
  # nudge test: runs infloop in background and runtest.cmake nudges it
  tobuild(infloop infloop.c)
  get_target_path_for_execution(infloop_path infloop)
  # we have special support to put run_app_in_bg and its args first, so we put
  # the test to run as a final drmem arg
  newtest_nobuild(nudge run_app_in_bg
    "-out;./nudge-out"
    "${nudge_test_args}--;${infloop_path}" "" OFF "")
endif ()
if (TOOL_DR_MEMORY AND WIN32)
  # See above for why passing -lib_blacklist_frames 0.
  set(nudge_handle_test_args "-leaks_only;-no_count_leaks;-check_handle_leaks;")
  newtest_nobuild(nudge_handle run_app_in_bg
    "-out;./nudge-handle-out"
    "${nudge_handle_test_args}--;${infloop_path}" "" OFF "")
endif (TOOL_DR_MEMORY AND WIN32)

newtest(leakcycle leakcycle.cpp)
if (WIN32)
  # With -replace_malloc we have trouble allocating a low enough heap for the wide
  # char test, so we stick to wrapping for this test.
  # Wrapping doesn't work on win8 so we disable the test there.
  if ("${CMAKE_SYSTEM_VERSION}" STRLESS "6.2")
    # i#2030: we do not support wrap tests on x64
    if (NOT X64)
      newtest_ex(leak_string leak_string.cpp "" "-no_replace_malloc" "" OFF leak_string 0)
    endif ()
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

if (APPLE)
  newtest(mac_zones mac_zones.c)
endif (APPLE)

else ()
  # XXX i#1726: we'll eliminate this duplication once we have full mode working --
  # and when we do, be sure to remove the runtest.cmake auto-ignore of # uninits.

  # default mode == pattern + leaks
  newtest(hello hello.c)
  newtest(free free.c)
  if (NOT ARM) # XXX i#1726: port to ARM
    newtest_custbuild(bitfield bitfield.cpp "-DBITFIELD_ASM" bitfield)
  endif ()
  newtest(patterns patterns.c)
  if (NOT ANDROID) # FIXME i#1860: fix for Android
    newtest_nobuild_ex(free.exitcode free "" "-exit_code_if_errors;42" "" OFF
      "free" 42 "")
  endif ()
  newtest_ex(track_origins track_origins.c "" "-light;-track_origins_unaddr" ""
    OFF "" 0)

  if (ARM)
    newtest(asmtest asmtest_arm.c)
  endif ()

  # pattern mode testing w/o leaks
  newtest_nobuild_ex(free.pattern free "" "-unaddr_only" "" OFF "addronly" 0 "")
  if (NOT ANDROID) # FIXME i#1860: fix for Android
    newtest_ex(malloc.pattern malloc.c "" "-unaddr_only" "" OFF "" 0)
  endif ()
  if (NOT ARM) # XXX i#1726: port to ARM
    newtest_ex(registers.pattern registers.c "" "-unaddr_only" "" OFF
      "registers.pattern" 0)
  endif ()
  newtest_ex(track_origins.pattern track_origins.c "" "-unaddr_only;-track_origins_unaddr"
    "" OFF "track_origins" 0)
  if (WIN32)
    newtest_ex(handle handle.cpp ""
      "-unaddr_only;-check_gdi;-check_handle_leaks;-lib_blacklist_frames;0" ""
      OFF "" 0)
    newtest_ex(procterm procterm.c "" "-unaddr_only;-lib_blacklist_frames;0" "" OFF
      "procterm.addronly" 0)
  endif (WIN32)

  if (NOT ARM) # i#1726: no shadow yet on ARM
    # shadow light testing
    newtest_nobuild_ex(hello.shadow hello "" "-pattern;0" "" OFF "hello" 0 "")
    newtest_nobuild_ex(free.shadow free "" "-pattern;0" "" OFF "free" 0 "")
    newtest_nobuild_ex(patterns.shadow patterns "" "-pattern;0" "" OFF "patterns" 0 "")
    if (LINUX)
      get_target_path_for_execution(hello_path hello)
      newtest_ex(nonaslr nonaslr.c "${hello_path}" "-pattern;0" "" OFF "hello" 0)
    endif (LINUX)
  endif ()
endif ()

# XXX i#1660: gtest is not building with clang 6.0
# XXX i#1726: need to port app_suite to ARM.
if (NOT APPLE AND NOT ARM)
  add_subdirectory(app_suite)
  if (TOOL_DR_HEAPSTAT)
    # i#1358: Dr. Heapstat currently can't handle code in the heap
    set(app_suite_ops "--gtest_filter=-MallocTests.Executable")
  else ()
    set(app_suite_ops "")
  endif ()
  if (NOT X64) # FIXME i#111: failing on Travis
    newtest_nobuild_allparams(app_suite app_suite_tests "${app_suite_ops}"
      "-suppress;{DRMEMORY_CTEST_SRC_DIR}/app_suite/default-suppressions.txt"
      # i#1309: turn off some DR debug checking to speed up the test, as it times out
      # on Dr. Heapstat w/ online symbolization.
      # i#1809: turn off ldmps from false pos curiosity
      "-checklevel;1;-dumpcore_mask;0x877d" OFF "" 0 ""
      # This test can take >120s in the suite.
      240)
  endif ()
  if (TOOL_DR_MEMORY)
    newtest_nobuild_allparams(app_suite.pattern app_suite_tests ""
      "-unaddr_only;-suppress;{DRMEMORY_CTEST_SRC_DIR}/app_suite/default-suppressions.txt"
      # i#1809: turn off ldmps from false pos curiosity
      "-dumpcore_mask;0x877d" OFF "" 0 ""
      # This test can take >120s in the suite.
      240)
  endif ()
  if (WIN32)
    # i#1908: Test using a syscall number text file by generating one and disabling
    # our internal tables.
    find_package(Perl)
    if (NOT PERL_FOUND)
      message(STATUS "Warning: perl not found: disabling syscall_file_all test")
    else ()
      # Place somewhere that DrM won't look by default:
      set(syscall_file_path "${CMAKE_CURRENT_BINARY_DIR}")
      add_custom_target(syscall_files ALL
        DEPENDS "${syscall_file_path}/syscalls_x86.txt")
      add_custom_command(
        OUTPUT "${syscall_file_path}/syscalls_x86.txt"
        DEPENDS "${PROJECT_SOURCE_DIR}/tools/mksyscalltxt.pl"
        "${PROJECT_SOURCE_DIR}/drsyscall/drsyscall_numx.h"
        "${PROJECT_SOURCE_DIR}/drsyscall/drsyscall_usercallx.h"
        COMMAND ${PERL_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/mksyscalltxt.pl
          ${syscall_file_path}
        VERBATIM)
      newtest_nobuild(syscall_file_all app_suite_tests
        # Run enough tests to generate some errors w/o accurate syscall info.
        # Disable Msgbox (slow) and ScrollDC (GDI error flakiness).
        "--gtest_filter=ATLTests.*:NtUserTests.*:-NtUserTests.Msgbox:NtUserTests.ScrollDC"
        "-no_use_syscall_tables;-ignore_kernel;-syscall_number_path;${syscall_file_path};-suppress;{DRMEMORY_CTEST_SRC_DIR}/app_suite/default-suppressions.txt"
        "-checklevel;1" OFF "syscall_file")
    endif (NOT PERL_FOUND)
    # Test auto-generating syscall number files (i#1848):
    newtest_nobuild(syscall_file_gen app_suite_tests
      # Run enough tests to generate some errors w/o accurate syscall info.
      # Disable Msgbox (slow) and ScrollDC (GDI error flakiness).
      "--gtest_filter=ATLTests.*:NtUserTests.*:-NtUserTests.Msgbox:NtUserTests.ScrollDC"
      "-no_use_syscall_tables;-suppress;{DRMEMORY_CTEST_SRC_DIR}/app_suite/default-suppressions.txt"
      "-checklevel;1" OFF "syscall_file")
  endif ()
endif ()

# framework subdir is added at top level b/c wants DR cflags

if (TOOL_DR_MEMORY)
  if (NOT ANDROID) # FIXME i#1860: fix for Android
    add_subdirectory(fuzz)
  endif ()
endif ()

if (APPLE)
  # Enable a few tests for the test suite without perturbing
  # all the code above.
  # XXX: can we get this to automatically happen for a local "ctest" w/o
  # the user having to pass "-L OSX"?
  set_tests_properties(hello free malloc asmtest bitfield addronly
    float annotations free.pattern mac_zones memalign
    memalign.nodelay memalign.pattern
    PROPERTIES LABELS OSX)
endif ()
