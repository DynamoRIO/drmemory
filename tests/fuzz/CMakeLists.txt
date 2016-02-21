# **********************************************************
# Copyright (c) 2012-2016 Google, Inc.  All rights reserved.
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

# Always build Debug
set(CMAKE_BUILD_TYPE "Debug")

set_output_dirs("${PROJECT_BINARY_DIR}/tests")

# variables for platform-specific options and descriptor components
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

# fuzz the c target
set(CORPUS_PATH "${PROJECT_SOURCE_DIR}/tests/fuzz/corpus")
set(CORPUS_OUT "${PROJECT_BINARY_DIR}/tests/corpus_out")
file(MAKE_DIRECTORY "${CORPUS_OUT}")
newtest_ex(fuzz_corpus fuzz_corpus.c ""
  "-fuzz_corpus;${CORPUS_PATH};-fuzz_corpus_out;${CORPUS_OUT};-fuzz_num_iters;3"
  # share the result file with asmtest
  "" OFF "../asmtest" 0)
newtest_ex(fuzz_buffer fuzz_buffer.c
  "initialize" "-fuzz_function;repeatme;-fuzz_num_iters;10" "" OFF "" 0)
newtest_nobuild_ex(fuzz_buffer.replace_buffer fuzz_buffer
  "initialize"
  "-fuzz_function;repeatme;-fuzz_num_iters;10;-fuzz_replace_buffer"
  "" OFF "fuzz_buffer" 0 "")
newtest_nobuild_ex(fuzz_buffer.overflow fuzz_buffer
  "initialize;overread"
  "-light;-fuzz_function;repeatme;-fuzz_num_iters;10;-fuzz_replace_buffer"
  "" OFF "" 0 "")
set(fuzz_buffer_drmem_ops "-no_fuzz_dump_on_error;-fuzz_target;<main>!repeatme|2|0|1|10")
set(mutator_drmem_ops "-fuzz_mutator_alg;ordered;-fuzz_mutator_unit;bits;-fuzz_mutator_flags;0x1;-fuzz_mutator_sparsity;3")
newtest_nobuild_ex(fuzz_buffer.mutator.o-b-s-3 fuzz_buffer
  "initialize" "${fuzz_buffer_drmem_ops};${mutator_drmem_ops}" "" OFF "" 0 "")
set(mutator_drmem_ops "-fuzz_mutator_alg;random;-fuzz_mutator_unit;bits;-fuzz_mutator_flags;0x1;-fuzz_mutator_sparsity;3")
newtest_nobuild_ex(fuzz_buffer.mutator.r-b-s-3 fuzz_buffer
  "initialize" "${fuzz_buffer_drmem_ops};${mutator_drmem_ops}" "" OFF "" 0 "")
set(mutator_drmem_ops "-fuzz_mutator_alg;ordered;-fuzz_mutator_unit;bits;-fuzz_mutator_flags;0x0;-fuzz_mutator_sparsity;3")
newtest_nobuild_ex(fuzz_buffer.mutator.o-b-3 fuzz_buffer
  "initialize" "${fuzz_buffer_drmem_ops};${mutator_drmem_ops}" "" OFF "" 0 "")
set(mutator_drmem_ops "-fuzz_mutator_alg;random;-fuzz_mutator_unit;num;-fuzz_mutator_flags;0x0;-fuzz_mutator_sparsity;0")
newtest_nobuild_ex(fuzz_buffer.mutator.r-n fuzz_buffer
  "initialize" "${fuzz_buffer_drmem_ops};${mutator_drmem_ops}" "" OFF "" 0 "")
set(mutator_drmem_ops "-fuzz_mutator_alg;random;-fuzz_mutator_unit;num;-fuzz_mutator_flags;0x0;-fuzz_mutator_sparsity;0;-fuzz_mutator_random_seed;0x123456789abcdef0")
newtest_nobuild_ex(fuzz_buffer.mutator.random_seed fuzz_buffer
  "initialize" "${fuzz_buffer_drmem_ops};${mutator_drmem_ops}" "" OFF "" 0 "")
set(fuzz_one_input_drmem_ops "-fuzz_one_input;01020304050607080f0a0b0c0d0e0f10")
newtest_nobuild_ex(fuzz_buffer.one-input fuzz_buffer
  "initialize" "${fuzz_buffer_drmem_ops};${fuzz_one_input_drmem_ops}" "" OFF "" 0 "")
find_file(INPUT_DATA input.dat HINT "${PROJECT_SOURCE_DIR}/tests/fuzz/")
if (INPUT_DATA-NOTFOUND)
  message(FATAL "Did not find input.dat for fuzz_buffer.load_input test")
endif ()
set(fuzz_load_input_drmem_ops
  "-fuzz_function;repeatme;-fuzz_input_file;${INPUT_DATA};-fuzz_num_iters;0;-no_fuzz_replace_buffer")
newtest_nobuild_ex(fuzz_buffer.load_input fuzz_buffer
  "initialize" "${fuzz_load_input_drmem_ops}" "" OFF
  "fuzz_buffer.one-input" 0 "")
set(skip_initial_drmem_ops "-fuzz_skip_initial;2")
newtest_nobuild_ex(fuzz_buffer.skip_initial fuzz_buffer
  "initialize" "${fuzz_buffer_drmem_ops};${skip_initial_drmem_ops}" "" OFF "" 0 "")
if (NOT X64) # test detection of errors that requires shadow-memory
  newtest_nobuild_ex(fuzz_buffer.uninitialized fuzz_buffer
    "" "${fuzz_buffer_drmem_ops}" "" OFF "" 0 "")
  newtest_nobuild_ex(fuzz_buffer.overwrite fuzz_buffer
    "initialize;overwrite" "${fuzz_buffer_drmem_ops}" "" OFF "" 0 "")
  newtest_nobuild_ex(fuzz_buffer.overread fuzz_buffer
    "initialize;overread" "${fuzz_buffer_drmem_ops}" "" OFF "" 0 "")
  newtest_nobuild_ex(fuzz_buffer.underwrite fuzz_buffer
    "initialize;underwrite" "${fuzz_buffer_drmem_ops}" "" OFF "" 0 "")
  newtest_nobuild_ex(fuzz_buffer.underread fuzz_buffer
    "initialize;underread" "${fuzz_buffer_drmem_ops}" "" OFF "" 0 "")
  newtest_nobuild_ex(fuzz_buffer.leak fuzz_buffer
    "initialize;leak" "${fuzz_buffer_drmem_ops}" "" OFF "" 0 "")
endif (NOT X64)
set(fuzz_buffer_drmem_ops "-fuzz_target;<main>!repeatme|2|0|1|20")
set(fixed_size_drmem_ops "-fuzz_buffer_fixed_size;11")
newtest_nobuild_ex(fuzz_buffer.fixed_size fuzz_buffer
  "initialize" "${fuzz_buffer_drmem_ops};${fixed_size_drmem_ops}" "" OFF "" 0 "")
set(offset_drmem_ops "-fuzz_buffer_offset;9")
newtest_nobuild_ex(fuzz_buffer.offset fuzz_buffer
  "initialize" "${fuzz_buffer_drmem_ops};${offset_drmem_ops}" "" OFF "" 0 "")
set(fixed_with_offset_drmem_ops "-fuzz_buffer_fixed_size;5;-fuzz_buffer_offset;5")
newtest_nobuild_ex(fuzz_buffer.offset fuzz_buffer
  "initialize" "${fuzz_buffer_drmem_ops};${fixed_with_offset_drmem_ops}" "" OFF "" 0 "")
set(fuzz_buffer_drmem_ops "-fuzz_target;fuzz_buffer${app_extension}!repeatme|2|0|1|10")
newtest_nobuild_ex(fuzz_buffer.module_name fuzz_buffer
  "initialize" "${fuzz_buffer_drmem_ops}" "" OFF "" 0 "")
set(fuzz_dictionary_drmem_ops
  "-fuzz_function;repeatme;-fuzz_dictionary;${CMAKE_CURRENT_SOURCE_DIR}/dictionary.txt")
newtest_nobuild_ex(fuzz_buffer.dictionary fuzz_buffer
  "initialize" "${fuzz_dictionary_drmem_ops};-fuzz_mutator_alg;ordered" "" OFF "" 0 "")

# fuzz the cpp target
if (NOT UNIX AND NOT X64)
  set(cpp_callconv "|6") # on Windows x86 the target uses thiscall
  set(fuzz_callconv ";-fuzz_call_convention;thiscall")
endif (NOT UNIX AND NOT X64)
set(fuzz_buffer_symbol "fuzz_buffer.cpp${app_extension}!${fuzz_buffer_cpp_symbol}")
newtest_ex(fuzz_buffer.cpp fuzz_buffer.cpp "initialize"
  "-no_fuzz_dump_on_error;-fuzz_function;${fuzz_buffer_cpp_symbol};-fuzz_num_args;3;-fuzz_data_idx;1;-fuzz_size_idx;2;-fuzz_num_iters;10${fuzz_callconv}${enable_mangled_names}"
  "" OFF "" 0)
set(fuzz_buffer_drmem_ops
  "-no_fuzz_dump_on_error;-fuzz_target;${fuzz_buffer_symbol}|3|1|2|10${cpp_callconv}${enable_mangled_names}")
if (NOT X64) # test detection of errors that requires shadow-memory
  newtest_nobuild_ex(fuzz_buffer.uninitialized.cpp fuzz_buffer.cpp
    "" "${fuzz_buffer_drmem_ops}" "" OFF "" 0 "")
  newtest_nobuild_ex(fuzz_buffer.overwrite.cpp fuzz_buffer.cpp
    "initialize;overwrite" "${fuzz_buffer_drmem_ops}" "" OFF "" 0 "")
  newtest_nobuild_ex(fuzz_buffer.underwrite.cpp fuzz_buffer.cpp
    "initialize;underwrite" "${fuzz_buffer_drmem_ops}" "" OFF "" 0 "")
  newtest_nobuild_ex(fuzz_buffer.overread.cpp fuzz_buffer.cpp
    "initialize;overread" "${fuzz_buffer_drmem_ops}" "" OFF "" 0 "")
  newtest_nobuild_ex(fuzz_buffer.underread.cpp fuzz_buffer.cpp
    "initialize;underread" "${fuzz_buffer_drmem_ops}" "" OFF "" 0 "")
  newtest_nobuild_ex(fuzz_buffer.leak.cpp fuzz_buffer.cpp
    "initialize;leak" "${fuzz_buffer_drmem_ops}" "" OFF "" 0 "")
endif (NOT X64)
if (NOT UNIX)
  # demangled symbols can't be found on unix (elf table only has mangled)
  set(fuzz_buffer_symbol "fuzz_buffer.cpp${app_extension}!BufferPrinter::repeatme")
  set(fuzz_buffer_drmem_ops
    "-fuzz_target;${fuzz_buffer_symbol}|3|1|2|10${cpp_callconv}")
  newtest_nobuild_ex(fuzz_buffer.cpp.demangled fuzz_buffer.cpp
    "initialize" "${fuzz_buffer_drmem_ops}" "" OFF "" 0 "")

  # disable optimizations to prevent the target from being inlined
  append_property_string(TARGET fuzz_buffer COMPILE_FLAGS "/Ob0")
  append_property_string(TARGET fuzz_buffer.cpp COMPILE_FLAGS "/Ob0")
endif (NOT UNIX)
# XXX i#1734: need a test for a fuzz target loaded after target registration

if (NOT X64)
  set(fuzz_threads_drmem_ops "-fuzz_target;<main>!print_buffer|2|0|1|10")
  if (UNIX)
    newtest_ex(fuzz_threads fuzz_pthreads.c "" "${fuzz_threads_drmem_ops}" "" OFF "" 0)
    if (NOT ANDROID) # pthread is built in to Bionic
      target_link_libraries(fuzz_threads pthread)
    endif ()
  else ()
    newtest_ex(fuzz_threads fuzz_winthreads.c "" "${fuzz_threads_drmem_ops}" "" OFF "" 0)
  endif ()
endif (NOT X64)

# Test custom mutator
add_library(custom_mutator SHARED custom_mutator.c)
configure_DynamoRIO_client(custom_mutator)
# This is a little awkward: it might be better to do this in framework/ and configure
# as a DRMF client?  But we want to test end-to-end Dr. Memory custom mutators here.
append_test_compile_flags(custom_mutator "-UX86 -I${PROJECT_SOURCE_DIR}/drfuzz -I${PROJECT_BINARY_DIR}/drmf/include")
get_target_path_for_execution(mutator_libpath custom_mutator)
newtest_nobuild_ex(fuzz_custom_mutator fuzz_buffer
  "initialize"
  "-fuzz_function;repeatme;-fuzz_num_iters;10;-fuzz_mutator_lib;${mutator_libpath};-fuzz_mutator_ops;-add 0xdeadbeef"
  "" OFF "" 0 "")
