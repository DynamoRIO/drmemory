# **********************************************************
# Copyright (c) 2011-2013 Google, Inc.  All rights reserved.
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

# tests are always built w/o optimizations and with symbols,
# regardless of DrMem library settings
set(CMAKE_BUILD_TYPE "Debug")

# TODO(timurrrr): I couldn't find out how to integrate googletest
# using CMake macros so here's a small hack. Sorry for that.
# xref http://code.google.com/p/googletest/issues/detail?id=372
set(GTEST_ROOT "../../third_party/googletest")
include_directories("${GTEST_ROOT}/include" "${GTEST_ROOT}")

# Automatically find all C/C++ sources and exclude tests for the different platform.
file(GLOB test_sources *.c *.cpp)
file(GLOB win_test_sources *_win.c *_win.cpp)
file(GLOB posix_test_sources *_posix.c *_posix.cpp)
if (UNIX)
    list(REMOVE_ITEM test_sources "" ${win_test_sources})
else (UNIX)
    list(REMOVE_ITEM test_sources "" ${posix_test_sources})
endif (UNIX)

add_executable(app_suite_tests
               ${test_sources}
               "${GTEST_ROOT}/src/gtest-all.cc"
               "${GTEST_ROOT}/src/gtest_main.cc")

if (UNIX)
  append_compile_flags(app_suite_tests "-DLINUX")
else (UNIX)
  # Work around googletest VS2012 failures by upping _VARIADIC_MAX from 5 (i#1141)
  append_compile_flags(app_suite_tests "-DWIN32 -D_VARIADIC_MAX=10")
endif (UNIX)

if (UNIX)
  # googletest requires -lpthread on Linux unless we define GTEST_HAS_PTHREAD=0
  # but we'll likely write some pthread tests anyways.
  find_package(Threads REQUIRED)
  target_link_libraries(app_suite_tests ${CMAKE_THREAD_LIBS_INIT})
endif (UNIX)
