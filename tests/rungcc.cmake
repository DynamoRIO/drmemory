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

# arguments:
# * gcc = path to gcc.exe
# * exename = name of executable to create
# * source = name of source file to compile
# * args = extra args to gcc

set(GCC ${gcc})
if (${GCC} MATCHES "cygwin/g")
  # cygwin sets up /c/cygwin/bin/gcc.exe -> /etc/alternatives/gcc -> /usr/bin/gcc-3.exe
  # we just hardcode -4 and -3: too lazy to go get cygwin tools and resolve
  # the chain of links.
  string(REPLACE ".exe" "-4.exe" real ${GCC})
  if (EXISTS "${real}")
    set(GCC "${real}")
  else ()
    string(REPLACE ".exe" "-3.exe" real ${GCC})
    if (EXISTS "${real}")
      set(GCC "${real}")
    endif ()
  endif ()
endif()

# If cygwin is installed but isn't found on the system path it will be temporarily
# added to avoid build issues.
set(pre_path "$ENV{PATH}")
if (NOT pre_path MATCHES "cygwin/bin")
  if (GCC MATCHES "cygwin/bin")
    string(REGEX REPLACE "(^.*cygwin/bin/).*$" "\\1" suffix_path "${GCC}")
    set(ENV{PATH} "${pre_path};${suffix_path}")
  endif (GCC MATCHES "cygwin/bin")
endif (NOT pre_path MATCHES "cygwin/bin")

# We want -ggdb to get dwarf2 symbols instead of stabs, if using older gcc.
# We don't want dynamic C++ library b/c then we need machine to have
# libgcc_s_dw2-1.dll and libstdc++-6.dll on path and we want to support
# a non-intrusive mingw installation.
set(CMD_BASE ${GCC} -ggdb -fno-omit-frame-pointer ${args} -DWINDOWS
  -o ${exename} ${source} ${stdcpp})
execute_process(COMMAND ${CMD_BASE}
  RESULT_VARIABLE cmd_result
  ERROR_VARIABLE cmd_err)
if (cmd_result)
  if (cmd_err MATCHES "unrecognized option")
    # Older g++ doesn't have the -static-* params, but also doesn't depend on
    # a dll (static by default maybe?)
    string(REPLACE "-static-libgcc -static-libstdc++" "" CMD_BASE ${CMD_BASE})
    execute_process(COMMAND ${CMD_BASE}
      RESULT_VARIABLE cmd_result
      ERROR_VARIABLE cmd_err)
    if (cmd_result)
      message(FATAL_ERROR "*** ${GCC} failed (${cmd_result}): ${cmd_err}***\n")
    endif (cmd_result)
  else ()
    message(FATAL_ERROR "*** ${GCC} failed (${cmd_result}): ${cmd_err}***\n")
  endif ()
endif (cmd_result)
