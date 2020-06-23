# **********************************************************
# Copyright (c) 2014 Google, Inc.  All rights reserved.
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

# Caller must set these variables:
# + BASEDIR  = base build dir
# + VERINFO  = path to verinfo.exe

function (check_version_resources BASEDIR VERINFO)
  file(GLOB binaries
    ${BASEDIR}/bin/*.dll
    ${BASEDIR}/bin/*.exe
    ${BASEDIR}/bin/*/*.dll
    ${BASEDIR}/bin/*/*.exe
    ${BASEDIR}/drmf/*.dll
    ${BASEDIR}/drmf/*.exe
    ${BASEDIR}/drmf/*/*.dll
    ${BASEDIR}/drmf/*/*.exe
    ${BASEDIR}/drmf/*/*/*.dll
    ${BASEDIR}/drmf/*/*/*.exe)
  foreach (bin ${binaries})
    message("Running |${VERINFO}| on |${bin}|")
    if (NOT bin MATCHES "dbghelp.dll")
      execute_process(COMMAND
        ${VERINFO} ${bin}
        RESULT_VARIABLE result
        ERROR_VARIABLE stderr
        OUTPUT_VARIABLE stdout
        )
      # There's no reason to check the actual version: we have DR and DrMem
      # binaries.  If there's any version, we were the ones who put it there.
      if (result OR stderr OR NOT stdout MATCHES "FileVersion:")
        message(FATAL_ERROR
          "*** Error: ${bin} is missing resources (${result}, ${stderr})")
      endif ()
    endif ()
  endforeach ()
endfunction (check_version_resources)
