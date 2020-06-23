# **********************************************************
# Copyright (c) 2011-2020 Google, Inc.  All rights reserved.
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

# **********************************************************
# Copyright (c) 2009 VMware, Inc.    All rights reserved.
# **********************************************************

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of VMware, Inc. nor the names of its contributors may be
#   used to endorse or promote products derived from this software without
#   specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.

# inputs:
# * srcdir
# * srclist
# * commondir
# * outfile
# * version_number
# * DOXYGEN_EXECUTABLE
# * VMKERNEL
# * options_for_docs
# * toolname
# * toolname_cap_spc
# * doxygen_ver
# * DynamoRIO_DIR
# * TOOL_DR_MEMORY
# * PACKAGED_WITH_DYNAMORIO

set(outdir "${CMAKE_CURRENT_BINARY_DIR}")
get_filename_component(optionsdir "${options_for_docs}" PATH)
# store cmake paths prior to cygwin conversion
set(srcdir_orig "${srcdir}")
set(optionsdir_orig "${optionsdir}")
set(commondir_orig "${commondir}")
set(outdir_orig "${outdir}")

include("${DynamoRIO_DIR}/docs_doxyutils.cmake")
set(input_paths srcdir outdir optionsdir commondir)
doxygen_path_xform(${DOXYGEN_EXECUTABLE} "${input_paths}")

configure_file(${commondir_orig}/Doxyfile.in ${outfile} COPYONLY)
process_doxyfile(${outfile} ${DOXYGEN_EXECUTABLE} ${doxygen_ver})

file(READ ${outfile} string)

# Be sure to quote ${string} to avoid interpretation (semicolons removed, etc.)

# Insert optionsx.h expansion
file(READ "${options_for_docs}" ops)
string(REGEX REPLACE "\"" "" ops "${ops}")
string(REGEX REPLACE "@!" "<" ops "${ops}")
string(REGEX REPLACE "@%" ">" ops "${ops}")
string(REGEX REPLACE "@&" "\"" ops "${ops}")
string(REGEX REPLACE "@@" "\n" ops "${ops}")
# Now insert into file that contains doxygen comment, etc., which is
# hard to include via cpp.
file(READ "${srcdir_orig}/options-base.dox.in" opsfile)
string(REGEX REPLACE "REPLACEME" "${ops}" opsfile "${opsfile}")
file(WRITE "${optionsdir_orig}/options-docs.dox" "${opsfile}")

function (replace_aliases out in)
  string(REGEX REPLACE "drmemory" "${toolname}" in "${in}")
  set(${out} ${in} PARENT_SCOPE)
endfunction (replace_aliases)

# Include mechanism: we copy all .dox files from srcdir into outdir
# and expand ^INCLUDEFILE
file(GLOB dox_files "${srcdir_orig}/*.dox")
foreach (dox ${dox_files} ${srclist})
  file(READ "${dox}" contents)
  string(REGEX MATCHALL "\nINCLUDEFILE [^ \r\n]*" includes "${contents}")
  foreach (inc ${includes})
    string(REGEX REPLACE "\nINCLUDEFILE " "" incfile "${inc}")
    # no support for including from other than srcdir
    file(READ "${srcdir_orig}/${incfile}" subst)
    # escape backslashes
    string(REGEX REPLACE "\\\\" "\\\\\\\\" subst "${subst}")
    string(REGEX REPLACE "${inc}" "\n${subst}" contents "${contents}")
    replace_aliases(contents "${contents}")
  endforeach (inc)
  # We assume Dr. Memory is the starting point for all tools
  string(REGEX REPLACE "Dr. Memory" "${toolname_cap_spc}" contents "${contents}")
  # Replace prefix
  string(REGEX REPLACE " " "" toolname_cap "${toolname_cap_spc}")
  string(REGEX REPLACE "Dr.Memory" "${toolname_cap}" contents "${contents}")
  replace_aliases(contents "${contents}")
  get_filename_component(doxbasename "${dox}" NAME)
  file(WRITE "${outdir_orig}/${doxbasename}" "${contents}")
endforeach (dox)

# Executed inside build dir, so we leave footer.html alone
# and have to fix up refs to source dir and subdirs
string(REGEX REPLACE
  "(PROJECT_NAME *= )[^\n]*\n"
  "\\1\"${toolname_cap_spc}\"\n" string "${string}")
string(REGEX REPLACE
  "(EXAMPLE_PATH *= )\\.\\."
  "\\1\"${commondir}/..\"" string "${string}")
string(REGEX REPLACE
  "(INPUT *= )\\."
  "\\1\"${outdir}\" \"${optionsdir}\" " string "${string}")
string(REGEX REPLACE
  "(IMAGE_PATH *= )\\."
  "\\1\"${commondir}\" \"${srcdir}\" " string "${string}")

string(REGEX REPLACE
  # if I don't quote ${string}, then this works: [^$]*$
  # . always seems to match newline, despite book's claims
  # xref cmake emails about regexp ^$ ignoring newlines: ugh!
  "(OUTPUT_DIRECTORY[ \t]*=)[^\n\r](\r?\n)"
  "\\1 \"${outdir}\"\\2" string "${string}")

string(REGEX REPLACE
  "TOOL_VERSION=X.Y.Z"
  "TOOL_VERSION=${version_number}" string "${string}")
if (PERL_TO_EXE OR USE_DRSYMS)
  string(REGEX REPLACE
    "FRONT_END=[^ ]*.pl"
    "FRONT_END=${toolname}.exe" string "${string}")
  string(REGEX REPLACE
    "FRONT_END_PATH=[^ ]*.pl"
    "FRONT_END_PATH=bin/${toolname}.exe" string "${string}")
  string(REGEX REPLACE
    "DRCONFIG_PATH=drconfig"
    "DRCONFIG_PATH=bin/drconfig.exe" string "${string}")
else (PERL_TO_EXE OR USE_DRSYMS)
  string(REGEX REPLACE
    "FRONT_END=[^ ]*.pl"
    "FRONT_END=${toolname}.pl" string "${string}")
  string(REGEX REPLACE
    "FRONT_END_PATH=[^ ]*.pl"
    "FRONT_END_PATH=bin/${toolname}.pl" string "${string}")
  string(REGEX REPLACE
    "DRCONFIG_PATH=drconfig"
    "DRCONFIG_PATH=bin/drconfig" string "${string}")
endif (PERL_TO_EXE OR USE_DRSYMS)
if (WIN32)
  string(REGEX REPLACE "PLATFORM=Linux" "PLATFORM=Windows" string "${string}")
else ()
  if (APPLE)
    string(REGEX REPLACE "PLATFORM=Linux" "PLATFORM=MacOS" string "${string}")
  else ()
    if (VMKERNEL)
      string(REGEX REPLACE "PLATFORM=Linux" "PLATFORM=ESXi" string "${string}")
    endif (VMKERNEL)
  endif (APPLE)
endif (WIN32)

string(REGEX REPLACE
  "(ENABLED_SECTIONS[ \t]*=)"
  "\\1 ${toolname}" string "${string}")
if (VMKERNEL)
  string(REGEX REPLACE
    "(ENABLED_SECTIONS[ \t]*=)"
    "\\1 VMX86_SERVER" string "${string}")
endif (VMKERNEL)
if (WIN32)
  string(REGEX REPLACE
    "(ENABLED_SECTIONS[ \t]*=)"
    "\\1 WINDOWS" string "${string}")
endif (WIN32)
if (TOOL_DR_MEMORY)
  string(REGEX REPLACE
    "(ENABLED_SECTIONS[ \t]*=)"
    "\\1 TOOL_DR_MEMORY" string "${string}")
endif (TOOL_DR_MEMORY)
if (PACKAGED_WITH_DYNAMORIO)
  string(REGEX REPLACE
    "(ENABLED_SECTIONS[ \t]*=)"
    "\\1 PACKAGED_WITH_DYNAMORIO" string "${string}")
endif()

# XXX: share w/ list of source paths in CMakeLists.txt ${headers}
set(headers "${commondir}/../drsyscall/drsyscall.h ${commondir}/../umbra/umbra.h ${commondir}/../drfuzz/drfuzz.h ${commondir}/../drfuzz/drfuzz_mutator.h")
set(headers "${headers} ${commondir}/../drsymcache/drsymcache.h")
set(headers "${headers} ${outdir}/../drmf/include/drmemory_framework.h")
if (TOOL_DR_MEMORY)
  string(REGEX REPLACE
    "using.dox" "using.dox errors.dox reports.dox light.dox fuzzer.dox coverage.dox"
    string "${string}")
  string(REGEX REPLACE
    "main.dox" "main.dox tools.dox ${headers}" string "${string}")
else ()
  string(REGEX REPLACE
    "main.dox" "main.dox ${headers}" string "${string}")
endif ()

file(WRITE ${outfile} "${string}")

# Newer doxygen complains if header.html and footer.html are missing and we
# don't create those until CMake_rundoxygen.cmake.
file(WRITE header.html "placeholder")
file(WRITE footer.html "placeholder")

# Now update to latest doxygen.  Suppress warnings since they're misleading:
# they say "please run doxygen -u" but we're currently doing just that.
execute_process(COMMAND
  ${DOXYGEN_EXECUTABLE} -u
  RESULT_VARIABLE doxygen_u_result
  ERROR_VARIABLE doxygen_u_error
  OUTPUT_QUIET # suppress "Configuration file `Doxyfile' updated."
  )
# I want to see errors other than:
#  Warning: Tag `MAX_DOT_GRAPH_HEIGHT' at line 248 of file Doxyfile has become obsolete.
#  To avoid this warning please update your configuration file using "doxygen -u"
string(REGEX REPLACE
  "(^|(\r?\n))[^\r\n]*has become obsolete.\r?\n"
  "\\1" doxygen_u_error "${doxygen_u_error}")
string(REGEX REPLACE
  "(^|(\r?\n))[^\r\n]*using \"doxygen -u\"\r?\n"
  "\\1" doxygen_u_error "${doxygen_u_error}")
if (doxygen_u_result)
  message(FATAL_ERROR "${DOXYGEN_EXECUTABLE} -u failed: ${doxygen_u_error}")
endif (doxygen_u_result)
if (doxygen_u_error)
  message(FATAL_ERROR "${DOXYGEN_EXECUTABLE} -u failed: ${doxygen_u_error}")
endif (doxygen_u_error)
