# **********************************************************
# Copyright (c) 2009 VMware, Inc.  All rights reserved.
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

file(GLOB dox_files "${PROJECT_SOURCE_DIR}/${toolname}/docs/*.dox")
file(GLOB dox_files_gen "${PROJECT_BINARY_DIR}/*.dox")
file(GLOB sub_files "${PROJECT_SOURCE_DIR}/${toolname}/docs/*.dox.sub")
file(GLOB in_files "${PROJECT_SOURCE_DIR}/${toolname}/docs/*.dox.in")
file(GLOB imgs "${PROJECT_SOURCE_DIR}/${toolname}/docs/*.png")

# some defines are set by DR config files so we must add here
if (WIN32)
  set(DEFINES ${DEFINES} -DWINDOWS)
else (WIN32)
  set(DEFINES ${DEFINES} -DLINUX)
endif (WIN32)

set(options_for_docs "${PROJECT_BINARY_DIR}/docs/options-docs.dox.in")
add_custom_command(
  OUTPUT "${options_for_docs}"
  DEPENDS "${PROJECT_SOURCE_DIR}/common/options-docs.c"
  "${PROJECT_SOURCE_DIR}/${tooldir}/optionsx.h"
  COMMAND ${CMAKE_CPP}
  ARGS -E ${CPP_NO_LINENUM} "${PROJECT_SOURCE_DIR}/common/options-docs.c"
  -I${PROJECT_SOURCE_DIR}/${tooldir} ${DEFINES} > "${options_for_docs}"
  VERBATIM)

set(doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
add_custom_command(
  OUTPUT ${doxyfile}
  DEPENDS ${dox_files}
          ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in
          ${CMAKE_CURRENT_SOURCE_DIR}/CMake_doxyfile.cmake
          ${PROJECT_SOURCE_DIR}/${tooldir}/docs/options-base.dox.in
          ${options_for_docs}
  COMMAND ${CMAKE_COMMAND}
  # script does not inherit any vars so we must pass them all in
  # Be sure to put a space after -D for 1st arg at least
  ARGS -D srcdir=${PROJECT_SOURCE_DIR}/${tooldir}/docs
       -D srcdir2=${PROJECT_SOURCE_DIR}/${INTERNAL_DIR}/${toolname}/docs
       -Dcommondir=${CMAKE_CURRENT_SOURCE_DIR}
       -Doutfile=${doxyfile}
       -Dversion_number=${TOOL_VERSION_NUMBER} 
       -DDOXYGEN_EXECUTABLE=${DOXYGEN_EXECUTABLE}
       -DVMKERNEL=${VMKERNEL}
       -DPERL_TO_EXE=${PERL_TO_EXE}
       -DUSE_DRSYMS=${USE_DRSYMS}
       -Doptions_for_docs=${options_for_docs}
       -Dtoolname=${toolname}
       -Dtoolname_cap_spc=${toolname_cap_spc}
       -P ${CMAKE_CURRENT_SOURCE_DIR}/CMake_doxyfile.cmake
  VERBATIM # recommended: p260
  )

set(footer ${CMAKE_CURRENT_BINARY_DIR}/footer.html)
add_custom_command(
  OUTPUT ${footer}
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/footer.html
          ${CMAKE_CURRENT_SOURCE_DIR}/CMake_footer.cmake
  COMMAND ${CMAKE_COMMAND}
  # Be sure to put a space after -D for 1st arg at least
  ARGS -D srcdir=${CMAKE_CURRENT_SOURCE_DIR} -Doutfile=${footer}
       -Dversion_number=${TOOL_VERSION_NUMBER}
       -P ${CMAKE_CURRENT_SOURCE_DIR}/CMake_footer.cmake
  VERBATIM # recommended: p260
  )

set(docsgen ${CMAKE_CURRENT_BINARY_DIR}/html/index.html)
add_custom_command(
  OUTPUT ${docsgen} # among other files
  DEPENDS ${dox_files} ${dox_files_gen} ${sub_files} ${in_files} ${imgs}
          ${CMAKE_CURRENT_SOURCE_DIR}/header.html
          ${CMAKE_CURRENT_SOURCE_DIR}/htmlstyle.css
          ${footer}
          ${doxyfile}
          ${CMAKE_CURRENT_SOURCE_DIR}/CMake_rundoxygen.cmake
  # We want doxygen to fail if it has warnings like "can't find header
  # files" so we run it through a script
  COMMAND ${CMAKE_COMMAND}
  # Be sure to put a space after -D for 1st arg at least
  ARGS -D DOXYGEN_EXECUTABLE=${DOXYGEN_EXECUTABLE}
       -P ${CMAKE_CURRENT_SOURCE_DIR}/CMake_rundoxygen.cmake
  VERBATIM # recommended: p260
  )
set_directory_properties(PROPERTIES
  ADDITIONAL_MAKE_CLEAN_FILES "html;latex;rtf")

add_custom_target(htmldocs ALL
  DEPENDS ${doxyfile}
          ${footer}
          ${docsgen}
  )

# FIXME: generate pdf: check for epstopdf and latex first

###########################################################################
# install rules

install(DIRECTORY
  ${CMAKE_CURRENT_BINARY_DIR}/html
  DESTINATION "${toolname}/docs"
  )

# IE for some reason won't initially load an .ico in a web page from a server,
# though will show it via file: or after pointing straight at image from server.
# doxygen fails to copy image referenced only in footer.html
install(FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/favicon.png
  DESTINATION "${toolname}/docs/html"
  )

