# ***************************************************************************
# Copyright (c) 2017 Google, Inc.  All rights reserved.
# ***************************************************************************
#
#
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
# * Neither the name of Google, Inc. nor the names of its contributors may be
#   used to endorse or promote products derived from this software without
#   specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE, INC. OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.
#
# ********************************************************************************
# The script is used to search for WinAPI function prototypes in the SDK's headers

import os
import sys
from os import listdir
from os.path import isfile, join

# the list of ignored expored functions
common_dll_names = {"DllCanUnloadNow", "DllGetClassObject", "DllRegisterServer",
                    "DllUnregisterServer", "DllEntryPoint", "DllInstall"}

# the path where a list or lists of WinAPI functions to search for are located
EXPORT_PATH = "exports\\"

# the path where Windows headers are located (install Microsoft SDK to have them)
HEADERS_PATH = "C:\\Program Files\\Microsoft SDKs\\Windows\\v7.1\\Include\\"

# the path where the script saves results
RESULTS_PATH = "results\\"

def merge_entries(entry, duplicates, function_name):
    '''
    The function converts a list of entries into the string to save in the log
    @in entry - a list of entries
    @in duplicates_found - prepend an output string with [DUPLICATE] token
    @out - a string to save in the log
    '''
    final_str = function_name + " -> "
    if duplicates == 1:
        final_str += "[DUPLICATE] "
    for element in entry:
        element = element.replace("\n", "")
        element = ' '.join(element.split())
        element = element.replace("*", "* ")
        final_str = final_str + " " + element
    return final_str

def parse_headers():
    '''
    @in - the routine parse SDKs headers located in HEADERS_PATH
    @out - a list of lines from each header
    '''

    headers_content = list()
    headers = [f for f in listdir(HEADERS_PATH) if isfile(join(HEADERS_PATH, f))]
    for header in headers:
        if not header.endswith(".h"):
            continue
        header_content = open(HEADERS_PATH + header, 'r').readlines()
        headers_content.append(header_content)
    return headers_content

def find_in_headers(entry_name, headers_content):
    '''
    The function looks for the entry_name in the headers_count and returns a list of
    potentially similar functions (that looks like WinAPI function prototype)
    @in entry_name - a name of WinAPI function to search for
    @in headers_content - headers content to search in
    @out - a list of WinAPI function prototypes
    '''

    list_of_results = list()
    for header_content in headers_content:
        for idx, line in enumerate(header_content):
            if entry_name in line:
                ''' Parse line, look for separate names '''
                if "(" in line and not "#define" in line and not "return " in line\
                   and not "//" in line and not "/*" in line and not "*/" in line\
                   and not "=" in line and not "STDMETHOD" in line\
                   and not "EXTERN_GUID" in line:

                    final_line = tuple()
                    tmp_idx = idx
                    #take return type, it can sit before function or at the same line
                    while tmp_idx > 1:
                        tmp_idx = tmp_idx - 1 # looking back
                        if header_content[tmp_idx] == '\n' or ';' in header_content[tmp_idx]\
                           or "#" in header_content[tmp_idx]:
                            break
                        if header_content[tmp_idx].startswith("\\"): # ignore comments
                            continue
                        final_line = final_line + (header_content[tmp_idx],)

                    tmp_idx = idx
                    # take arguments if exist
                    while tmp_idx < len(header_content):
                        if not header_content[tmp_idx].startswith("//"):
                            comment_idx = header_content[tmp_idx].find("//")
                            new_line = header_content[tmp_idx]
                            if comment_idx: # remove comment after an argument
                                new_line = header_content[tmp_idx][:comment_idx]
                            final_line = final_line + (new_line,)
                        if ";" in header_content[tmp_idx]:
                            break
                        tmp_idx = tmp_idx + 1
                    # we have a limitation for the prototype length (e.g. no more than
                    # 70 elements).
                    if len(final_line) > 70  or "{" in final_line:
                        continue
                    found = 0
                    '''for element in final_line:
                        element = element.replace("(", "")
                        if entry_name == element:
                            found = 1
                    if found != 1:
                        continue'''
                    list_of_results.append(final_line)
    results = ""
    duplicates = 0
    for entry in list_of_results:
        results += merge_entries(entry, duplicates, entry_name) + "\n"
        duplicates = 1
    return results

if __name__ == "__main__":
    export_files = [f for f in listdir(EXPORT_PATH) if isfile(join(EXPORT_PATH, f))]
    headers_content = parse_headers() # parse all headers

    for idx, file in enumerate(export_files):
        print "Done %d out of %d" % (idx, len(export_files))

        if "kernel32" not in file:
            continue

        if file.startswith("api-ms-win"): # just special wrappers for the system dlls
            continue

        exp_file_content = open(EXPORT_PATH + file, 'r').readlines()
        config = open(RESULTS_PATH + file +".headers.out", 'w')

        for export_entry in exp_file_content:
            export_entry = export_entry[:-1] # remove \n
            if export_entry in common_dll_names: # ignore common exports
               continue

            config.write("Looking for entry " + export_entry + "\n")

            entry = find_in_headers(export_entry, headers_content)
            if entry == "":
                config.write("NONE\n")
            else:
                config.write(entry)
        config.close()
print "All done. Please use gen_drltrace_config.py for postprocessing"
