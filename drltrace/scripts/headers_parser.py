# ***************************************************************************
# Copyright (c) 2017 Google, Inc.  All rights reserved.
# ***************************************************************************
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
# The script is used to search for WinAPI function prototypes in the SDK's headers based
# on the list/lists of exported functions and to save them in a separate set of files for
# the further postprocessing using gen_drltrace_config.py. The list of exported functions
# should have one exported function name per line. For example, the list can be obtained
# using dumpbin tool on Windows.
#
# The script saves possible function prototypes using the following pattern:
# [exported function name] -> [possible return types] [function name found]([args])
# where [exported function name] is a name of function we are searching for.
#
# In some cases, we can find several function prototypes that match a certain exported
# function. Such cases should be resolved manually and we add a special label [DUPLICATE]
# to make the search easier for the user.

import os
import sys
from os import listdir
from os.path import isfile, join
import argparse

# the list of ignored exported functions
common_dll_names = {"DllCanUnloadNow", "DllGetClassObject", "DllRegisterServer",
                    "DllUnregisterServer", "DllEntryPoint", "DllInstall"}

# the maximum number of elements in a function prototype
prototype_length = 70

def merge_entries(entry, duplicates, function_name):
    '''
    The function converts a list of entries into the string to save in the log.
    @in entry - a list of entries.
    @in duplicates_found - prepend an output string with [DUPLICATE] token.
    @out - a string to save in the log.
    '''
    final_str = function_name + " -> "
    if duplicates == 1:
        final_str += "[DUPLICATE] "
    for element in entry:
        element = element.replace("\n", "")
        element = ' '.join(element.split())
        element = element.replace(" *", "*")
        element = element.replace("*", "* ")
        final_str = final_str + " " + element
    return final_str

def parse_headers(headers_path):
    '''
    @in - the routine parse SDKs headers located in the headers_path.
    @out - a list of lines from each header.
    '''

    headers_content = list()
    headers = [f for f in listdir(headers_path) if isfile(join(headers_path, f))]
    for header in headers:
        if not header.endswith(".h"):
            continue
        header_content = open(headers_path + header, 'r').readlines()
        headers_content.append(header_content)
    return headers_content

def find_in_headers(entry_name, headers_content):
    '''
    The function looks for the entry_name in the headers_count and returns a list of
    potentially similar functions (that looks like WinAPI function prototype).
    @in entry_name - a name of WinAPI function to search for.
    @in headers_content - headers content to search in.
    @out - a list of WinAPI function prototypes.
    '''

    list_of_results = list()
    for header_content in headers_content:
        for idx, line in enumerate(header_content):
            if entry_name in line:
                # parse line, look for separate names
                if "(" in line and not "#define" in line and not "return " in line\
                   and not "//" in line and not "/*" in line and not "*/" in line\
                   and not "=" in line and not "STDMETHOD" in line\
                   and not "EXTERN_GUID" in line:

                    final_line = tuple()
                    tmp_idx = idx
                    # take return type (before function or at the same line)
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
                    # We need some limitation for the prototype length to filter out really
                    # long incorrect results. For example, we found that the threshold of
                    # 70 elements is the best for kernel32.dll. However, it might be
                    # different for other dlls.
                    # The special check for "Boolean status" is required to handle specific
                    # case when a header has the comment like "Boolean status. Error code
                    # available via GetLastError()".
                    if len(final_line) > prototype_length or "{" in final_line\
                       or "Boolean status" in final_line or "&&" in final_line:
                        continue
                    list_of_results.append(final_line)
    results = ""
    duplicates = 0
    for entry in list_of_results:
        results += merge_entries(entry, duplicates, entry_name) + "\n"
        duplicates = 1
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "The script is used to search for WinAPI"
" function prototypes in the SDK headers.")
    parser.add_argument('-exports_path', help = "The path where a list or lists of WinAPI"
" functions to search for are located.", default = "exports\\")
    parser.add_argument('-headers_path', help = "The path where Windows headers are located"
" (install Microsoft SDK to have them).",
    default = "C:\\Program Files\\Microsoft SDKs\\Windows\\v7.1\\Include\\")
    parser.add_argument('-results_path', help = "The path where the script saves results.",
    default = "results\\")
    parser.add_argument('-parse_one_export_file', help = "The option is used to specify"
" for parsing a single file located in the exports_path.")

    args = parser.parse_args()

    print "Using %s as the exports dir, %s as the headers dir, %s as the results dir " %\
          (args.exports_path, args.headers_path, args.results_path)

    export_files = [f for f in listdir(args.exports_path) if isfile(join(args.exports_path, f))]
    # parse headers
    headers_content = parse_headers(args.headers_path)

    for idx, file in enumerate(export_files):
        print "Done %d out of %d" % (idx, len(export_files))

        if args.parse_one_export_file != None and args.parse_one_export_file not in file:
            continue

        if file.startswith("api-ms-win"): # just special wrappers for the system dlls
            continue

        exp_file_content = open(args.exports_path + file, 'r').readlines()
        config = open(args.results_path + file +".headers_out", 'w')

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
    print "All done. Please use gen_drltrace_config.py for postprocessing."
