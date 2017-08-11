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
# The script is used for searching of WinAPI function prototypes in the output of
# headers_parser.py and convert them into the format supported by drltrace.
# IMPORTANT NOTE: The resulting output is not a final configuration file. The script is
# not ideal. We tested it only for kernel32.dll and the manual analysis is required!

import os
import sys
from os import listdir
from os.path import isfile, join

types_map = {"BYTE":"BYTE", "WORD":"WORD", "DWORD":"DWORD", "WCHAR":"wchar", "UINT":"uint",
"DOUBLE":"double", "BOOLEAN":"bool", "BOOL":"bool", "ULONG":"ulong", "LONG":"long", "long":"long",
"LARGE_INTEGER":"LARGE_INTEGER", "_LARGE_INTEGER":"LARGE_INTEGER", "ULARGE_INTEGER":"ULARGE_INTEGER",
"_ULARGE_INTEGER":"_ULARGE_INTEGER", "OLESTR":"wchar", "LPOLESTR":"wchar*", "LPCOLESTR":"wchar*",
"PWSTR": "wchar*","LPWSTR":"wchar*", "PCWSTR":"wchar*", "LPCWSTR":"wchar*", "LPSTR":"char*",
"LPCSTR":"char*", "WPARAM":"WPARAM", "LPARAM":"LPARAM", "ATOM":"ATOM", "LANGID":"LANGID",
"COLORREF":"COLORREF", "LGRPID":"LGRPID", "LCTYPE":"LCTYPE", "LCID":"LCID",
"HANDLE":"HANDLE", "HACCEL":"HACCEL", "HBITMAP":"HBITMAP", "HBRUSH":"HBRUSH",
"HCOLORSPACE":"HCOLORSPACE", "HDC":"HDC", "HDESK":"HDESK", "HDWP":"HDWP",
"HENHMETAFILE":"HENHMETAFILE", "HFONT":"HFONT", "HGDIOBJ":"HGDIOBJ", "HGLOBAL":"HGLOBAL",
"HHOOK":"HHOOK", "HICON":"HICON", "HINSTANCE":"HINSTANCE", "HKEY":"HKEY", "HKL":"HKL",
"HLOCAL":"HLOCAL", "HMENU":"HMENU", "HMETAFILE":"HMETAFILE", "HMODULE":"HMODULE",
"HMONITOR":"HMONITOR", "HPALETTE":"HPALETTE", "HPEN":"HPEN", "HRGN":"HRGN",
"HRSRC":"HRSRC", "HSTR":"HSTR", "HTASK":"HTASK", "HWINSTA":"HWINSTA", "HWND":"HWND",
"SC_HANDLE":"SC_HANDLE", "SERVICE_STATUS_HANDLE":"SERVICE_STATUS_HANDLE", "int":"int",
"char": "char", "wchar_t":"wchar", "PSRWLOCK": "SRWLOCK*", "ULONG_PTR": "ULONG_PTR",
"PSID":"SID*", "PSECURE_MEMORY_CACHE_CALLBACK":"SECURE_MEMORY_CACHE_CALLBACK*",
"PVOID":"VOID*", "VOID":"VOID", "PVECTORED_EXCEPTION_HANDLER":"VECTORED_EXCEPTION_HANDLER*",
"PULONG_PTR":"ULONG_PTR*", "PBOOL":"BOOL*", "LPDWORD":"DWORD*", "LPVOID":"VOID*",
"LPOVERLAPPED_COMPLETION_ROUTINE":"OVERLAPPED_COMPLETION_ROUTINE*", "LPDCB":"DCB*",
"LPCOMMTIMEOUTS":"COMMTIMEOUTS*", "PTP_CALLBACK_INSTANCE": "TP_CALLBACK_INSTANCE*",
"LPOVERLAPPED":"OVERLAPPED*", "PTP_IO": "TP_IO*", "LPCOMSTAT":"COMSTAT*",
"PTP_POOL": "TP_POOL*", "PTP_CLEANUP_GROUP": "TP_CLEANUP_GROUP*", "PTP_TIMER": "TP_TIMER*",
"PTP_WAIT": "TP_WAIT*", "PTP_WORK":"TP_WORK*", "LPCOMMCONFIG": "COMMCONFIG*",
"FILETIME":"FILETIME", "PCNZWCH": "wchar*", "PNZWCH":"wchar*", "PUNZWCH": "wchar*",
"PCUNZWCH":"wchar*", "LPBOOL":"bool*", "LPPROGRESS_ROUTINE":"PROGRESS_ROUTINE*",
"INT":"int", "PCACTCTXA": "ACTCTXA*", "PCACTCTXW": "ACTCTXW*",
"SECURITY_ATTRIBUTES": "SECURITY_ATTRIBUTES", "LPSECURITY_ATTRIBUTES": "SECURITY_ATTRIBUTES*",
"SIZE_T": "size_t", "LPFIBER_START_ROUTINE": "FIBER_START_ROUTINE*",
"PJOB_SET_ARRAY": "JOB_SET_ARRAY*", "PHANDLE": "HANDLE*",
"MEMORY_RESOURCE_NOTIFICATION_TYPE": "MEMORY_RESOURCE_NOTIFICATION_TYPE",
"LPTHREAD_START_ROUTINE": "THREAD_START_ROUTINE*", "PTP_WIN32_IO_CALLBACK": "TP_WIN32_IO_CALLBACK*",
"PTP_CALLBACK_ENVIRON": "TP_CALLBACK_ENVIRON*", "PTP_TIMER_CALLBACK": "TP_TIMER_CALLBACK*",
"PTP_WAIT_CALLBACK": "TP_WAIT_CALLBACK*", "PTP_WORK_CALLBACK": "TP_WORK_CALLBACK*",
"WAITORTIMERCALLBACK": "WAITORTIMERCALLBACK", "LPPROC_THREAD_ATTRIBUTE_LIST": "PROC_THREAD_ATTRIBUTE_LIST*",
"LPFILETIME": "FILETIME*", "DWORD64": "DWORD64", "CALINFO_ENUMPROCA": "CALINFO_ENUMPROCA",
"CALINFO_ENUMPROCW": "CALINFO_ENUMPROCW", "CALID": "CALID", "CALINFO_ENUMPROCEXEX": "CALINFO_ENUMPROCEXEX",
"CALINFO_ENUMPROCEXA": "CALINFO_ENUMPROCEXA", "CALINFO_ENUMPROCEXW": "CALINFO_ENUMPROCEXW",
"CALTYPE": "CALTYPE", "DATEFMT_ENUMPROCA": "DATEFMT_ENUMPROCA", "DATEFMT_ENUMPROCEXA": "DATEFMT_ENUMPROCEXA",
"DATEFMT_ENUMPROCW": "DATEFMT_ENUMPROCW", "DATEFMT_ENUMPROCEXW": "DATEFMT_ENUMPROCEXW",
"DATEFMT_ENUMPROCEXEX": "DATEFMT_ENUMPROCEXEX", "LANGGROUPLOCALE_ENUMPROCA": "LANGGROUPLOCALE_ENUMPROCA",
"LANGGROUPLOCALE_ENUMPROCW": "LANGGROUPLOCALE_ENUMPROCW", "LONG_PTR": "LONG_PTR",
"ENUMRESLANGPROCA": "ENUMRESLANGPROCA", "ENUMRESLANGPROCW": "ENUMRESLANGPROCW", "ENUMRESNAMEPROCA": "ENUMRESNAMEPROCA",
"ENUMRESNAMEPROCW": "ENUMRESNAMEPROCW", "ENUMRESTYPEPROCA": "ENUMRESTYPEPROCA",
"ENUMRESTYPEPROCW": "ENUMRESTYPEPROCW", "CODEPAGE_ENUMPROCA": "CODEPAGE_ENUMPROCA",
"CODEPAGE_ENUMPROCW": "CODEPAGE_ENUMPROCW", "PDWORD": "DWORD*", "COORD": "COORD",
"PULONG": "ULONG*", "LPSYSTEMTIME":"SYSTEMTIME*", "LPCVOID":"VOID*", "PSIZE_T":"size_t*",
"LPCRITICAL_SECTION":"CRITICAL_SECTION*", "PULARGE_INTEGER":"ULARGE_INTEGER*",
"LPWORD":"WORD*", "PZZWSTR":"wchar*", "PCZZWSTR": "wchar*", "PUSHORT":"USHORT*",
"PULONGLONG":"ULONGLONG*", "PSLIST_HEADER":"SLIST_HEADER*",
"PPROCESSOR_NUMBER":"PROCESSOR_NUMBER*", "PCONDITION_VARIABLE":"CONDITION_VARIABLE*",
"PULONG64":"ULONG64*", "PSMALL_RECT":"SMALL_RECT*", "PINPUT_RECORD":"INPUT_RECORD*",
"PHKEY":"HKEY*", "LPBYTE":"BYTE*", "PWCHAR":"wchar*", "PUCHAR":"uchar*",
"PGROUP_AFFINITY":"GROUP_AFFINITY*", "PCZZWSTR":"wchar*","PACTCTX_SECTION_KEYED_DATA":"ACTCTX_SECTION_KEYED_DATA*",
"LPWCH":"wchar*", "LPOFSTRUCT":"OFSTRUCT*", "LPCH":"char*", "PTP_POOL_STACK_INFORMATION":"TP_POOL_STACK_INFORMATION*",
"PTIMERAPCROUTINE":"TIMERAPCROUTINE*", "PSTR":"char*", "PSECURITY_DESCRIPTOR":"SECURITY_DESCRIPTOR*",
"PREASON_CONTEXT":"REASON_CONTEXT*", "POWER_REQUEST_TYPE":"POWER_REQUEST_TYPE",
"PMEMORY_BASIC_INFORMATION":"MEMORY_BASIC_INFORMATION*", "PLARGE_INTEGER":"LARGE_INTEGER*",
"PIPE_ATTRIBUTE_TYPE":"PIPE_ATTRIBUTE_TYPE", "PINIT_ONCE":"INIT_ONCE*", "PFILETIME":"FILETIME*",
"PEXCEPTION_RECORD":"EXCEPTION_RECORD*", "PDYNAMIC_TIME_ZONE_INFORMATION":"DYNAMIC_TIME_ZONE_INFORMATION*",
"PDWORD_PTR":"DWORD_PTR*", "PCRITICAL_SECTION":"CRITICAL_SECTION*", "PCONTEXT":"CONTEXT*",
"PCONSOLE_SCREEN_BUFFER_INFOEX":"CONSOLE_SCREEN_BUFFER_INFOEX*", "PCONSOLE_READCONSOLE_CONTROL":"CONSOLE_READCONSOLE_CONTROL*",
"PCONSOLE_HISTORY_INFO":"CONSOLE_HISTORY_INFO*", "PCONSOLE_FONT_INFOEX":"CONSOLE_FONT_INFOEX*",
"PCHAR_INFO":"CHAR_INFO*", "LPWIN32_FIND_DATAW":"WIN32_FIND_DATAW*",
"LPWIN32_FIND_DATAA":"WIN32_FIND_DATAA*", "LPTIME_ZONE_INFORMATION":"TIME_ZONE_INFORMATION*",
"LPTHREADENTRY32":"THREADENTRY32*", "LPSYSTEM_INFO":"SYSTEM_INFO*",
"LPPROCESSENTRY32W":"PROCESSENTRY32W*", "LPPROCESSENTRY32":"PROCESSENTRY32*", "LPNLSVERSIONINFO":"NLSVERSIONINFO*",
"LPMODULEENTRY32W":"MODULEENTRY32W*", "LPMODULEENTRY32":"MODULEENTRY32*",
"LPINIT_ONCE":"INIT_ONCE*", "LPHEAPLIST32":"HEAPLIST32*", "LPHEAPENTRY32":"HEAPENTRY32*",
"LPCCH":"char*", "PWOW64_LDT_ENTRY":"WOW64_LDT_ENTRY*", "PWOW64_CONTEXT":"WOW64_CONTEXT*",
"PVOID*":"VOID**", "PTP_SIMPLE_CALLBACK":"TP_SIMPLE_CALLBACK*",
"PSYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION":"SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION*",
"PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX":"SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*",
"PSYSTEM_LOGICAL_PROCESSOR_INFORMATION":"SYSTEM_LOGICAL_PROCESSOR_INFORMATION*", "PSLIST_ENTRY":"SLIST_ENTRY*",
"PPERFORMANCE_DATA":"PERFORMANCE_DATA*", "PLONG":"LONG*", "PIO_COUNTERS":"IO_COUNTERS*",
"PINIT_ONCE_FN":"INIT_ONCE_FN*", "PHANDLER_ROUTINE":"HANDLER_ROUTINE*",
"PFLS_CALLBACK_FUNCTION":"FLS_CALLBACK_FUNCTION*", "PFILEMUIINFO":"FILEMUIINFO*",
"PCOORD":"COORD*", "PCONSOLE_SELECTION_INFO":"CONSOLE_SELECTION_INFO*",
"PCONSOLE_SCREEN_BUFFER_INFO":"CONSOLE_SCREEN_BUFFER_INFO*", "PCONSOLE_FONT_INFO":"CONSOLE_FONT_INFO*",
"PCONSOLE_CURSOR_INFO":"CONSOLE_CURSOR_INFO*", "PBOOLEAN":"BOOLEAN*", "PAPCFUNC":"APCFUNC*",
"LPTOP_LEVEL_EXCEPTION_FILTER":"TOP_LEVEL_EXCEPTION_FILTER*",
"LPSYSTEM_POWER_STATUS":"SYSTEM_POWER_STATUS*", "LPSTARTUPINFOW":"STARTUPINFOW*",
"LPSTARTUPINFOA":"STARTUPINFOA*", "LPPROCESS_HEAP_ENTRY":"PROCESS_HEAP_ENTRY*",
"LPOVERLAPPED_ENTRY":"OVERLAPPED_ENTRY*", "LPOSVERSIONINFOW":"OSVERSIONINFOW*",
"LPOSVERSIONINFOEXW":"OSVERSIONINFOEXW*", "LPOSVERSIONINFOEXA":"OSVERSIONINFOEXA*",
"LPOSVERSIONINFOA":"OSVERSIONINFOA*", "LPNLSVERSIONINFOEX":"NLSVERSIONINFOEX*",
"LPMEMORYSTATUSEX":"MEMORYSTATUSEX*", "LPMEMORYSTATUS":"MEMORYSTATUS*", "LPLONG":"LONG*",
"LPLDT_ENTRY":"LDT_ENTRY*", "LPHANDLE":"HANDLE*", "LPFILE_ID_DESCRIPTOR":"FILE_ID_DESCRIPTOR*",
"LPDEBUG_EVENT":"DEBUG_EVENT*", "LPCPINFOEXW":"CPINFOEXW*", "LPCPINFOEXA":"CPINFOEXA*",
"LPCPINFO":"CPINFO*", "LPCONTEXT":"CONTEXT*", "LPCOMMPROP":"COMMPROP*",
"LPBY_HANDLE_FILE_INFORMATION":"BY_HANDLE_FILE_INFORMATION*", "SYSTEMTIME":"SYSTEMTIME",
"REGSAM":"REGSAM", "HFILE":"HFILE", "USHORT":"USHORT", "UINT_PTR":"UINT_PTR", "SMALL_RECT":"SMALL_RECT",
"UCHAR":"uchar", "LONGLONG":"LONGLONG", "GUID":"GUID", "GET_FILEEX_INFO_LEVELS":"GET_FILEEX_INFO_LEVELS",
"GEOID":"GEOID", "FINDEX_SEARCH_OPS":"FINDEX_SEARCH_OPS", "FINDEX_INFO_LEVELS":"FINDEX_INFO_LEVELS",
"COMPUTER_NAME_FORMAT":"COMPUTER_NAME_FORMAT", "CHAR_INFO":"CHAR_INFO", "ULONGLONG":"ULONGLONG",
"NLS_FUNCTION":"NLS_FUNCTION", "DWORD_PTR":"DWORD_PTR", "STREAM_INFO_LEVELS":"STREAM_INFO_LEVELS",
"SECURITY_INFORMATION":"SECURITY_INFORMATION", "NORM_FORM":"NORM_FORM",
"JOBOBJECTINFOCLASS":"JOBOBJECTINFOCLASS", "INPUT_RECORD":"INPUT_RECORD",
"HEAP_INFORMATION_CLASS":"HEAP_INFORMATION_CLASS", "GEOTYPE":"GEOTYPE", "GEOCLASS":"GEOCLASS",
"FILE_SEGMENT_ELEMENT":"FILE_SEGMENT_ELEMENT", "FILE_INFO_BY_HANDLE_CLASS":"FILE_INFO_BY_HANDLE_CLASS",
"DWORDLONG":"DWORDLONG","EXCEPTION_POINTERS":"EXCEPTION_POINTERS", "_EXCEPTION_POINTERS":"_EXCEPTION_POINTERS",
"WOW64_CONTEXT":"WOW64_CONTEXT", "UILANGUAGE_ENUMPROCW":"UILANGUAGE_ENUMPROCW",
"UILANGUAGE_ENUMPROCA":"UILANGUAGE_ENUMPROCA", "TIMEFMT_ENUMPROCW":"TIMEFMT_ENUMPROCW",
"TIMEFMT_ENUMPROCEX":"TIMEFMT_ENUMPROCEX", "TIMEFMT_ENUMPROCA":"TIMEFMT_ENUMPROCA",
"NUMBERFMTW":"NUMBERFMTW",  "LOGICAL_PROCESSOR_RELATIONSHIP":"LOGICAL_PROCESSOR_RELATIONSHIP",
"LOCALE_ENUMPROCW":"LOCALE_ENUMPROCW", "LOCALE_ENUMPROCEX":"LOCALE_ENUMPROCEX",
"LOCALE_ENUMPROCA":"LOCALE_ENUMPROCA", "LATENCY_TIME":"LATENCY_TIME", "LANGUAGEGROUP_ENUMPROCW":"LANGUAGEGROUP_ENUMPROCW",
"LANGUAGEGROUP_ENUMPROCA":"LANGUAGEGROUP_ENUMPROCA", "GROUP_AFFINITY":"GROUP_AFFINITY", "GEO_ENUMPROC":"GEO_ENUMPROC",
"EXECUTION_STATE":"EXECUTION_STATE", "DYNAMIC_TIME_ZONE_INFORMATION":"DYNAMIC_TIME_ZONE_INFORMATION",
"CURRENCYFMTW":"CURRENCYFMTW", "CONTEXT":"CONTEXT", "CONSOLE_CURSOR_INFO":"CONSOLE_CURSOR_INFO", "CHAR":"char",
"APPLICATION_RECOVERY_CALLBACK":"APPLICATION_RECOVERY_CALLBACK", "HRESULT": "HRESULT", "PCNZCH": "char*",
"LPPROCESS_INFORMATION": "PROCESS_INFORMATION*", "LPINT": "int*", "LSTATUS":"LSTATUS",
"DEP_SYSTEM_POLICY_TYPE":"DEP_SYSTEM_POLICY_TYPE", "CURRENCYFMTA":"CURRENCYFMTA", "va_list": "va_list"}


tokens_ignore_prefix = {"WINAPI", "WINBASEAPI", "APIENTRY", "virtual", "DECLSPEC_NORETURN",
                        "WINNORMALIZEAPI"}

PATH = "results/" # path where the output of headers_parser.py was saved

unknown_types = dict() # we use this dictionary to save and print a list of unknown types

def parse_internal_parentesses(str):
    while True:
        end = str.find(")")
        if end == -1:
            break
        start = str.rfind("(", 0, end)
        if start == -1:
            break
        new_str = str[:start]
        new_str += str[end+1:]
        str = new_str
    return str

def get_type(type_str):
    return str(types_map.get(type_str, None))

def parse_prefix(line):
    '''
    The function searches for a WinAPI return type in the string specified
    @in line - a string with a type to find
    @out - returning type
    '''
    if "//" in line or "Boolean" in line or "&&" in line:
        return None
    if ")" in line:
        line = parse_internal_parentesses(line)

    line = line.split(" ")
    func_type = None
    has_type = 0
    ignore_until_paren = False
    for element in line:
        if "__success" in element:
            ignore_until_paren = True
        if ")" in element:
            ignore_until_paren = False
            continue
        if ignore_until_paren == True:
            continue
        if element in tokens_ignore_prefix or element == "" or "__" in element\
           or (("WIN" in element or "NT" in element) and "API" in element):
            continue
        if has_type >= 1:
            print "Warning. Failed to parse line %s (%s)" % (line, element)
            return "None"
        func_type = element
        has_type += 1

    if func_type != None:
        save_type = func_type
        func_type = get_type(func_type)
        if func_type == "None":
            try:
                unknown_types[save_type] += 1
            except:
                unknown_types[save_type] = 1

    return func_type

def parse_args(args_str):
    if "//" in args_str:
        return "FAILED"
    args_str = args_str.replace("\n", "")
    args_str = args_str.replace(");", "")
    if ")" in args_str:
        args_str = parse_internal_parentesses(args_str)
    args_str = args_str.replace("(", "")
    args = args_str.split(",")
    #if len(args) <= 1:
        #return "FAILED"
    res_types = list()
    for arg in args:
        arg = arg.split(" ")
        param_type = 0
        pointer = 0
        res_type = None
        for element in arg:
            if "__out" in element or "__deref_out" in element or "__deref_opt_out_opt" in element or "__deref_opt_out" in element:
                param_type = 1
                continue
            elif "__inout" in element:
                param_type = 2
                continue
            if "*" in element:
                pointer = 1
                element = element.replace("*", "")
            type = analyze_type(element)
            if type != None:
                res_type = type
            #else:
                #try:
                    #unknown_types[element] += 1
                #except:
                    #unknown_types[element] = 1
        if res_type == None:
            print "Unknown type for us"
        else:
            if param_type == 1:
                res_type = "+" + res_type
            elif param_type ==  2:
                res_type = "++" + res_type
            if pointer == 1:
                res_type += "*"
        res_types.append(str(res_type))
    return "|".join(res_types)

def parse_args(args_str):
    '''
    The function searches for a WinAPI function arguments in the string specified
    @in args_str - a string with arguments to find
    @out - a list of arguments separated by |
    '''
    if "//" in args_str: # it means we have a bug in the headers_parser.py
        return None
    args_str = args_str.replace("\n", "")
    args_str = args_str.replace(");", "")
    if ")" in args_str:
        args_str = parse_internal_parentesses(args_str)
    args_str = args_str.replace("(", "")
    args = args_str.split(",")
    res_types = list()
    for arg in args:
        arg = arg.split(" ")
        param_type = 0
        pointer = 0
        res_type = "None"
        for element in arg:
            if element == "CONST":
                continue
            if "__out" in element or "__deref_out" in element\
               or "__deref_opt_out_opt" in element or "__deref_opt_out" in element:
                param_type = 1
                continue
            elif "__inout" in element:
                param_type = 2
                continue
            if "*" in element:
                pointer = 1
                element = element.replace("*", "")
            type = get_type(element) #if type is unknown we have None string
            if type == "None":
                try:
                    unknown_types[element] += 1
                except:
                    unknown_types[element] = 1
            else:
                res_type = type
        if res_type != "None":
            if param_type == 1:
                res_type = "+" + res_type # equals __out
            elif param_type ==  2:
                res_type = "++" + res_type #equals __inout
            if pointer == 1:
                res_type += "*"
        res_types.append(str(res_type))
    return "|".join(res_types)

def parse_line(line, name):
    '''
    The function starts parsing of the line specified
    @in line - a line to parse
    @in name - a name of WinAPI function
    @out - a string with a function return type, name and arguments separated by |
    '''

    prefix = line[:line.find(name)]
    suffix = line[line.find(name)+len(name) + 1:]
    new_prefix = parse_prefix(prefix)
    args = parse_args(suffix)
    return "%s|%s|%s" % (new_prefix, name, args)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Please specify 'all' to parse all files in \'%s\' or file name" % PATH
        sys.exit(-1)

    export_files = list()
    if sys.argv[1] == 'all':
        export_files = [f for f in listdir(PATH) if isfile(join(PATH, f))]
    else:
        if not sys.argv[1].endswith(".headers.out"):
            print "File should end with *.headers_out"
            sys.exit(-1)
        export_files.append(sys.argv[1])

    for file in export_files:
        if not file.endswith(".headers.out"): #parse only output of headers_parser.py
            continue
        content = open(PATH + file, 'r').readlines()
        file_write = open(file + ".config_raw", 'w') # the output file
        file_write.write("The result is not a final config. Manual analysis is required\n")

        print "Parsing %s\n" % file
        for line in content:
            line = line[:-1]
            if "->" not in line or "(This)->" in line:
                continue

            #parse line
            file_write.write(line + "\n")
            line = line.replace("[DUPLICATE]", "") #parse duplicates as well
            line = line.split(" -> ")
            if len(line) <= 1:
                continue
            name = line[0]
            function_str = line[1]
            final_str = parse_line(function_str, name)
            file_write.write(final_str + "\n\n")

    result = sorted( ((v,k) for k,v in unknown_types.iteritems()), reverse=True)
    final_line = ""
    for count, element in result:
        final_line += "\"%s\":\"%s\", " % (element, element)
    file_write.write(final_line + "\n")
    file_write.close()
