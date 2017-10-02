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
# The script is used for searching of WinAPI function prototypes in the output of
# headers_parser.py and converting them into the format supported by drltrace.
#
# IMPORTANT NOTE: The resulting output is not a final configuration file. The script is
# not ideal. We tested it only for kernel32.dll and the manual analysis is required!

import os
import sys
from os import listdir
from os.path import isfile, join
import argparse

types_map = {"BYTE":"BYTE",
"WORD":"WORD",
"DWORD":"DWORD",
"WCHAR":"wchar",
"UINT":"uint",
"DOUBLE":"double",
"BOOLEAN":"bool",
"BOOL":"bool",
"ULONG":"ulong",
"LONG":"long",
"long":"long",
"LARGE_INTEGER":"LARGE_INTEGER",
"_LARGE_INTEGER":"LARGE_INTEGER",
"ULARGE_INTEGER":"ULARGE_INTEGER",
"_ULARGE_INTEGER":"_ULARGE_INTEGER",
"OLESTR":"wchar",
"LPOLESTR":"wchar*",
"LPCOLESTR":"wchar*",
"PWSTR":"wchar*",
"LPWSTR":"wchar*",
"PCWSTR":"wchar*",
"LPCWSTR":"wchar*",
"LPSTR":"char*",
"LPCSTR":"char*",
"WPARAM":"WPARAM",
"LPARAM":"LPARAM",
"ATOM":"ATOM",
"LANGID":"LANGID",
"COLORREF":"COLORREF",
"LGRPID":"LGRPID",
"LCTYPE":"LCTYPE",
"LCID":"LCID",
"HANDLE":"HANDLE",
"HACCEL":"HACCEL",
"HBITMAP":"HBITMAP",
"HBRUSH":"HBRUSH",
"HCOLORSPACE":"HCOLORSPACE",
"HDC":"HDC",
"HDESK":"HDESK",
"HDWP":"HDWP",
"HENHMETAFILE":"HENHMETAFILE",
"HFONT":"HFONT",
"HGDIOBJ":"HGDIOBJ",
"HGLOBAL":"HGLOBAL",
"HHOOK":"HHOOK",
"HICON":"HICON",
"HINSTANCE":"HINSTANCE",
"HKEY":"HKEY",
"HKL":"HKL",
"HLOCAL":"HLOCAL",
"HMENU":"HMENU",
"HMETAFILE":"HMETAFILE",
"HMODULE":"HMODULE",
"HMONITOR":"HMONITOR",
"HPALETTE":"HPALETTE",
"HPEN":"HPEN",
"HRGN":"HRGN",
"HRSRC":"HRSRC",
"HSTR":"HSTR",
"HTASK":"HTASK",
"HWINSTA":"HWINSTA",
"HWND":"HWND",
"SC_HANDLE":"SC_HANDLE",
"SERVICE_STATUS_HANDLE":"SERVICE_STATUS_HANDLE",
"int":"int",
"char":"char",
"wchar_t":"wchar",
"PSRWLOCK":"SRWLOCK*",
"ULONG_PTR":"ULONG_PTR",
"PSID":"SID*",
"PSECURE_MEMORY_CACHE_CALLBACK":"SECURE_MEMORY_CACHE_CALLBACK*",
"PVOID":"VOID*",
"VOID":"VOID",
"PVECTORED_EXCEPTION_HANDLER":"VECTORED_EXCEPTION_HANDLER*",
"PULONG_PTR":"ULONG_PTR*",
"PBOOL":"BOOL*",
"LPDWORD":"DWORD*",
"LPVOID":"VOID*",
"LPOVERLAPPED_COMPLETION_ROUTINE":"OVERLAPPED_COMPLETION_ROUTINE*",
"LPDCB":"DCB*",
"LPCOMMTIMEOUTS":"COMMTIMEOUTS*",
"PTP_CALLBACK_INSTANCE":"TP_CALLBACK_INSTANCE*",
"LPOVERLAPPED":"OVERLAPPED*",
"PTP_IO":"TP_IO*",
"LPCOMSTAT":"COMSTAT*",
"PTP_POOL":"TP_POOL*",
"PTP_CLEANUP_GROUP":"TP_CLEANUP_GROUP*",
"PTP_TIMER":"TP_TIMER*",
"PTP_WAIT":"TP_WAIT*",
"PTP_WORK":"TP_WORK*",
"LPCOMMCONFIG":"COMMCONFIG*",
"FILETIME":"FILETIME",
"PCNZWCH":"wchar*",
"PNZWCH":"wchar*",
"PUNZWCH":"wchar*",
"PCUNZWCH":"wchar*",
"LPBOOL":"bool*",
"LPPROGRESS_ROUTINE":"PROGRESS_ROUTINE*",
"INT":"int",
"PCACTCTXA":"ACTCTXA*",
"PCACTCTXW":"ACTCTXW*",
"SECURITY_ATTRIBUTES":"SECURITY_ATTRIBUTES",
"LPSECURITY_ATTRIBUTES":"SECURITY_ATTRIBUTES*",
"SIZE_T":"size_t",
"LPFIBER_START_ROUTINE":"FIBER_START_ROUTINE*",
"PJOB_SET_ARRAY":"JOB_SET_ARRAY*",
"PHANDLE":"HANDLE*",
"MEMORY_RESOURCE_NOTIFICATION_TYPE":"MEMORY_RESOURCE_NOTIFICATION_TYPE",
"LPTHREAD_START_ROUTINE":"THREAD_START_ROUTINE*",
"PTP_WIN32_IO_CALLBACK":"TP_WIN32_IO_CALLBACK*",
"PTP_CALLBACK_ENVIRON":"TP_CALLBACK_ENVIRON*",
"PTP_TIMER_CALLBACK":"TP_TIMER_CALLBACK*",
"PTP_WAIT_CALLBACK":"TP_WAIT_CALLBACK*",
"PTP_WORK_CALLBACK":"TP_WORK_CALLBACK*",
"WAITORTIMERCALLBACK":"WAITORTIMERCALLBACK",
"LPPROC_THREAD_ATTRIBUTE_LIST":"PROC_THREAD_ATTRIBUTE_LIST*",
"LPFILETIME":"FILETIME*",
"DWORD64":"DWORD64",
"CALINFO_ENUMPROCA":"CALINFO_ENUMPROCA",
"CALINFO_ENUMPROCW":"CALINFO_ENUMPROCW",
"CALID":"CALID",
"CALINFO_ENUMPROCEXEX":"CALINFO_ENUMPROCEXEX",
"CALINFO_ENUMPROCEXA":"CALINFO_ENUMPROCEXA",
"CALINFO_ENUMPROCEXW":"CALINFO_ENUMPROCEXW",
"CALTYPE":"CALTYPE",
"DATEFMT_ENUMPROCA":"DATEFMT_ENUMPROCA",
"DATEFMT_ENUMPROCEXA":"DATEFMT_ENUMPROCEXA",
"DATEFMT_ENUMPROCW":"DATEFMT_ENUMPROCW",
"DATEFMT_ENUMPROCEXW":"DATEFMT_ENUMPROCEXW",
"DATEFMT_ENUMPROCEXEX":"DATEFMT_ENUMPROCEXEX",
"LANGGROUPLOCALE_ENUMPROCA":"LANGGROUPLOCALE_ENUMPROCA",
"LANGGROUPLOCALE_ENUMPROCW":"LANGGROUPLOCALE_ENUMPROCW",
"LONG_PTR":"LONG_PTR",
"ENUMRESLANGPROCA":"ENUMRESLANGPROCA",
"ENUMRESLANGPROCW":"ENUMRESLANGPROCW",
"ENUMRESNAMEPROCA":"ENUMRESNAMEPROCA",
"ENUMRESNAMEPROCW":"ENUMRESNAMEPROCW",
"ENUMRESTYPEPROCA":"ENUMRESTYPEPROCA",
"ENUMRESTYPEPROCW":"ENUMRESTYPEPROCW",
"CODEPAGE_ENUMPROCA":"CODEPAGE_ENUMPROCA",
"CODEPAGE_ENUMPROCW":"CODEPAGE_ENUMPROCW",
"PDWORD":"DWORD*",
"COORD":"COORD",
"PULONG":"ULONG*",
"LPSYSTEMTIME":"SYSTEMTIME*",
"LPCVOID":"VOID*",
"PSIZE_T":"size_t*",
"LPCRITICAL_SECTION":"CRITICAL_SECTION*",
"PULARGE_INTEGER":"ULARGE_INTEGER*",
"LPWORD":"WORD*",
"PZZWSTR":"wchar*",
"PCZZWSTR":"wchar*",
"PUSHORT":"USHORT*",
"PULONGLONG":"ULONGLONG*",
"PSLIST_HEADER":"SLIST_HEADER*",
"PPROCESSOR_NUMBER":"PROCESSOR_NUMBER*",
"PCONDITION_VARIABLE":"CONDITION_VARIABLE*",
"PULONG64":"ULONG64*",
"PSMALL_RECT":"SMALL_RECT*",
"PINPUT_RECORD":"INPUT_RECORD*",
"PHKEY":"HKEY*",
"LPBYTE":"BYTE*",
"PWCHAR":"wchar*",
"PUCHAR":"uchar*",
"PGROUP_AFFINITY":"GROUP_AFFINITY*",
"PCZZWSTR":"wchar*",
"PACTCTX_SECTION_KEYED_DATA":"ACTCTX_SECTION_KEYED_DATA*",
"LPWCH":"wchar*",
"LPOFSTRUCT":"OFSTRUCT*",
"LPCH":"char*",
"PTP_POOL_STACK_INFORMATION":"TP_POOL_STACK_INFORMATION*",
"PTIMERAPCROUTINE":"TIMERAPCROUTINE*",
"PSTR":"char*",
"PSECURITY_DESCRIPTOR":"SECURITY_DESCRIPTOR*",
"PREASON_CONTEXT":"REASON_CONTEXT*",
"POWER_REQUEST_TYPE":"POWER_REQUEST_TYPE",
"PMEMORY_BASIC_INFORMATION":"MEMORY_BASIC_INFORMATION*",
"PLARGE_INTEGER":"LARGE_INTEGER*",
"PIPE_ATTRIBUTE_TYPE":"PIPE_ATTRIBUTE_TYPE",
"PINIT_ONCE":"INIT_ONCE*",
"PFILETIME":"FILETIME*",
"PEXCEPTION_RECORD":"EXCEPTION_RECORD*",
"PDYNAMIC_TIME_ZONE_INFORMATION":"DYNAMIC_TIME_ZONE_INFORMATION*",
"PDWORD_PTR":"DWORD_PTR*",
"PCRITICAL_SECTION":"CRITICAL_SECTION*",
"PCONTEXT":"CONTEXT*",
"PCONSOLE_SCREEN_BUFFER_INFOEX":"CONSOLE_SCREEN_BUFFER_INFOEX*",
"PCONSOLE_READCONSOLE_CONTROL":"CONSOLE_READCONSOLE_CONTROL*",
"PCONSOLE_HISTORY_INFO":"CONSOLE_HISTORY_INFO*",
"PCONSOLE_FONT_INFOEX":"CONSOLE_FONT_INFOEX*",
"PCHAR_INFO":"CHAR_INFO*",
"LPWIN32_FIND_DATAW":"WIN32_FIND_DATAW*",
"LPWIN32_FIND_DATAA":"WIN32_FIND_DATAA*",
"LPTIME_ZONE_INFORMATION":"TIME_ZONE_INFORMATION*",
"LPTHREADENTRY32":"THREADENTRY32*",
"LPSYSTEM_INFO":"SYSTEM_INFO*",
"LPPROCESSENTRY32W":"PROCESSENTRY32W*",
"LPPROCESSENTRY32":"PROCESSENTRY32*",
"LPNLSVERSIONINFO":"NLSVERSIONINFO*",
"LPMODULEENTRY32W":"MODULEENTRY32W*",
"LPMODULEENTRY32":"MODULEENTRY32*",
"LPINIT_ONCE":"INIT_ONCE*",
"LPHEAPLIST32":"HEAPLIST32*",
"LPHEAPENTRY32":"HEAPENTRY32*",
"LPCCH":"char*",
"PWOW64_LDT_ENTRY":"WOW64_LDT_ENTRY*",
"PWOW64_CONTEXT":"WOW64_CONTEXT*",
"PVOID*":"VOID**",
"PTP_SIMPLE_CALLBACK":"TP_SIMPLE_CALLBACK*",
"PSYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION":"SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION*",
"PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX":"SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*",
"PSYSTEM_LOGICAL_PROCESSOR_INFORMATION":"SYSTEM_LOGICAL_PROCESSOR_INFORMATION*",
"PSLIST_ENTRY":"SLIST_ENTRY*",
"PPERFORMANCE_DATA":"PERFORMANCE_DATA*",
"PLONG":"LONG*",
"PIO_COUNTERS":"IO_COUNTERS*",
"PINIT_ONCE_FN":"INIT_ONCE_FN*",
"PHANDLER_ROUTINE":"HANDLER_ROUTINE*",
"PFLS_CALLBACK_FUNCTION":"FLS_CALLBACK_FUNCTION*",
"PFILEMUIINFO":"FILEMUIINFO*",
"PCOORD":"COORD*",
"PCONSOLE_SELECTION_INFO":"CONSOLE_SELECTION_INFO*",
"PCONSOLE_SCREEN_BUFFER_INFO":"CONSOLE_SCREEN_BUFFER_INFO*",
"PCONSOLE_FONT_INFO":"CONSOLE_FONT_INFO*",
"PCONSOLE_CURSOR_INFO":"CONSOLE_CURSOR_INFO*",
"PBOOLEAN":"BOOLEAN*",
"PAPCFUNC":"APCFUNC*",
"LPTOP_LEVEL_EXCEPTION_FILTER":"TOP_LEVEL_EXCEPTION_FILTER*",
"LPSYSTEM_POWER_STATUS":"SYSTEM_POWER_STATUS*",
"LPSTARTUPINFOW":"STARTUPINFOW*",
"LPSTARTUPINFOA":"STARTUPINFOA*",
"LPPROCESS_HEAP_ENTRY":"PROCESS_HEAP_ENTRY*",
"LPOVERLAPPED_ENTRY":"OVERLAPPED_ENTRY*",
"LPOSVERSIONINFOW":"OSVERSIONINFOW*",
"LPOSVERSIONINFOEXW":"OSVERSIONINFOEXW*",
"LPOSVERSIONINFOEXA":"OSVERSIONINFOEXA*",
"LPOSVERSIONINFOA":"OSVERSIONINFOA*",
"LPNLSVERSIONINFOEX":"NLSVERSIONINFOEX*",
"LPMEMORYSTATUSEX":"MEMORYSTATUSEX*",
"LPMEMORYSTATUS":"MEMORYSTATUS*",
"LPLONG":"LONG*",
"LPLDT_ENTRY":"LDT_ENTRY*",
"LPHANDLE":"HANDLE*",
"LPFILE_ID_DESCRIPTOR":"FILE_ID_DESCRIPTOR*",
"LPDEBUG_EVENT":"DEBUG_EVENT*",
"LPCPINFOEXW":"CPINFOEXW*",
"LPCPINFOEXA":"CPINFOEXA*",
"LPCPINFO":"CPINFO*",
"LPCONTEXT":"CONTEXT*",
"LPCOMMPROP":"COMMPROP*",
"LPBY_HANDLE_FILE_INFORMATION":"BY_HANDLE_FILE_INFORMATION*",
"SYSTEMTIME":"SYSTEMTIME",
"REGSAM":"REGSAM",
"HFILE":"HFILE",
"USHORT":"USHORT",
"UINT_PTR":"UINT_PTR",
"SMALL_RECT":"SMALL_RECT",
"UCHAR":"uchar",
"LONGLONG":"LONGLONG",
"GUID":"GUID",
"GET_FILEEX_INFO_LEVELS":"GET_FILEEX_INFO_LEVELS",
"GEOID":"GEOID",
"FINDEX_SEARCH_OPS":"FINDEX_SEARCH_OPS",
"FINDEX_INFO_LEVELS":"FINDEX_INFO_LEVELS",
"COMPUTER_NAME_FORMAT":"COMPUTER_NAME_FORMAT",
"CHAR_INFO":"CHAR_INFO",
"ULONGLONG":"ULONGLONG",
"NLS_FUNCTION":"NLS_FUNCTION",
"DWORD_PTR":"DWORD_PTR",
"STREAM_INFO_LEVELS":"STREAM_INFO_LEVELS",
"SECURITY_INFORMATION":"SECURITY_INFORMATION",
"NORM_FORM":"NORM_FORM",
"JOBOBJECTINFOCLASS":"JOBOBJECTINFOCLASS",
"INPUT_RECORD":"INPUT_RECORD",
"HEAP_INFORMATION_CLASS":"HEAP_INFORMATION_CLASS",
"GEOTYPE":"GEOTYPE",
"GEOCLASS":"GEOCLASS",
"FILE_SEGMENT_ELEMENT":"FILE_SEGMENT_ELEMENT",
"FILE_INFO_BY_HANDLE_CLASS":"FILE_INFO_BY_HANDLE_CLASS",
"DWORDLONG":"DWORDLONG",
"EXCEPTION_POINTERS":"EXCEPTION_POINTERS",
"_EXCEPTION_POINTERS":"_EXCEPTION_POINTERS",
"WOW64_CONTEXT":"WOW64_CONTEXT",
"UILANGUAGE_ENUMPROCW":"UILANGUAGE_ENUMPROCW",
"UILANGUAGE_ENUMPROCA":"UILANGUAGE_ENUMPROCA",
"TIMEFMT_ENUMPROCW":"TIMEFMT_ENUMPROCW",
"TIMEFMT_ENUMPROCEX":"TIMEFMT_ENUMPROCEX",
"TIMEFMT_ENUMPROCA":"TIMEFMT_ENUMPROCA",
"NUMBERFMTW":"NUMBERFMTW",
"LOGICAL_PROCESSOR_RELATIONSHIP":"LOGICAL_PROCESSOR_RELATIONSHIP",
"LOCALE_ENUMPROCW":"LOCALE_ENUMPROCW",
"LOCALE_ENUMPROCEX":"LOCALE_ENUMPROCEX",
"LOCALE_ENUMPROCA":"LOCALE_ENUMPROCA",
"LATENCY_TIME":"LATENCY_TIME",
"LANGUAGEGROUP_ENUMPROCW":"LANGUAGEGROUP_ENUMPROCW",
"LANGUAGEGROUP_ENUMPROCA":"LANGUAGEGROUP_ENUMPROCA",
"GROUP_AFFINITY":"GROUP_AFFINITY",
"GEO_ENUMPROC":"GEO_ENUMPROC",
"EXECUTION_STATE":"EXECUTION_STATE",
"DYNAMIC_TIME_ZONE_INFORMATION":"DYNAMIC_TIME_ZONE_INFORMATION",
"CURRENCYFMTW":"CURRENCYFMTW",
"CONTEXT":"CONTEXT",
"CONSOLE_CURSOR_INFO":"CONSOLE_CURSOR_INFO",
"CHAR":"char",
"APPLICATION_RECOVERY_CALLBACK":"APPLICATION_RECOVERY_CALLBACK",
"HRESULT":"HRESULT",
"PCNZCH":"char*",
"LPPROCESS_INFORMATION":"PROCESS_INFORMATION*",
"LPINT":"int*",
"LSTATUS":"LSTATUS",
"DEP_SYSTEM_POLICY_TYPE":"DEP_SYSTEM_POLICY_TYPE",
"CURRENCYFMTA":"CURRENCYFMTA",
"va_list":"va_list",
"NTSTATUS":"NTSTATUS",
"TRACEHANDLE":"TRACEHANDLE",
"LSA_HANDLE":"LSA_HANDLE",
"HCRYPTHASH":"HCRYPTHASH",
"HCRYPTKEY":"HCRYPTKEY",
"PGENERIC_MAPPING":"GENERIC_MAPPING*",
"PTRUSTEE_W":"TRUSTEE_W*",
"PTRUSTEE_A":"TRUSTEE_A*",
"HCRYPTPROV":"HCRYPTPROV",
"LPCGUID":"GUID*",
"PLSA_UNICODE_STRING":"LSA_UNICODE_STRING*",
"SE_OBJECT_TYPE":"SE_OBJECT_TYPE",
"PEVENT_TRACE_PROPERTIES":"EVENT_TRACE_PROPERTIES*",
"PPRIVILEGE_SET":"PRIVILEGE_SET*",
"PPERF_COUNTERSET_INSTANCE":"PERF_COUNTERSET_INSTANCE*",
"POBJECT_TYPE_LIST":"OBJECT_TYPE_LIST*",
"PEXPLICIT_ACCESS_W":"EXPLICIT_ACCESS_W*",
"PEXPLICIT_ACCESS_A":"EXPLICIT_ACCESS_A*",
"SAFER_LEVEL_HANDLE":"SAFER_LEVEL_HANDLE",
"REGHANDLE":"REGHANDLE",
"LPGUID":"GUID*",
"PCREDENTIALW":"CREDENTIALW*",
"PCREDENTIALA":"CREDENTIALA*",
"PACCESS_MASK":"ACCESS_MASK*",
"AUDIT_EVENT_TYPE":"AUDIT_EVENT_TYPE",
"PTRACEHANDLE":"TRACEHANDLE*",
"PLUID":"LUID*",
"PENCRYPTION_CERTIFICATE_HASH_LIST":"ENCRYPTION_CERTIFICATE_HASH_LIST*",
"TRUSTED_INFORMATION_CLASS":"TRUSTED_INFORMATION_CLASS",
"PSID_NAME_USE":"SID_NAME_USE*",
"PROG_INVOKE_SETTING":"PROG_INVOKE_SETTING",
"PCEVENT_DESCRIPTOR":"EVENT_DESCRIPTOR*",
"PBYTE":"BYTE*",
"PAUDIT_POLICY_INFORMATION":"AUDIT_POLICY_INFORMATION*",
"FN_PROGRESS":"FN_PROGRESS",
"CRED_PROTECTION_TYPE":"CRED_PROTECTION_TYPE",
"ACCESS_MODE":"ACCESS_MODE",
"SECURITY_IMPERSONATION_LEVEL":"SECURITY_IMPERSONATION_LEVEL",
"PSID_IDENTIFIER_AUTHORITY":"SID_IDENTIFIER_AUTHORITY*",
"PLSA_REFERENCED_DOMAIN_LIST":"LSA_REFERENCED_DOMAIN_LIST*",
"PLSA_HANDLE":"LSA_HANDLE*",
"PFN_OBJECT_MGR_FUNCTS":"FN_OBJECT_MGR_FUNCTS*",
"PEVENT_INSTANCE_INFO":"EVENT_INSTANCE_INFO*",
"PEVENT_DATA_DESCRIPTOR":"EVENT_DATA_DESCRIPTOR*",
"PENCRYPTION_CERTIFICATE":"ENCRYPTION_CERTIFICATE*",
"PCREDENTIAL_TARGET_INFORMATIONW":"CREDENTIAL_TARGET_INFORMATIONW*",
"PCREDENTIAL_TARGET_INFORMATIONA":"CREDENTIAL_TARGET_INFORMATIONA*",
"LPSERVICE_STATUS":"SERVICE_STATUS*",
"HWCT":"HWCT",
"ALG_ID":"ALG_ID",
"ACCESS_MASK":"ACCESS_MASK",
"WMIDPREQUEST":"WMIDPREQUEST",
"WELL_KNOWN_SID_TYPE":"WELL_KNOWN_SID_TYPE",
"TRUSTEE_TYPE":"TRUSTEE_TYPE",
"TRUSTEE_FORM":"TRUSTEE_FORM",
"TOKEN_INFORMATION_CLASS":"TOKEN_INFORMATION_CLASS",
"SECURITY_DESCRIPTOR_CONTROL":"SECURITY_DESCRIPTOR_CONTROL",
"SC_LOCK":"SC_LOCK",
"SC_ENUM_TYPE":"SC_ENUM_TYPE",
"SAFER_POLICY_INFO_CLASS":"SAFER_POLICY_INFO_CLASS",
"SAFER_OBJECT_INFO_CLASS":"SAFER_OBJECT_INFO_CLASS",
"PTRACE_GUID_REGISTRATION":"TRACE_GUID_REGISTRATION*",
"PTOKEN_PRIVILEGES":"TOKEN_PRIVILEGES*",
"PTOKEN_GROUPS":"TOKEN_GROUPS*",
"PSID_AND_ATTRIBUTES":"SID_AND_ATTRIBUTES*",
"PSAMPR_ENCRYPTED_USER_PASSWORD":"SAMPR_ENCRYPTED_USER_PASSWORD*",
"PQUOTA_LIMITS":"QUOTA_LIMITS*",
"POLICY_INFORMATION_CLASS":"POLICY_INFORMATION_CLASS",
"POLICY_DOMAIN_INFORMATION_CLASS":"POLICY_DOMAIN_INFORMATION_CLASS",
"POBJECTS_AND_SID":"OBJECTS_AND_SID*",
"PNT_OWF_PASSWORD":"NT_OWF_PASSWORD*",
"PLSA_FOREST_TRUST_INFORMATION":"LSA_FOREST_TRUST_INFORMATION*",
"PLSA_ENUMERATION_HANDLE":"LSA_ENUMERATION_HANDLE*",
"PLM_OWF_PASSWORD":"LM_OWF_PASSWORD*",
"PINHERITED_FROMW":"INHERITED_FROMW*",
"PERFLIBREQUEST":"PERFLIBREQUEST",
"PCSTR":"char*",
"PCRED_MARSHAL_TYPE":"CRED_MARSHAL_TYPE*",
"PCAUDIT_POLICY_INFORMATION":"AUDIT_POLICY_INFORMATION*",
"MULTIPLE_TRUSTEE_OPERATION":"MULTIPLE_TRUSTEE_OPERATION",
"LPHANDLER_FUNCTION_EX":"HANDLER_FUNCTION_EX*",
"LPHANDLER_FUNCTION":"HANDLER_FUNCTION*",
"LPENUM_SERVICE_STATUSW":"ENUM_SERVICE_STATUSW*",
"LPENUM_SERVICE_STATUSA":"ENUM_SERVICE_STATUSA*",
"CRED_MARSHAL_TYPE":"CRED_MARSHAL_TYPE",
"ACL_INFORMATION_CLASS":"ACL_INFORMATION_CLASS",
"ULONG64":"ULONG64",
"TRACE_QUERY_INFO_CLASS":"TRACE_QUERY_INFO_CLASS",
"TRACE_INFO_CLASS":"TRACE_INFO_CLASS",
"TOKEN_TYPE":"TOKEN_TYPE",
"SERVICE_TABLE_ENTRYW":"SERVICE_TABLE_ENTRYW",
"SERVICE_TABLE_ENTRYA":"SERVICE_TABLE_ENTRYA",
"SC_STATUS_TYPE":"SC_STATUS_TYPE",
"PWAITCHAIN_NODE_INFO":"WAITCHAIN_NODE_INFO*",
"PWAITCHAINCALLBACK":"WAITCHAINCALLBACK*",
"PVALENTW":"VALENTW*",
"PVALENTA":"VALENTA*",
"PTRUSTED_DOMAIN_INFORMATION_EX":"TRUSTED_DOMAIN_INFORMATION_EX*",
"PTRUSTED_DOMAIN_AUTH_INFORMATION":"TRUSTED_DOMAIN_AUTH_INFORMATION*",
"PTRACE_GUID_PROPERTIES":"TRACE_GUID_PROPERTIES*",
"PSERVICE_NOTIFYW":"SERVICE_NOTIFYW*",
"PSERVICE_NOTIFYA":"SERVICE_NOTIFYA*",
"PSECURITY_DESCRIPTOR_CONTROL":"SECURITY_DESCRIPTOR_CONTROL*",
"PSAFER_CODE_PROPERTIES":"SAFER_CODE_PROPERTIES*",
"PREGHANDLE":"REGHANDLE*",
"PPOLICY_AUDIT_SID_ARRAY":"POLICY_AUDIT_SID_ARRAY*",
"PPOLICY_AUDIT_EVENT_TYPE":"POLICY_AUDIT_EVENT_TYPE*",
"PPERF_PROVIDER_CONTEXT":"PERF_PROVIDER_CONTEXT*",
"PPERF_COUNTERSET_INFO":"PERF_COUNTERSET_INFO*",
"POLICY_AUDIT_EVENT_TYPE":"POLICY_AUDIT_EVENT_TYPE",
"POBJECTS_AND_NAME_W":"OBJECTS_AND_NAME_W*",
"POBJECTS_AND_NAME_A":"OBJECTS_AND_NAME_A*",
"PMANAGEDAPPLICATION":"MANAGEDAPPLICATION*",
"PLUID_AND_ATTRIBUTES":"LUID_AND_ATTRIBUTES*",
"PLSA_TRANSLATED_SID2":"LSA_TRANSLATED_SID2*",
"PLSA_TRANSLATED_SID":"LSA_TRANSLATED_SID*",
"PLSA_TRANSLATED_NAME":"LSA_TRANSLATED_NAME*",
"PLSA_OBJECT_ATTRIBUTES":"LSA_OBJECT_ATTRIBUTES*",
"PLSA_FOREST_TRUST_COLLISION_INFORMATION":"LSA_FOREST_TRUST_COLLISION_INFORMATION*",
"PLOCALMANAGEDAPPLICATION":"LOCALMANAGEDAPPLICATION*",
"PINSTALLDATA":"INSTALLDATA*",
"PINHERITED_FROMA":"INHERITED_FROMA*",
"PFE_IMPORT_FUNC":"FE_IMPORT_FUNC*",
"PFE_EXPORT_FUNC":"FE_EXPORT_FUNC*",
"PEVENT_TRACE_LOGFILEW":"EVENT_TRACE_LOGFILEW*",
"PEVENT_TRACE_LOGFILEA":"EVENT_TRACE_LOGFILEA*",
"PEVENT_TRACE_HEADER":"EVENT_TRACE_HEADER*",
"PEVENT_INSTANCE_HEADER":"EVENT_INSTANCE_HEADER*",
"PEVENT_FILTER_DESCRIPTOR":"EVENT_FILTER_DESCRIPTOR*",
"PEVENT_CALLBACK":"EVENT_CALLBACK*",
"PENCRYPTION_CERTIFICATE_LIST":"ENCRYPTION_CERTIFICATE_LIST*",
"PENCRYPTION_CERTIFICATE_HASH":"ENCRYPTION_CERTIFICATE_HASH*",
"PENCRYPTED_NT_OWF_PASSWORD":"ENCRYPTED_NT_OWF_PASSWORD*",
"PENCRYPTED_LM_OWF_PASSWORD":"ENCRYPTED_LM_OWF_PASSWORD*",
"PENABLE_TRACE_PARAMETERS":"ENABLE_TRACE_PARAMETERS*",
"PENABLECALLBACK":"ENABLECALLBACK*",
"PCOGETCALLSTATE":"COGETCALLSTATE*",
"PCOGETACTIVATIONSTATE":"COGETACTIVATIONSTATE*",
"LPQUERY_SERVICE_LOCK_STATUSW":"QUERY_SERVICE_LOCK_STATUSW*",
"LPQUERY_SERVICE_LOCK_STATUSA":"QUERY_SERVICE_LOCK_STATUSA*",
"LPQUERY_SERVICE_CONFIGW":"QUERY_SERVICE_CONFIGW*",
"LPQUERY_SERVICE_CONFIGA":"QUERY_SERVICE_CONFIGA*",
"LPHW_PROFILE_INFOW":"HW_PROFILE_INFOW*",
"LPHW_PROFILE_INFOA":"HW_PROFILE_INFOA*",
"APPCATEGORYINFOLIST":"APPCATEGORYINFOLIST",
"PACL": "ACL*",
"LPSIZE":"SIZE*",
"LPPOINT":"POINT*",
"RECT":"RECT",
"XFORM":"XFORM",
"FLOAT":"FLOAT",
"POINT":"POINT",
"LPRECT":"RECT*",
"LPABC":"ABC*",
"FONTENUMPROCW":"FONTENUMPROCW",
"FONTENUMPROCA":"FONTENUMPROCA",
"RGBQUAD":"RGBQUAD",
"PIXELFORMATDESCRIPTOR":"PIXELFORMATDESCRIPTOR",
"PFLOAT":"FLOAT*",
"PALETTEENTRY":"PALETTEENTRY",
"MAT2":"MAT2",
"LPXFORM":"XFORM*",
"LPPALETTEENTRY":"PALETTEENTRY*",
"LPLOGCOLORSPACEW":"LOGCOLORSPACEW*",
"LPLOGCOLORSPACEA":"LOGCOLORSPACEA*",
"LPKERNINGPAIR":"KERNINGPAIR*",
"LPHANDLETABLE":"HANDLETABLE*",
"LPGLYPHMETRICS":"GLYPHMETRICS*",
"LPABCFLOAT":"ABCFLOAT*",
"LOGBRUSH":"LOGBRUSH",
"GOBJENUMPROC":"GOBJENUMPROC",
"DEVMODEW":"DEVMODEW",
"DEVMODEA":"DEVMODEA",
"D2D1_SIZE_U":"D2D1_SIZE_U",
"D2D1_BITMAP_PROPERTIES":"D2D1_BITMAP_PROPERTIES",
"UINT32":"UINT32",
"RGNDATA":"RGNDATA",
"PTRIVERTEX":"TRIVERTEX*",
"MFENUMPROC":"MFENUMPROC",
"METAFILEPICT":"METAFILEPICT",
"LPTEXTMETRICW":"TEXTMETRICW*",
"LPTEXTMETRICA":"TEXTMETRICA*",
"LPRGNDATA":"RGNDATA*",
"LPRGBTRIPLE":"RGBTRIPLE*",
"LPRASTERIZER_STATUS":"RASTERIZER_STATUS*",
"LPPIXELFORMATDESCRIPTOR":"PIXELFORMATDESCRIPTOR*",
"LPOUTLINETEXTMETRICW":"OUTLINETEXTMETRICW*",
"LPOUTLINETEXTMETRICA":"OUTLINETEXTMETRICA*",
"LPMETARECORD":"METARECORD*",
"LPLOGFONTW":"LOGFONTW*",
"LPLOGFONTA":"LOGFONTA*",
"LPGLYPHSET":"GLYPHSET*",
"LPGCP_RESULTSW":"GCP_RESULTSW*",
"LPGCP_RESULTSA":"GCP_RESULTSA*",
"LPFONTSIGNATURE":"FONTSIGNATURE*",
"LPENHMETAHEADER":"ENHMETAHEADER*",
"LPCOLORADJUSTMENT":"COLORADJUSTMENT*",
"LPCHARSETINFO":"CHARSETINFO*",
"LOGPEN":"LOGPEN",
"LOGPALETTE":"LOGPALETTE",
"LOGFONTW":"LOGFONTW",
"LOGFONTA":"LOGFONTA",
"LINEDDAPROC":"LINEDDAPROC",
"ICMENUMPROCW":"ICMENUMPROCW",
"ICMENUMPROCA":"ICMENUMPROCA",
"ENUMLOGFONTEXDVW":"ENUMLOGFONTEXDVW",
"ENUMLOGFONTEXDVA":"ENUMLOGFONTEXDVA",
"ENHMFENUMPROC":"ENHMFENUMPROC",
"ENHMETARECORD":"ENHMETARECORD",
"D2D1_POINT_2F":"D2D1_POINT_2F",
"D2D1_ELLIPSE":"D2D1_ELLIPSE",
"COLORADJUSTMENT":"COLORADJUSTMENT",
"BITMAPINFOHEADER":"BITMAPINFOHEADER",
"BITMAPINFO":"BITMAPINFO",
"BITMAP":"BITMAP",
"REAL":"REAL",
"RDN":"RDN",
"POLYTEXTW":"POLYTEXTW",
"POLYTEXTA":"POLYTEXTA",
"LPCWCH":"wchar*",
"DOCINFOW":"DOCINFOW",
"DOCINFOA":"DOCINFOA",
"BLENDFUNCTION":"BLENDFUNCTION",
"ABORTPROC":"ABORTPROC",
"void":"void",
"SURFOBJ":"SURFOBJ",
"CLIPOBJ":"CLIPOBJ",
"POINTL":"POINTL",
"RECTL":"RECTL",
"BRUSHOBJ":"BRUSHOBJ",
"XLATEOBJ":"XLATEOBJ",
"PATHOBJ":"PATHOBJ",
"FONTOBJ":"FONTOBJ",
"FLONG":"FLONG",
"STROBJ":"STROBJ",
"MIX":"MIX",
"XFORMOBJ":"XFORMOBJ",
"HSURF":"HSURF",
"SIZEL":"SIZEL",
"LINEATTRS":"LINEATTRS",
"ROP4":"ROP4",
"PGLYPHPOS":"GLYPHPOS*",
"HGLYPH":"HGLYPH",
"DHSURF":"DHSURF",
"XFORML":"XFORML",
"TRIVERTEX":"TRIVERTEX",
"PRECTFX":"RECTFX*",
"PPOLYPATBLT":"POLYPATBLT*",
"POINTQF":"POINTQF",
"POINTFIX":"POINTFIX",
"PCHWIDTHINFO":"CHWIDTHINFO*",
"PATHDATA":"PATHDATA",
"LPMAT2":"MAT2*",
"KERNINGPAIR":"KERNINGPAIR",
"HDEV":"HDEV",
"FONT_FILE_INFO":"FONT_FILE_INFO",
"FONTINFO":"FONTINFO",
"EXTTEXTMETRIC":"EXTTEXTMETRIC",
"CLIPLINE":"CLIPLINE",
"BLENDOBJ":"BLENDOBJ",}


tokens_ignore_prefix = {"APIENTRY", "virtual", "DECLSPEC_NORETURN", "__kernel_entry",
"W32KAPI", "WINGDIAPI", "__gdi_entry", "WMIAPI", "EXTERN_C", "WINADVAPI", "extern",
"D2D1FORCEINLINE", "__kernel_entry"}

unknown_types = dict() # We use this dictionary to save and print a list of unknown types.

def remove_internal_parentheses(str):
    while True: # the all parentheses in the string
        end = str.find(")") # find the last parenthesis
        if end == -1: # exit in case of no parenthesis
            break
        start = str.rfind("(", 0, end) # looking back for the first parenthesis
        if start == -1: # exit in case of no parenthesis
            break
        new_str = str[:start] # remove everything after (
        new_str += str[end+1:] # remove everything before )
        str = new_str
    return str

def get_type(type_str):
    return str(types_map.get(type_str, None))

def parse_return_type(line):
    '''
    The function searches for a WinAPI return type in the string specified.
    The caller should remove function name and arguments from the line.
    @in line - a string with a type to find.
    @out - returning type.
    '''
    if ")" in line:
        line = remove_internal_parentheses(line)

    line = line.split(" ")
    func_type = None
    type_token_count = 0
    for element in line:
        if element in tokens_ignore_prefix or element == "" or "__" in element\
           or (("WIN" in element or "NT" in element) and "API" in element):
            continue
        # Let's return "None" if we have more than 2 tokens that look like candidates for
        # the return type.
        if type_token_count >= 1:
            print "Warning. Failed to parse line %s (%s)" % (line, element)
            return "None"
        func_type = element
        type_token_count += 1

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
    '''
    The function searches for a WinAPI function arguments in the string specified.
    The caller should remove return type and function name from the args_str.
    @in args_str - a string with arguments to find.
    @out - a list of arguments separated by |.
    '''
    no_type = 0
    out_type = 1
    inout_type = 2
    args_str = args_str.replace("\n", "")
    args_str = args_str.replace(");", "")
    if ")" in args_str:
        args_str = remove_internal_parentheses(args_str)
    args_str = args_str.replace("(", "")
    args = args_str.split(",")
    res_types = list()
    for arg in args:
        arg = arg.split(" ")
        param_type = no_type
        res_type = "None"
        pointers_count = 0
        for element in arg:
            if element == "CONST":
                continue
            if "__out" in element or "__deref_out" in element\
               or "__deref_opt_out_opt" in element or "__deref_opt_out" in element:
                param_type = out_type
                continue
            elif "__inout" in element:
                param_type = inout_type
                continue
            pointers_count_tmp = element.count("*")
            if  element.count("*") > 0:
                pointers_count = pointers_count_tmp
                element = element.replace("*", "")
            type = get_type(element) # if type is unknown we have None string
            if type == "None":
                try:
                    unknown_types[element] += 1
                except:
                    unknown_types[element] = 1
            else:
                res_type = type
        if res_type != "None":
            if param_type == out_type:
                res_type = "+" + res_type # equals __out
            elif param_type ==  inout_type:
                res_type = "++" + res_type # equals __inout
            if pointers_count > 0:
                res_type += "*" * pointers_count
        res_types.append(str(res_type))
    return_string = "|".join(res_types)
    return_string = return_string.replace("++", "__inout ")
    return_string = return_string.replace("+", "__out ")
    return return_string

def parse_line(line, name):
    '''
    The function starts parsing of the line specified.
    @in line - a line to parse.
    @in name - a name of WinAPI function.
    @out - a string with a function return type, name and arguments separated by |.
    '''

    prefix = line[:line.find(name)]
    suffix = line[line.find(name)+len(name) + 1:]
    new_prefix = parse_return_type(prefix)
    args = parse_args(suffix)
    return "%s|%s|%s" % (new_prefix, name, args)

def check_api_exist(api_name, prototype_line):
    ''' The function checks whether api_name exists in prototype_line.
    In some cases, Windows has specific prefix for some API entries (e.g. NtGdi, NtUser).
    We have to take into account that here.
    @in api_name - a name of WinAPI function to look for.
    @in prototype_line - a prototype string to look in.
    @out - 1 if api_name exists in prototype_line and 0 otherwise.
    '''
    prototype_line = prototype_line[:-1]
    prototype_line = prototype_line.split(" ")
    for element in prototype_line:
        element = element[:element.find("(")]
        if element == api_name or element == "NtGdi" + api_name:
            return 1
    return 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "The script is used for searching of"
" WinAPI function prototypes in the output of headers_parser.py and converting them into"
" the format supported by drltrace.")
    parser.add_argument('-results_path', help = "The path where headers_parser.py saved results.",
    default = "results\\")
    parser.add_argument('-parse_specific_file', help = "The option is used to specify for"
" the script only a single file")

    args = parser.parse_args()

    export_files = list()
    if args.parse_specific_file == None:
        print "Parsing all files from %s" % args.results_path
        export_files = [f for f in listdir(args.results_path) if isfile(join(args.results_path, f))]
    else:
        print "Parsing %s from %s" % (args.parse_specific_file, args.results_path)
        if not args.parse_specific_file.endswith(".headers_out"):
            print "File should end with *.headers_out"
            sys.exit(-1)
        export_files.append(args.parse_specific_file)

    for file in export_files:
        if not file.endswith(".headers_out"): # parse only output of headers_parser.py
            continue
        content = open(args.results_path + file, 'r').readlines()
        file_write = open(file + ".config_raw", 'w') # the output file
        file_write.write("The result is not a final config. Manual analysis is required\n")

        for line in content:
            line = line[:-1]
            # The headers_parser.py saves possible prototypes using the following pattern:
            # [exported function name] -> [possible return types] [function name found]([args])
            # where [exported function name] is a name of function we are searching for.
            if "->" not in line or "(This)->" in line:
                continue

            # parse line
            line = line.replace("[DUPLICATE]", "") # parse duplicates as well
            line_splitted = line.split(" -> ")
            if len(line_splitted) <= 1:
                continue
            name = line_splitted[0]
            function_str = line_splitted[1]
            # The headers_parser.py searches for all occurences of exported API name in
            # a line of SDK header. As a result, there are entries where exported API name
            # is a substring of some API call. We have to filter out such entries using
            # check_api_entries function.
            if check_api_exist(name, function_str) == 0:
                continue
            final_str = parse_line(function_str, name)
            file_write.write(line + "\n")
            file_write.write(final_str + "\n\n")

    result = sorted( ((v,k) for k,v in unknown_types.iteritems()), reverse=True)
    final_line = ""
    for count, element in result:
        if element.isupper(): # Types in Windows are usually in uppercase.
            final_line += "\"%s\":\"%s\", " % (element, element)
    file_write.write(final_line + "\n")
    file_write.close()
