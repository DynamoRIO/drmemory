/****************************************************************************
 ****************************************************************************
 ***
 ***   This header was created to make information necessary for userspace
 ***   to call into the Windows kernel available to Dr. Memory.  It contains 
 ***   only constants, structures, and macros, and thus, contains no 
 ***   copyrightable information.
 ***
 ****************************************************************************
 ****************************************************************************/

#ifndef _NTEXAPI_H_
#define _NTEXAPI_H_ 1

NTSTATUS NTAPI
NtEnumerateBootEntries(
    __out_bcount_opt(*BufferLength) PVOID Buffer,
    __inout PULONG BufferLength
    );

NTSTATUS NTAPI
NtEnumerateDriverEntries(
    __out_bcount(*BufferLength) PVOID Buffer,
    __inout PULONG BufferLength
    );

NTSTATUS NTAPI
NtEnumerateSystemEnvironmentValuesEx(
    __in ULONG InformationClass,
    __out PVOID Buffer,
    __inout PULONG BufferLength
    );

NTSTATUS NTAPI
NtQueryBootEntryOrder(
    __out_ecount_opt(*Count) PULONG Ids,
    __inout PULONG Count
    );

NTSTATUS NTAPI
NtQueryBootOptions(
    __out_bcount_opt(*BootOptionsLength) PBOOT_OPTIONS BootOptions,
    __inout PULONG BootOptionsLength
    );

NTSTATUS NTAPI
NtQueryDriverEntryOrder(
    __out_ecount(*Count) PULONG Ids,
    __inout PULONG Count
    );

NTSTATUS NTAPI
NtQuerySystemEnvironmentValueEx(
    __in PUNICODE_STRING VariableName,
    __in LPGUID VendorGuid,
    __out_bcount_opt(*ValueLength) PVOID Value,
    __inout PULONG ValueLength,
    __out_opt PULONG Attributes
    );

NTSTATUS NTAPI
NtSetBootEntryOrder(
    __in_ecount(Count) PULONG Ids,
    __in ULONG Count
    );

NTSTATUS NTAPI
NtSetDriverEntryOrder(
    __in_ecount(Count) PULONG Ids,
    __in ULONG Count
    );

NTSTATUS
NTAPI
NtQuerySystemInformationEx(
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __in_bcount(QueryInformationLength) PVOID QueryInformation,
    __in ULONG QueryInformationLength,
    __out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
    );

#endif /* _NTEXAPI_H_ 1 */
