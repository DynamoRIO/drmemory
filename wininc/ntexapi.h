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

NTSTATUS
NTAPI
NtInitializeNlsFiles(
    __out PVOID *BaseAddress,
    __out PLCID DefaultLocaleId,
    __out PLARGE_INTEGER DefaultCasingTableSize
    );
	
NTSTATUS
NTAPI
NtAcquireCMFViewOwnership(
    __out PULONGLONG TimeStamp,
    __out PBOOLEAN tokenTaken,
    __in BOOLEAN replaceExisting
    );

NTSTATUS
NTAPI
NtCreateProfileEx(
    __out PHANDLE ProfileHandle,
    __in_opt HANDLE Process,
    __in PVOID ProfileBase,
    __in SIZE_T ProfileSize,
    __in ULONG BucketSize,
    __in PULONG Buffer,
    __in ULONG BufferSize,
    __in KPROFILE_SOURCE ProfileSource,
    __in ULONG GroupAffinityCount,
    __in_opt PGROUP_AFFINITY GroupAffinity
    );

NTSTATUS
NTAPI
NtCreateWorkerFactory(
    __out PHANDLE WorkerFactoryHandleReturn,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in HANDLE CompletionPortHandle,
    __in HANDLE WorkerProcessHandle,
    __in PVOID StartRoutine,
    __in_opt PVOID StartParameter,
    __in_opt ULONG MaxThreadCount,
    __in_opt SIZE_T StackReserve,
    __in_opt SIZE_T StackCommit
    );

NTSTATUS
NTAPI
NtFlushInstallUILanguage(
    __in LANGID InstallUILanguage,
    __in ULONG SetComittedFlag
    );

NTSTATUS
NTAPI
NtGetMUIRegistryInfo(
    __in ULONG Flags,
    __inout PULONG DataSize,
    __out PVOID Data
    );

NTSTATUS
NTAPI
NtGetNlsSectionPtr(
    __in ULONG SectionType,
    __in ULONG SectionData,
    __in PVOID ContextData,
    __out PVOID *SectionPointer,
    __out PULONG SectionSize
    );

NTSTATUS
NTAPI
NtIsUILanguageComitted(
    VOID
    );

NTSTATUS
NTAPI
NtReleaseCMFViewOwnership(
    VOID
    );

NTSTATUS
NTAPI
NtReleaseWorkerFactoryWorker(
    __in HANDLE WorkerFactoryHandle
    );
	
NTSTATUS
NTAPI
NtWorkerFactoryWorkerReady(
    __in HANDLE WorkerFactoryHandle
    );
	

#endif /* _NTEXAPI_H_ 1 */
