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

NTSTATUS NTAPI
NtSetDriverEntryOrder(
    __in_ecount(Count) PULONG Ids,
    __in ULONG Count
    );
