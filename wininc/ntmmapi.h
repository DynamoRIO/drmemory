/****************************************************************************
 ****************************************************************************
 ***
 ***   This header was created from a ProcessHacker header to make
 ***   information necessary for userspace to call into the Windows
 ***   kernel available to Dr. Memory.  It contains only constants,
 ***   structures, and macros generated from the original header, and
 ***   thus, contains no copyrightable information.
 ***
 ****************************************************************************
 ****************************************************************************/
/* from phlib/include/ntmisc.h */

#ifndef __PHLIB_NTMMAPI_H
#define __PHLIB_NTMMAPI_H

NTSTATUS
NTAPI
NtOpenSession(
    __out PHANDLE SessionHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSTATUS
NTAPI
NtNotifyChangeSession(
    __in HANDLE SessionHandle,
    __in ULONG IoStateSequence,
    __in PVOID Reserved,
    __in ULONG Action,
    __in IO_SESSION_STATE IoState,
    __in IO_SESSION_STATE IoState2,
    __in PVOID Buffer,
    __in ULONG BufferSize
    );

#endif /* __PHLIB_NTMMAPI_H */

/* EOF */