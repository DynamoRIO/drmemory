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

#endif /* __PHLIB_NTMMAPI_H */

/* EOF */