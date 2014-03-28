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

 /* from phlib/include/ntioapi.h */

#ifndef __PHLIB_NTIOAPI_H
#define __PHLIB_NTIOAPI_H

NTSTATUS NTAPI
NtDisableLastKnownGood(
    VOID
    );

NTSTATUS NTAPI
NtEnableLastKnownGood(
    VOID
    );

#endif /* __PHLIB_NTIOAPI_H */

/* EOF */