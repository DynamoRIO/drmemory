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

#ifndef __PHLIB_NTMISC_H
#define __PHLIB_NTMISC_H

NTSTATUS NTAPI
NtDrawText(
    __in PUNICODE_STRING Text
    );

#endif /* __PHLIB_NTMISC_H */

/* EOF */