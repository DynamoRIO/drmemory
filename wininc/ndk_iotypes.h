/****************************************************************************
 ****************************************************************************
 ***
 ***   This header was generated from a ReactOS header to make
 ***   information necessary for userspace to call into the Windows
 ***   kernel available to Dr. Memory.  It contains only constants,
 ***   structures, and macros generated from the original header, and
 ***   thus, contains no copyrightable information.
 ***
 ****************************************************************************
 ****************************************************************************/

/* from reactos/include/ndk/iotypes.h */

#ifndef _IOTYPES_H
#define _IOTYPES_H

//
// Firmware Boot File Path
//
typedef struct _FILE_PATH
{
    ULONG Version;
    ULONG Length;
    ULONG Type;
    CHAR FilePath[1];
} FILE_PATH, *PFILE_PATH;

//
// Firmware Boot Options
//
typedef struct _BOOT_OPTIONS
{
    ULONG Version;
    ULONG Length;
    ULONG Timeout;
    ULONG CurrentBootEntryId;
    ULONG NextBootEntryId;
    WCHAR HeadlessRedirection[1];
} BOOT_OPTIONS, *PBOOT_OPTIONS;

#endif /* _IOTYPES_H */
