/****************************************************************************
 ****************************************************************************
 ***
 ***   This header was generated from a ProcessHacker header to make
 ***   information necessary for userspace to call into the Windows
 ***   kernel available to Dr. Memory.  It contains only constants,
 ***   structures, and macros generated from the original header, and
 ***   thus, contains no copyrightable information.
 ***
 ****************************************************************************
 ****************************************************************************/

/* from phlib/include/ntpsapi.h */

#ifndef __PHLIB_NTPSAPI_H
#define __PHLIB_NTPSAPI_H

/**************************************************
 * Syscalls added in Win7
 */
NTSTATUS NTAPI
NtAllocateReserveObject(
    __out PHANDLE MemoryReserveHandle,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in MEMORY_RESERVE_TYPE Type
    );

#endif /* __PHLIB_NTPSAPI_H */

/* EOF */
