/* This header contains typedefs and prototypes for some ntdll routines.
 *
 * This type information was originally reverse engineered by the Process Hacker
 * project.  This header only contains typedefs, prototypes, and constants, and
 * thus contains no copyrightable information.
 *
 * Project page: http://processhacker.sourceforge.net/
 * Original source: http://processhacker.svn.sourceforge.net/viewvc/
 *   processhacker/2.x/trunk/phlib/include/ntrtl.h?view=markup
 */

#ifdef RTL_MEMORY_ZONES_H_
# error "Cannot include this file multiple times."
#endif
#define RTL_MEMORY_ZONES_H_

#include <windows.h>

typedef LONG NTSTATUS;

/* Memory zone routines and types.  These seem to implement a straightforward
 * pool allocator on top of NtAllocateVirtualMemory that does not grow.
 * When creating a memory zone, we make a minimum space request, and the size of
 * the bookkeeping data structure is added to it and rounded up to the next page
 * boundary.  We can allocate memory beyond the amount we requested but after we
 * hit the next page boundary it will not allocate more blocks.
 */

typedef struct _RTL_MEMORY_ZONE_SEGMENT
{
    struct _RTL_MEMORY_ZONE_SEGMENT *NextSegment;
    SIZE_T Size;
    PVOID Next;
    PVOID Limit;
} RTL_MEMORY_ZONE_SEGMENT, *PRTL_MEMORY_ZONE_SEGMENT;

typedef struct _RTL_MEMORY_ZONE
{
    RTL_MEMORY_ZONE_SEGMENT Segment;
    RTL_SRWLOCK Lock;
    ULONG LockCount;
    PRTL_MEMORY_ZONE_SEGMENT FirstSegment;
} RTL_MEMORY_ZONE, *PRTL_MEMORY_ZONE;

NTSTATUS
(NTAPI *RtlCreateMemoryZone)(
    __out PVOID *MemoryZone,
    __in SIZE_T InitialSize,
    __reserved ULONG Flags
    );

NTSTATUS
(NTAPI *RtlDestroyMemoryZone)(
    __in __post_invalid PVOID MemoryZone
    );

NTSTATUS
(NTAPI *RtlAllocateMemoryZone)(
    __in PVOID MemoryZone,
    __in SIZE_T BlockSize,
    __out PVOID *Block
    );

NTSTATUS
(NTAPI *RtlResetMemoryZone)(
    __in PVOID MemoryZone
    );

NTSTATUS
(NTAPI *RtlLockMemoryZone)(
    __in PVOID MemoryZone
    );

NTSTATUS
(NTAPI *RtlUnlockMemoryZone)(
    __in PVOID MemoryZone
    );

/* Memory block lookaside routines.
 */

NTSTATUS
(NTAPI *RtlCreateMemoryBlockLookaside)(
    __out PVOID *MemoryBlockLookaside,
    __reserved ULONG Flags,
    __in ULONG InitialSize,
    __in ULONG MinimumBlockSize,
    __in ULONG MaximumBlockSize
    );

NTSTATUS
(NTAPI *RtlDestroyMemoryBlockLookaside)(
    __in PVOID MemoryBlockLookaside
    );

NTSTATUS
(NTAPI *RtlAllocateMemoryBlockLookaside)(
    __in PVOID MemoryBlockLookaside,
    __in ULONG BlockSize,
    __out PVOID *Block
    );

NTSTATUS
(NTAPI *RtlFreeMemoryBlockLookaside)(
    __in PVOID MemoryBlockLookaside,
    __in PVOID Block
    );

NTSTATUS
(NTAPI *RtlExtendMemoryBlockLookaside)(
    __in PVOID MemoryBlockLookaside,
    __in ULONG Increment
    );

NTSTATUS
(NTAPI *RtlResetMemoryBlockLookaside)(
    __in PVOID MemoryBlockLookaside
    );
