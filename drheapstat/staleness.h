/* **********************************************************
 * Copyright (c) 2012 Google, Inc.  All rights reserved.
 * Copyright (c) 2010 VMware, Inc.  All rights reserved.
 * **********************************************************/

/* Dr. Memory: the memory debugger
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License, and no later version.

 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Library General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _STALENESS_H_
#define _STALENESS_H_ 1

/* staleness.h: header file for staleness.c for data staleness tool */
#include "callstack.h" /* for app_loc_t */

/* many exported routines are declared in shadow.h */

void
shadow_table_init(void);

void
shadow_table_exit(void);

void
shadow_create_shadow_memory(byte * start, byte * end, byte value);

void
shadow_reinstate_specials_in_range(byte * start, byte * end);

bool
slow_path_for_staleness(void *drcontext, dr_mcontext_t *mc, instr_t *inst,
                        app_loc_t *loc);

bool
instr_uses_memory_we_track(instr_t *inst);

/***************************************************************************
 * for drheapstat only, not drmemory files
 */
#ifdef _DRHEAPSTAT_H_

/* per-malloc-chunk data */
typedef struct _stale_per_alloc_t {
    /* timestamp: units and value are provided by drheapstat front end */
    uint64 last_access;
    /* point to cstack stored in cstack table: no extra copy, no ref count bump */
    per_callstack_t *cstack;
} stale_per_alloc_t;

/* What we store in each snapshot: we need data per live alloc, so we have
 * to save space where we can.  We use two different data structures: one
 * when the timestamp will fit in a uint, and one for uint64.
 * For the uint version we further compress the cstack_id and bytes_asked_for
 * fields via an out-of-line extension array for large values (simpler than
 * in-line using subsequent entries).
 *
 * Today we only store the asked-for size.  FIXME: should we add padding + total?
 * Padded size and total can drop bottom 3 bits since 8-aligned.
 */
#define STALE_SMALL_BITS_STAMP 31
/* ID and SZ should add to 32: */
#define STALE_SMALL_BITS_ID    19 /* 512K (hostd unit tests => 350K) */
#define STALE_SMALL_BITS_SZ    13 /*   8K */
#define STALE_SMALL_MAX_STAMP (UINT_MAX / 2) /* 1<<31 => warnings */
#define STALE_SMALL_MAX_ID    ((1 << (STALE_SMALL_BITS_ID))-1)
#define STALE_SMALL_MAX_SZ    ((1 << (STALE_SMALL_BITS_SZ))-1)
#define STALE_SMALL_EXT_INITIAL_CAPACITY  512

typedef struct _stale_snap_alloc_small_t {
    /* Most mallocs are small, and most apps have a small number of
     * unique callstacks, so we compress the fields.  The first bit
     * says whether the values were too large: if the bit is set, the
     * actual values are found in the out-of-line extension array
     * at index ext_idx.
     */
    uint uses_ext:1; /* if "bool" won't occupy same dword as last_access */
    /* A ushort would do for <10-min run (for -time_clock) but w/ padding
     * no savings, so we use uint which is sufficient for nearly all runs.
     * We take the first bit from here to give more room for the other fields.
     */
    uint last_access:STALE_SMALL_BITS_STAMP;
    union {
        struct {
            uint cstack_id:STALE_SMALL_BITS_ID;
            uint bytes_asked_for:STALE_SMALL_BITS_SZ;
        } val;
        uint ext_idx;
    } u;
} stale_snap_alloc_small_t;

/* An entry in the extension array */
typedef struct _stale_snap_alloc_ext_t {
    uint cstack_id;
    uint bytes_asked_for;
} stale_snap_alloc_ext_t;

/* Uses a 64-bit timestamp, which due to padding means we may as well use full
 * fields for the others (or we could request no padding).
 */
typedef struct _stale_snap_alloc_large_t {
    uint cstack_id;
    uint bytes_asked_for;
    uint64 last_access;
} stale_snap_alloc_large_t;

/* The top-level struct for a single snapshot */
typedef struct _stale_snap_allocs_t {
    /* This bool determines whether data.lg is used */
    bool uses_large;
    uint num_entries;
    uint idx; /* used only when filling in the array */
    union {
        struct {
            stale_snap_alloc_small_t *main; /* size = num_entries */
            /* Resizable array */
            stale_snap_alloc_ext_t *ext;
            uint ext_entries;
            uint ext_capacity;
        } sm;
        stale_snap_alloc_large_t *lg;
    } data;
} stale_snap_allocs_t;

#ifdef STATISTICS
extern uint stale_small_needs_ext;
extern uint stale_needs_large;
#endif

stale_per_alloc_t *
staleness_create_per_alloc(per_callstack_t *cstack, uint64 stamp);

void
staleness_free_per_alloc(stale_per_alloc_t *spa);

void
staleness_sweep(uint64 stamp);

stale_snap_allocs_t *
staleness_take_snapshot(uint64 cur_stamp);

void
staleness_free_snapshot(stale_snap_allocs_t *snaps);

uint
staleness_get_snap_cstack_id(stale_snap_allocs_t *snaps, uint idx);

uint
staleness_get_snap_bytes(stale_snap_allocs_t *snaps, uint idx);

uint64
staleness_get_snap_last_access(stale_snap_allocs_t *snaps, uint idx);

#endif /* _DRHEAPSTAT_H_ */


#endif /* _STALENESS_H_ */
