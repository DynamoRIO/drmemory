/* **********************************************************
 * Copyright (c) 2011-2014 Google, Inc.  All rights reserved.
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

/* staleness.c
 *
 * Memory staleness tool.  The basic algorithm is to have each
 * read/write set shadow metadata, and use a periodic sweep then sets
 * a last-accessed timestamp if an alloc's metadata is set and
 * subsequently clears the metadata.
 */

#include "dr_api.h"
#include "drheapstat.h"
#include "utils.h"
#include "staleness.h"
#include "alloc.h"
#include "../drmemory/slowpath.h"
#include "../drmemory/fastpath.h"
#include "umbra.h"

/***************************************************************************
 * MEMORY SHADOWING DATA STRUCTURES
 */

/* We need 1 bit per malloc chunk.  To support later adding staleness of .data
 * we do general shadowing rather than a malloc hashtable (which would have to
 * support resizing, etc.).  Mallocs are aligned to 8, and since we only
 * allocate for heap we can afford the more efficient 1 shadow byte to hold our
 * 1 bit (so no bitwise operations needed).  So we have 1 shadow byte per 8 app
 * bytes.
 */
#define SHADOW_GRANULARITY 8
#define SHADOW_MAP_SCALE   UMBRA_MAP_SCALE_DOWN_8X

#define SHADOW_DEFAULT_VALUE      1
#define SHADOW_DEFAULT_VALUE_SIZE 1

static umbra_map_t *umbra_map;

void
shadow_table_init(void)
{
    umbra_map_options_t umbra_map_ops;

    LOG(2, "shadow_table_init\n");
    /* create umbra shadow map */
    memset(&umbra_map_ops, 0, sizeof(umbra_map_ops));
    umbra_map_ops.struct_size = sizeof(umbra_map_ops);
    umbra_map_ops.flags =
        UMBRA_MAP_CREATE_SHADOW_ON_TOUCH |
        UMBRA_MAP_SHADOW_SHARED_READONLY;
    umbra_map_ops.scale = SHADOW_MAP_SCALE;
    umbra_map_ops.default_value = SHADOW_DEFAULT_VALUE;
    umbra_map_ops.default_value_size = SHADOW_DEFAULT_VALUE_SIZE;
#ifndef X64
    umbra_map_ops.redzone_size = 0;
#endif
    if (umbra_create_mapping(&umbra_map_ops, &umbra_map) != DRMF_SUCCESS)
        ASSERT(false, "fail to create shadow memory mapping");
}

void
shadow_table_exit(void)
{
    LOG(2, "shadow_table_exit\n");
    if (umbra_destroy_mapping(umbra_map) != DRMF_SUCCESS)
        ASSERT(false, "fail to destroy shadow memory");
}

size_t
get_shadow_block_size()
{
    size_t size;
    if (umbra_get_shadow_block_size(umbra_map, &size) != DRMF_SUCCESS) {
        ASSERT(false, "fail to get shadow block size");
        return PAGE_SIZE;
    }
    return size;
}

uint
shadow_get_byte(byte *addr)
{
    byte val;
    size_t app_size = SHADOW_GRANULARITY;
    size_t shdw_size = sizeof(val);
    if (umbra_read_shadow_memory(umbra_map,
                                 (app_pc)addr,
                                 app_size,
                                 &shdw_size,
                                 &val) != DRMF_SUCCESS ||
        shdw_size != sizeof(val))
        ASSERT(false, "fail to get shadow byte");
    return val;
}

void
shadow_set_byte(byte *addr, byte val)
{
    size_t app_size = SHADOW_GRANULARITY;
    size_t shdw_size = sizeof(val);
    ASSERT(val == 0 || val == 1, "invalid staleness shadow val");
    if (umbra_write_shadow_memory(umbra_map, (app_pc)addr,
                                  app_size, &shdw_size, &val) != DRMF_SUCCESS ||
        shdw_size != sizeof(val))
        ASSERT(false, "fail to set shadow byte");
}

void
shadow_set_range(byte *start, byte *end, byte val)
{
    size_t app_size = end - start;
    size_t shdw_size;
    ASSERT(val == 0 || val == 1, "invalid staleness shadow val");
    /* synch: I don't think having races is unacceptable here so not going
     * to lock anything just yet
     */
    if (umbra_shadow_set_range(umbra_map, (app_pc)start,
                               app_size, &shdw_size,
                               val, 1) != DRMF_SUCCESS ||
        shdw_size != app_size / SHADOW_GRANULARITY)
        ASSERT(false, "fail to set shadow range");
}

void
shadow_copy_range(byte *old_start, byte *new_start, size_t size)
{
    size_t shdw_size;
    if (umbra_shadow_copy_range(umbra_map,
                                (app_pc)old_start,
                                (app_pc)new_start,
                                size,
                                &shdw_size) != DRMF_SUCCESS ||
        shdw_size != size / SHADOW_GRANULARITY)
        ASSERT(false, "fail to copy shadow range");
}

void
shadow_create_shadow_memory(byte * start, byte * end, byte val)
{
    uint flags = 0; /* no special shadow memory */
    LOG(2, "%s "PFX"-"PFX"\n", __FUNCTION__, start, end);
    ASSERT(end > start, "invalid range");
    if (umbra_create_shadow_memory(umbra_map, flags,
                                   (app_pc)start, end - start,
                                   val,
                                   SHADOW_DEFAULT_VALUE_SIZE) != DRMF_SUCCESS)
        ASSERT(false, "fail to create shadow memory");
}

void
shadow_reinstate_specials_in_range(byte * start, byte * end)
{
    /* PR 580017: we can't free a non-special b/c we could have a
     * use-after-free in our own code.  We expect this to be rare
     * enough (large heap alloc being de-allocated) and the
     * consequences of leaving the non-special non-severe enough (use
     * a little more memory, do a few more writes if something else
     * gets allocated here) that it's not worth a fancy delayed
     * deletion algorithm, or using file mmap address games.
     */
    ASSERT(false, "not safe to call");
}

static bool
shadow_val_in_range(byte *start, byte *end, byte val)
{
    bool found;
    if (umbra_value_in_shadow_memory(umbra_map,
                                     (app_pc *)&start,
                                     end - start,
                                     val,
                                     SHADOW_DEFAULT_VALUE_SIZE,
                                     &found) != DRMF_SUCCESS)
        ASSERT(false, "failed to check value in shadow memory");
    return found;
}

/* Returns a pointer to an always-bitlevel shadow block */
byte *
shadow_bitlevel_addr(void)
{
    /* FIXME: if we do impl xl8 sharing should rename this routine */
    ASSERT(false, "should not get here");
    return NULL;
}

/* XXX: share near-identical code in drmemory/shadow.c.  The plan is to
 * merge this 8B-to-1B shadow implementation into the forthcoming
 * Umbra Extension.
 */
void
shadow_gen_translation_addr(void *drcontext, instrlist_t *bb, instr_t *inst,
                            reg_id_t addr_reg, reg_id_t scratch_reg)
{
#ifdef DEBUG
    int num_regs;
#endif
    ASSERT(umbra_num_scratch_regs_for_translation(&num_regs) == DRMF_SUCCESS &&
           num_regs <= 1, "not enough scratch registers");
    umbra_insert_app_to_shadow(drcontext, umbra_map, bb, inst, addr_reg,
                               &scratch_reg, 1);
}

/***************************************************************************
 * INSTRUMENTATION
 */

/* Called by slow_path() after initial decode.  Expected to free inst. */
bool
slow_path_for_staleness(void *drcontext, dr_mcontext_t *mc, instr_t *inst,
                        app_loc_t *loc)
{
    opnd_t opnd;
    int opc, i, num_srcs, num_dsts;
    uint sz;
    bool pushpop_stackop;

    opc = instr_get_opcode(inst);
    num_srcs = num_true_srcs(inst, mc);
    for (i = 0; i < num_srcs; i++) {
        opnd = instr_get_src(inst, i);
        if (opnd_is_memory_reference(opnd)) {
            opnd = adjust_memop(inst, opnd, false, &sz, &pushpop_stackop);
            check_mem_opnd_nouninit(opc, 0, loc, opnd, sz, mc);
        }
    }

    num_dsts = num_true_dsts(inst, mc);
    for (i = 0; i < num_dsts; i++) {
        opnd = instr_get_dst(inst, i);
        if (opnd_is_memory_reference(opnd)) {
            opnd = adjust_memop(inst, opnd, true, &sz, &pushpop_stackop);
            check_mem_opnd_nouninit(opc, 0, loc, opnd, sz, mc);
        }
    }

    instr_free(drcontext, inst);
    /* we're not sharing xl8 so no need to call slow_path_xl8_sharing */

    return true;
}

bool
handle_mem_ref(uint flags, app_loc_t *loc, byte *addr, size_t sz, dr_mcontext_t *mc)
{
    byte *ptr;
    /* We're piggybacking on Dr. Memory syscall, etc. code.  For reads
     * and writes we want to mark the shadow byte to indicate the
     * memory was accessed.  For an addressability check we do
     * nothing.
     */
    if (TEST(MEMREF_CHECK_ADDRESSABLE, flags))
        return true;
    /* We ignore MEMREF_MOVS, etc.: we don't propagate anything */
    for (ptr = (byte *) ALIGN_BACKWARD(addr, SHADOW_GRANULARITY);
         ptr < (byte *) ALIGN_FORWARD(addr + sz, SHADOW_GRANULARITY);
         ptr += SHADOW_GRANULARITY) {
        shadow_set_byte(ptr, 1);
    }
    return true;
}

static bool
opnd_uses_memory_we_track(opnd_t opnd)
{
    /* PR 553724: by default assume esp always points to stack and that user
     * doesn't care about staleness of any stacks allocated in the heap.
     *
     * FIXME PR 553724: track ebp and ignore refs when ebp is clearly
     * used as a frame ptr
     */
    return (opnd_is_memory_reference(opnd) &&
            (!options.stale_ignore_sp ||
             !opnd_is_base_disp(opnd) ||
             reg_to_pointer_sized(opnd_get_base(opnd)) != REG_XSP ||
             opnd_get_index(opnd) != REG_NULL ||
             opnd_is_far_memory_reference(opnd)));
}

bool
instr_uses_memory_we_track(instr_t *inst)
{
    int i;
    ASSERT(options.staleness, "should not be called");
    if (instr_get_opcode(inst) == OP_lea) /* not a real mem access */
        return false;
    for (i = 0; i < instr_num_srcs(inst); i++) {
        if (opnd_uses_memory_we_track(instr_get_src(inst, i)))
            return true;
    }
    for (i = 0; i < instr_num_dsts(inst); i++) {
        if (opnd_uses_memory_we_track(instr_get_dst(inst, i)))
            return true;
    }
    return false;
}

/* Our version, versus Dr. Memory's version in drmemory/fastpath.c */
bool
instr_ok_for_instrument_fastpath(instr_t *inst, fastpath_info_t *mi, bb_info_t *bi)
{
    uint opc = instr_get_opcode(inst);
    int i;
    initialize_fastpath_info(mi, bi, inst);
    if (!options.fastpath)
        return false;
    if (opc == OP_xlat) {
        /* can't use base-disp "%ds:(%ebx,%al,1)" for lea: would have to expand
         * to multiple instrs.  not worth supporting since pretty rare though I
         * do see 3K in twolf test on windows.
         */
        return false;
    }

    /* We assume that any one memory reference, even in a rep string form,
     * will only access one heap allocation.  Since we're taking the most
     * recent access to any part of a heap alloc we thus don't care about the
     * size of a memory reference.
     */
    for (i=0; i<instr_num_dsts(inst); i++) {
        if (opnd_uses_memory_we_track(instr_get_dst(inst, i))) {
            mi->store = true;
            if (!opnd_is_null(mi->dst[0].app)) {
                /* FIXME: we could handle 2 dsts if no srcs easily,
                 * and even more dsts if we really wanted to w/o too
                 * much trouble.  also something like pusha w/
                 * consecutive dsts is easy: just take first one.
                 */
                return false;
            }
            mi->dst[0].app = instr_get_dst(inst, i);
        }
    }
    for (i=0; i<instr_num_srcs(inst); i++) {
        if (opnd_uses_memory_we_track(instr_get_src(inst, i))) {
            if (mi->store)
                mi->mem2mem = true;
            else
                mi->load = true;
            if (!opnd_is_null(mi->src[0].app)) {
                /* see notes above about handling this: in particular cmps */
                return false;
            }
            mi->src[0].app = instr_get_src(inst, i);
        }
    }
    return true;
}

/***************************************************************************
 * STALENESS DATA
 */

/* We need the count of live mallocs so we can alloc an array to store
 * per snapshot (PR 557636)
 */
static uint num_live_mallocs;

#ifdef STATISTICS
uint stale_small_needs_ext;
uint stale_needs_large;
#endif

/* We assume a lock is held by caller */
stale_per_alloc_t *
staleness_create_per_alloc(per_callstack_t *cstack, uint64 stamp)
{
    stale_per_alloc_t *spa = (stale_per_alloc_t *)
        global_alloc(sizeof(*spa), HEAPSTAT_STALENESS);
    /* we mark as "last accessed" with the timestamp of the alloc, which
     * is the most straightforward technique.
     *
     * FIXME PR 553710: store alloc time separately, and use a
     * sentinel value for initial timestamp (unless zero-on-alloc), to
     * identify memory not used since allocated even when not much
     * time has gone by.
     */
    spa->last_access = stamp;
    spa->cstack = cstack;
    num_live_mallocs++;
    return spa;
}

/* We assume a lock is held by caller */
void
staleness_free_per_alloc(stale_per_alloc_t *spa)
{
    global_free(spa, sizeof(*spa), HEAPSTAT_STALENESS);
    num_live_mallocs--;
}

/* The basic algorithm is to have each read/write set the shadow metadata,
 * and the periodic sweep then sets the timestamp if an alloc's metadata
 * is set and subsequently clears the metadata.
 */
static bool
alloc_itercb_sweep(malloc_info_t *info, void *iter_data)
{
    /* we don't care much about synch: ok to not be perfectly accurate */
    /* FIXME: ignore pre_us? option-controlled? */
    byte *end = info->base + info->request_size;
    if (shadow_val_in_range(info->base, end, 1)) {
        stale_per_alloc_t *spa = (stale_per_alloc_t *) info->client_data;
        uint64 stamp = *((uint64 *)iter_data);
        LOG(3, "\t"PFX"-"PFX" was accessed @%"INT64_FORMAT"u\\n", info->base, end, stamp);
        spa->last_access = stamp;
        shadow_set_range(info->base, end, 0);
    }
    return true;
}

void
staleness_sweep(uint64 stamp)
{
    /* if we changed iter param to always be 64 bits we wouldn't need this */
    uint64 *iter_data = (uint64 *) global_alloc(sizeof(*iter_data), HEAPSTAT_STALENESS);
    /* note that depending on the time units in use, and the period between
     * snapshots, this sweep could use the same stamp as the last sweep:
     * that's fine, but should we up the sweep timer?
     */
    *iter_data = stamp;
    ASSERT(options.staleness, "should not get here");
    LOG(2, "\nSTALENESS SWEEP @%"INT64_FORMAT"u\n", stamp);
    malloc_iterate(alloc_itercb_sweep, (void *) iter_data);
    global_free(iter_data, sizeof(*iter_data), HEAPSTAT_STALENESS);
}

/* Accessors for compressed per-snapshot data */
uint
staleness_get_snap_cstack_id(stale_snap_allocs_t *snaps, uint idx)
{
    ASSERT(idx < snaps->num_entries, "idx out of range");
    if (snaps->uses_large)
        return snaps->data.lg[idx].cstack_id;
    if (snaps->data.sm.main[idx].uses_ext)
        return snaps->data.sm.ext[snaps->data.sm.main[idx].u.ext_idx].cstack_id;
    else
        return snaps->data.sm.main[idx].u.val.cstack_id;
}

uint
staleness_get_snap_bytes(stale_snap_allocs_t *snaps, uint idx)
{
    ASSERT(idx < snaps->num_entries, "idx out of range");
    if (snaps->uses_large)
        return snaps->data.lg[idx].bytes_asked_for;
    if (snaps->data.sm.main[idx].uses_ext)
        return snaps->data.sm.ext[snaps->data.sm.main[idx].u.ext_idx].bytes_asked_for;
    else
        return snaps->data.sm.main[idx].u.val.bytes_asked_for;
}

uint64
staleness_get_snap_last_access(stale_snap_allocs_t *snaps, uint idx)
{
    ASSERT(idx < snaps->num_entries, "idx out of range");
    if (snaps->uses_large)
        return snaps->data.lg[idx].last_access;
    else
        return snaps->data.sm.main[idx].last_access;
}

static bool
alloc_itercb_snapshot(malloc_info_t *info, void *iter_data)
{
    stale_snap_allocs_t *snaps = (stale_snap_allocs_t *) iter_data;
    stale_per_alloc_t *spa = (stale_per_alloc_t *) info->client_data;
    uint cstack_id;
    uint bytes_asked_for;
    ASSERT(snaps != NULL, "invalid param");
    ASSERT(spa != NULL, "invalid param");
    /* FIXME: ignore pre_us? option-controlled? */
    cstack_id = get_cstack_id(spa->cstack);
    bytes_asked_for = info->request_size;
    ASSERT(snaps->idx < snaps->num_entries, "stale array overflow");
    if (snaps->uses_large) {
        snaps->data.lg[snaps->idx].cstack_id = cstack_id;
        snaps->data.lg[snaps->idx].bytes_asked_for = bytes_asked_for;
        snaps->data.lg[snaps->idx].last_access = spa->last_access;
    } else {
        ASSERT(spa->last_access <= STALE_SMALL_MAX_STAMP, "stale stamp overflow");
        snaps->data.sm.main[snaps->idx].last_access = spa->last_access;
        if (cstack_id <= STALE_SMALL_MAX_ID &&
            bytes_asked_for <= STALE_SMALL_MAX_SZ) {
            snaps->data.sm.main[snaps->idx].uses_ext = false;
            snaps->data.sm.main[snaps->idx].u.val.cstack_id = cstack_id;
            snaps->data.sm.main[snaps->idx].u.val.bytes_asked_for = bytes_asked_for;
        } else {
            STATS_INC(stale_small_needs_ext);
            snaps->data.sm.main[snaps->idx].uses_ext = true;
            if (snaps->data.sm.ext_entries >= snaps->data.sm.ext_capacity) {
                stale_snap_alloc_ext_t *newext;
                uint old_cap = snaps->data.sm.ext_capacity;
                if (snaps->data.sm.ext_capacity == 0)
                    snaps->data.sm.ext_capacity = STALE_SMALL_EXT_INITIAL_CAPACITY;
                else
                    snaps->data.sm.ext_capacity *= 2;
                newext = (stale_snap_alloc_ext_t *)
                    global_alloc(snaps->data.sm.ext_capacity*sizeof(*newext),
                                 HEAPSTAT_STALENESS);
                if (snaps->data.sm.ext != NULL) {
                    memcpy(newext, snaps->data.sm.ext,
                           snaps->data.sm.ext_entries*sizeof(*newext));
                    global_free(snaps->data.sm.ext, old_cap*sizeof(*newext),
                                HEAPSTAT_STALENESS);
                }
                snaps->data.sm.ext = newext;
            }
            snaps->data.sm.ext[snaps->data.sm.ext_entries].cstack_id = cstack_id;
            snaps->data.sm.ext[snaps->data.sm.ext_entries].bytes_asked_for =
                bytes_asked_for;
            snaps->data.sm.main[snaps->idx].u.ext_idx = snaps->data.sm.ext_entries;
            snaps->data.sm.ext_entries++;
        }
    }
    LOG(3, "\tadding "PFX"-"PFX" stamp %"INT64_FORMAT"u to snapshot idx %d\n",
        info->base, info->base + info->request_size, spa->last_access, snaps->idx);
    snaps->idx++;
    return true;
}

/* The malloc lock must be held by the caller */
stale_snap_allocs_t *
staleness_take_snapshot(uint64 cur_stamp)
{
    stale_snap_allocs_t *snaps = (stale_snap_allocs_t *)
        global_alloc(sizeof(*snaps), HEAPSTAT_STALENESS);
    snaps->num_entries = num_live_mallocs;
    snaps->idx = 0;
    snaps->uses_large = (cur_stamp > STALE_SMALL_MAX_STAMP);
    if (snaps->uses_large) {
        /* FIXME: this path was tested by forcing uses_large to be true but
         * has not been tested w/ a really long running app
         */
        STATS_INC(stale_needs_large);
        if (snaps->num_entries == 0) {
            snaps->data.lg = NULL;
        } else {
            snaps->data.lg = (stale_snap_alloc_large_t *)
                global_alloc(snaps->num_entries*sizeof(*snaps->data.lg),
                             HEAPSTAT_STALENESS);
        }
    } else {
        if (snaps->num_entries == 0) {
            snaps->data.sm.main = NULL;
        } else {
            snaps->data.sm.main = (stale_snap_alloc_small_t *)
                global_alloc(snaps->num_entries*sizeof(*snaps->data.sm.main),
                             HEAPSTAT_STALENESS);
        }
        snaps->data.sm.ext = NULL;
        snaps->data.sm.ext_entries = 0;
        snaps->data.sm.ext_capacity = 0;
    }
    ASSERT(options.staleness, "should not get here");
    /* These two could be done at init time but there is no staleness_init() */
    ASSERT(sizeof(stale_snap_alloc_small_t) == 8, "struct size changed");
    ASSERT(STALE_SMALL_BITS_ID + STALE_SMALL_BITS_SZ == 32, "bitfields inconsistent");
    LOG(2, "\nSTALENESS SNAPSHOT\n");
    if (snaps->num_entries > 0)
        malloc_iterate(alloc_itercb_snapshot, (void *) snaps);
    ASSERT(snaps->idx == snaps->num_entries, "mismatch in # mallocs");
    return snaps;
}

void
staleness_free_snapshot(stale_snap_allocs_t *snaps)
{
    if (snaps == NULL)
        return;
    if (snaps->num_entries > 0) {
        if (snaps->uses_large) {
            global_free(snaps->data.lg, snaps->num_entries*sizeof(*snaps->data.lg),
                        HEAPSTAT_STALENESS);
        } else {
            global_free(snaps->data.sm.main,
                        snaps->num_entries*sizeof(*snaps->data.sm.main),
                        HEAPSTAT_STALENESS);
            if (snaps->data.sm.ext != NULL) {
                global_free(snaps->data.sm.ext, snaps->data.sm.ext_capacity*
                            sizeof(*snaps->data.sm.ext), HEAPSTAT_STALENESS);
            }
        }
    }
    global_free(snaps, sizeof(*snaps), HEAPSTAT_STALENESS);
}

