/* **********************************************************
 * Copyright (c) 2011-2012 Google, Inc.  All rights reserved.
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
#include "../drmemory/readwrite.h"
#include "../drmemory/fastpath.h"

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

/* Holds shadow state for a 64K unit of memory (the basic allocation
 * unit size on Windows)
 */
#define ALLOC_UNIT (64*1024)
typedef byte shadow_block_t[ALLOC_UNIT/SHADOW_GRANULARITY];
#define BLOCK_IDX(addr) (((ptr_uint_t)(addr) & 0x0000ffff) / SHADOW_GRANULARITY)

/* Shadow state for 4GB address space: 4GB/ALLOC_UNIT */
#define TABLE_ENTRIES (64*1024)
/* We store the displacement (shadow addr minus app addr) from the base to
 * shrink instrumentation size (PR 553724)
 */
ptr_int_t shadow_table[TABLE_ENTRIES];
#define TABLE_IDX(addr) (((ptr_uint_t)(addr) & 0xffff0000) >> 16)
#define ADDR_OF_BASE(table_idx) ((ptr_uint_t)(table_idx) << 16)

/* For non-heap we use special read-only blocks */
static shadow_block_t *special_nonheap;

/* Not adding redzone: giving up xl8 sharing in order to have no extra
 * checks and no jmp to slowpath
 */
#define SHADOW_BLOCK_ALLOC_SZ (sizeof(shadow_block_t))

static shadow_block_t *
create_shadow_block(bool special)
{
    shadow_block_t *block;
    if (special) {
        bool ok;
        block = (shadow_block_t *)
            nonheap_alloc(SHADOW_BLOCK_ALLOC_SZ, DR_MEMPROT_READ|DR_MEMPROT_WRITE,
                          HEAPSTAT_SHADOW);
        memset(block, 1, sizeof(*block));
        if (!options.stale_blind_store) {
            /* We will never write to the special */
            ok = dr_memory_protect(block, SHADOW_BLOCK_ALLOC_SZ, DR_MEMPROT_READ);
            ASSERT(ok, "-w failed: will have inconsistencies in shadow data");
        }
    } else {
        block = (shadow_block_t *) global_alloc(SHADOW_BLOCK_ALLOC_SZ, HEAPSTAT_SHADOW);
        memset(block, 0, sizeof(*block));
    }
    LOG(2, "created new shadow block "PFX"\n", block);
    return block;
}

static inline void
set_shadow_table(uint idx, shadow_block_t *block)
{
    /* We store the displacement (shadow minus app) (PR 553724) */
    shadow_table[idx] = ((ptr_int_t)block) - (ADDR_OF_BASE(idx) / SHADOW_GRANULARITY);
    LOG(2, "setting shadow table idx %d for block "PFX" to "PFX"\n",
        idx, block, shadow_table[idx]);
}

static inline shadow_block_t *
get_shadow_table(uint idx)
{
    /* We store the displacement (shadow minus app) (PR 553724) */
    return (shadow_block_t *)
        (shadow_table[idx] + (ADDR_OF_BASE(idx) / SHADOW_GRANULARITY));
}

void
shadow_table_init(void)
{
    uint i;
    special_nonheap = create_shadow_block(true);
    for (i = 0; i < TABLE_ENTRIES; i++)
        set_shadow_table(i, special_nonheap);
}

void
shadow_table_exit(void)
{
    uint i;
    LOG(2, "shadow_table_exit\n");
    for (i = 0; i < TABLE_ENTRIES; i++) {
        if (get_shadow_table(i) != special_nonheap) {
            LOG(2, "freeing shadow block idx=%d "PFX"\n", i, get_shadow_table(i));
            global_free(get_shadow_table(i), SHADOW_BLOCK_ALLOC_SZ, HEAPSTAT_SHADOW);
        }
    }
    nonheap_free(special_nonheap, SHADOW_BLOCK_ALLOC_SZ, HEAPSTAT_SHADOW);
}

size_t
get_shadow_block_size(void)
{
    return sizeof(shadow_block_t);
}

uint
shadow_get_byte(byte *addr)
{
    shadow_block_t *block = get_shadow_table(TABLE_IDX(addr));
    return (*block)[BLOCK_IDX(addr)];
}

void
shadow_set_byte(byte * addr, uint val)
{
    shadow_block_t *block = get_shadow_table(TABLE_IDX(addr));
    ASSERT(val == 0 || val == 1, "invalid staleness shadow val");
    if (block == special_nonheap) {
        ASSERT(val == 1, "cannot clear special shadow!");
        return;
    }
    (*block)[BLOCK_IDX(addr)] = val;
}

void
shadow_set_range(byte *start, byte *end, uint val)
{
    byte * pc = (byte *) ALIGN_BACKWARD(start, SHADOW_GRANULARITY);
    ASSERT(val == 0 || val == 1, "invalid staleness shadow val");
    /* synch: I don't think having races is unacceptable here so not going
     * to lock anything just yet
     */
    while (pc <= end -1 /*handle end of address space*/) {
        shadow_block_t *block = get_shadow_table(TABLE_IDX(pc));
        byte *block_start = &(*block)[BLOCK_IDX(pc)];
        byte *block_end = (TABLE_IDX(end) > TABLE_IDX(pc)) ? 
            ((*block) + sizeof(*block)) : (&(*block)[BLOCK_IDX(end)] + 1);
        ASSERT(block != special_nonheap, "cannot set nonheap shadow");
        memset(block_start, val, block_end - block_start);
        pc += (block_end - block_start) * SHADOW_GRANULARITY;
        if (pc < start) /* overflow */
            break;
    }
}

void
shadow_copy_range(byte *old_start, byte *new_start, size_t size)
{
    byte * pc = (byte *) ALIGN_BACKWARD(old_start, SHADOW_GRANULARITY);
    byte * new_pc = (byte *) ALIGN_BACKWARD(new_start, SHADOW_GRANULARITY);
    /* FIXME: optimize */
    for (; pc < old_start + size; pc += SHADOW_GRANULARITY, new_pc += SHADOW_GRANULARITY)
        shadow_set_byte(new_pc, shadow_get_byte(pc));
}

byte *
shadow_replace_special(byte * addr)
{
    shadow_block_t *block = get_shadow_table(TABLE_IDX(addr));
    if (block == special_nonheap) {
        block = create_shadow_block(false);
        set_shadow_table(TABLE_IDX(addr), block);
        LOG(2, "added heap shadow block for "PFX" @idx=%d\n", addr, TABLE_IDX(addr));
    }
    return NULL; /* nobody needs the return value */
}

void
shadow_replace_specials_in_range(byte * start, byte * end)
{
    byte * pc;
    LOG(2, "%s "PFX"-"PFX"\n", __FUNCTION__, start, end);
    for (pc = (byte *) ALIGN_BACKWARD(start, ALLOC_UNIT);
         /* don't loop beyond overflow */
         pc >= (byte *) ALIGN_BACKWARD(start, ALLOC_UNIT) &&
         /* but do process a region at very end of address space: use -1 */
         pc < (byte *) (ALIGN_FORWARD(end, ALLOC_UNIT) - 1);
         pc += ALLOC_UNIT) {
        shadow_replace_special(pc);
    }
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
#if 0 /* disabled: see comment above */
    byte * pc;
    /* If either end is not aligned we do not want to replace since
     * another heap piece can be in the region
     */
    for (pc = (byte *) ALIGN_FORWARD(start-1, ALLOC_UNIT);
         pc < (byte *) ALIGN_BACKWARD(end, ALLOC_UNIT);
         pc += ALLOC_UNIT) {
        shadow_block_t *block = get_shadow_table(TABLE_IDX(pc));
        if (block != special_nonheap) {
            /* reduce race window: eventually we'll try to add more synch */
            set_shadow_table(TABLE_IDX(pc), special_nonheap);
            global_free(block, SHADOW_BLOCK_ALLOC_SZ, HEAPSTAT_SHADOW);
            LOG(2, "reinstated non-heap shadow block for "PFX"\n", pc);
        }
    }
#endif
}

static bool
shadow_val_in_range(byte *start, byte *end, uint val)
{
    byte * pc = (byte *) ALIGN_BACKWARD(start, SHADOW_GRANULARITY);
    ASSERT(val == 0 || val == 1, "invalid staleness shadow val");
    while (pc <= end - 1 /*handle end of address space*/) {
        shadow_block_t *block = get_shadow_table(TABLE_IDX(pc));
        byte *block_start = &(*block)[BLOCK_IDX(pc)];
        byte *block_end = (TABLE_IDX(end) > TABLE_IDX(pc)) ? 
            ((*block) + sizeof(*block)) : (&(*block)[BLOCK_IDX(end)] + 1);
        byte *where = memchr(block_start, (int) val, block_end - block_start);
        if (where != NULL)
            return true;
        pc += (block_end - block_start) * SHADOW_GRANULARITY;
        if (pc < start) /* overflow */
            break;
    }
    return false;
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
    uint disp;
    /* Shadow table stores displacement so we want copy of whole addr */
    PRE(bb, inst, INSTR_CREATE_mov_ld
        (drcontext, opnd_create_reg(scratch_reg), opnd_create_reg(addr_reg)));
    /* Get top 16 bits into lower half.  We'll do x4 in a scale later, which
     * saves us from having to clear the lower bits here via OP_and or sthg (PR
     * 553724).
     */
    PRE(bb, inst, INSTR_CREATE_shr
        (drcontext, opnd_create_reg(scratch_reg), OPND_CREATE_INT8(16)));

    /* Instead of finding the uint array index we go straight to the single
     * byte (or 2 bytes) that shadows this <4-byte (or 8-byte) read, since aligned.
     * If sub-dword but not aligned we go ahead and get shadow byte for
     * containing dword.
     */
    PRE(bb, inst, INSTR_CREATE_shr
        (drcontext, opnd_create_reg(addr_reg),
         /* Staleness has 1 shadow byte per 8 app bytes */
         OPND_CREATE_INT8(3)));

    /* Index into table: no collisions and no tag storage since full size */
    /* Storing displacement, so add table result to app addr */
    ASSERT_TRUNCATE(disp, uint, (ptr_uint_t)shadow_table);
    disp = (uint)(ptr_uint_t)shadow_table;
    PRE(bb, inst, INSTR_CREATE_add
        (drcontext, opnd_create_reg(addr_reg), opnd_create_base_disp
         (REG_NULL, scratch_reg, 4, disp, OPSZ_PTR)));
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
            check_mem_opnd(opc, 0, loc, opnd, sz, mc, NULL);
        }
    }

    num_dsts = num_true_dsts(inst, mc);
    for (i = 0; i < num_dsts; i++) {
        opnd = instr_get_dst(inst, i);
        if (opnd_is_memory_reference(opnd)) {
            opnd = adjust_memop(inst, opnd, true, &sz, &pushpop_stackop);
            check_mem_opnd(opc, 0, loc, opnd, sz, mc, NULL);
        }
    }

    instr_free(drcontext, inst);
    /* we're not sharing xl8 so no need to call slow_path_xl8_sharing */

    return true;
}

bool
handle_mem_ref(uint flags, app_loc_t *loc, byte *addr, size_t sz, dr_mcontext_t *mc,
                  uint *shadow_vals)
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
         ptr += SHADOW_GRANULARITY)
        shadow_set_byte(ptr, 1);
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
    initialize_fastpath_info(mi, bi);
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
alloc_itercb_sweep(app_pc start, app_pc end, app_pc real_end,
                   bool pre_us, uint client_flags,
              void *client_data, void *iter_data)
{
    /* we don't care much about synch: ok to not be perfectly accurate */
    /* FIXME: ignore pre_us? option-controlled? */
    if (shadow_val_in_range(start, end, 1)) {
        stale_per_alloc_t *spa = (stale_per_alloc_t *) client_data;
        uint64 stamp = *((uint64 *)iter_data);
        LOG(3, "\t"PFX"-"PFX" was accessed @%"INT64_FORMAT"u\\n", start, end, stamp);
        spa->last_access = stamp;
        shadow_set_range(start, end, 0);
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

uint
staleness_get_snap_last_access(stale_snap_allocs_t *snaps, uint idx)
{
    ASSERT(idx < snaps->num_entries, "idx out of range");
    if (snaps->uses_large)
        return snaps->data.lg[idx].last_access;
    else
        return snaps->data.sm.main[idx].last_access;
}

static bool
alloc_itercb_snapshot(app_pc start, app_pc end, app_pc real_end,
                      bool pre_us, uint client_flags,
                      void *client_data, void *iter_data)
{
    stale_snap_allocs_t *snaps = (stale_snap_allocs_t *) iter_data;
    stale_per_alloc_t *spa = (stale_per_alloc_t *) client_data;
    uint cstack_id;
    uint bytes_asked_for;
    ASSERT(snaps != NULL, "invalid param");
    ASSERT(spa != NULL, "invalid param");
    /* FIXME: ignore pre_us? option-controlled? */
    cstack_id = get_cstack_id(spa->cstack);
    bytes_asked_for = end - start;
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
        start, end, spa->last_access, snaps->idx);
    snaps->idx++;
    return true;
}

/* The malloc lock is held by caller */
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

