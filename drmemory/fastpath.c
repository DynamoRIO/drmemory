/* **********************************************************
 * Copyright (c) 2015 Google, Inc.  All rights reserved.
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

/***************************************************************************
 * fastpath.c: Dr. Memory cross-platform shadow instrumentation fastpath
 */

#include "dr_api.h"
#include "drmemory.h"
#include "slowpath.h"
#include "spill.h"
#include "fastpath.h"
#include "shadow.h"
#include "stack.h"
#ifdef TOOL_DR_MEMORY
# include "alloc_drmem.h"
# include "report.h"
#endif
#include "pattern.h"

#ifdef UNIX
# include <signal.h> /* for SIGSEGV */
#else
# include <stddef.h> /* for offsetof */
#endif

static uint share_xl8_num_flushes;

void
slow_path_xl8_sharing(app_loc_t *loc, size_t inst_sz, opnd_t memop, dr_mcontext_t *mc)
{
    /* PR 493257: share shadow translation across multiple instrs */
    uint xl8_sharing_cnt;
    app_pc pc, nxt_pc;
    bool translated = true;
    ASSERT(loc != NULL && loc->type == APP_LOC_PC, "invalid param");
    if (options.single_arg_slowpath) {
        /* We don't want to pay the xl8 cost every time so we have
         * an additional entry for the cache pc and we only xl8 when
         * that crosses the threshold.  This may be superior anyway since
         * app pc can be duplicated in other bbs where it might behave
         * differently (though seems unlikely).
         */
        translated = loc->u.addr.valid;
        pc = loc->u.addr.pc;
    } else
        pc = loc_to_pc(loc);
    nxt_pc = pc + inst_sz;
    xl8_sharing_cnt = (uint)(ptr_uint_t) hashtable_lookup(&xl8_sharing_table, pc);
    if (xl8_sharing_cnt > 0) {
        STATS_INC(xl8_shared_slowpath_count);
        ASSERT(!opnd_is_null(memop), "error in xl8 sharing");
        /* Since we can't share across 64K boundaries we exit to slowpath.
         * If this happens too often, abandon sharing.
         */
        if (xl8_sharing_cnt > options.share_xl8_max_slow &&
            /* 2* is signal to not flush again */
            xl8_sharing_cnt < 2*options.share_xl8_max_slow) {
            uint num_flushes;
            STATS_INC(xl8_not_shared_slowpaths);
            /* If this instr has other reasons to go to slowpath, don't flush
             * repeatedly: only flush if it's actually due to addr sharing
             */
            hashtable_add_replace(&xl8_sharing_table, pc,
                                  (void *)(ptr_uint_t)
                                  (2*options.share_xl8_max_slow));
            /* We don't need a synchronous flush: go w/ most performant.
             * dr_delay_flush_region() doesn't do any unlinking, so if in
             * a loop we'll repeatedly flush => performance problem!
             * So we go w/ dr_unlink_flush_region(): should be ok since
             * we'll never want -coarse_units.
             * XXX i#1426: actually we do have -coarse_units with -persist_code!
             * To support full mode persistence we'll have to change this flush!
             */

            /* Flushing can be expensive so we disable sharing
             * completely if we flush too many times.
             *
             * XXX DRi#373: really, DR should split vm areas up to
             * make these flushes more performant so each flush
             * doesn't throw out entire executable's worth!
             */
            num_flushes = atomic_add32_return_sum((int*)&share_xl8_num_flushes, 1);
            if (num_flushes >= options.share_xl8_max_flushes/2) {
                /* reduce the max diff to reduce # of 64K crossings.
                 * the flush will flush all in this module (at least
                 * until DRi#373) so this will affect other sharings.
                 */
                LOG(1, "reached %d flushes: shrinking -share_xl8_max_diff\n",
                    num_flushes);
                options.share_xl8_max_diff /= 8;
            } else if (num_flushes >= options.share_xl8_max_flushes) {
                LOG(1, "reached %d flushes: disabling xl8 sharing\n", num_flushes);
                options.share_xl8 = false;
            }

            LOG(3, "slow_path_xl8_sharing: flushing "PFX"\n", pc);
            if (!translated) {
                /* Now we have to xl8 */
                pc = loc_to_pc(loc);
                /* We've been incrementing the cache pc entry, but the
                 * hashtable_add_replace below will tell the
                 * instrumentation to not share this app pc again.
                 */
            }
            dr_unlink_flush_region(pc, 1);
        } else {
            xl8_sharing_cnt++;
            /* We don't care about races: threshold is low enough we won't overflow */
            hashtable_add_replace(&xl8_sharing_table, pc,
                                  (void *)(ptr_uint_t) xl8_sharing_cnt);
        }
    } else if (!translated && !opnd_is_null(memop)) {
        LOG(3, "slow_path_xl8_sharing: adding entry "PFX"\n", pc);
        hashtable_add(&xl8_sharing_table, pc, (void *)1);
        STATS_INC(xl8_shared_slowpath_instrs);
    }

    /* For -single_arg_slowpath we don't want to xl8 so we always
     * clear, assuming reg1 is scratch if not used for sharing.
     */
    if (!translated ||
        hashtable_lookup(&xl8_sharing_table, nxt_pc) > 0) {
        /* We're sharing w/ the next instr.  We had the addr in reg1 and we need
         * to put it back there.  shared_slowpath will xchg slot1 w/ reg1.  We
         * only support sharing w/ 1 memop so we ignore multiple here.
         */
        byte *addr;
        byte *memref = opnd_is_null(memop) ? NULL : opnd_compute_address(memop, mc);
        if (!ALIGNED(memref, sizeof(void*))) {
            /* If we exited b/c unaligned, do not share => all subsequent instrs
             * sharing this translation will exit to slowpath
             */
            addr = shadow_bitlevel_addr();
        } else {
            /* If all subsequent shared uses of this translation are stores, we
             * can simply use shadow_translation_addr(memref) here.  But loads
             * use an offset from the original translation: and if we're now in
             * a new block (if we came to slowpath b/c we hit the redzone of
             * shared addr's original block) we can't easily recover.  We could
             * have loads update reg1 every time but that costs an extra instr
             * in the fastpath; we could instead try to decode forward and see
             * whether it's a load.  For now we take the simple route and
             * disable subsequent sharing.  This will cause slowpath exits for
             * all subsequent sharers, but we assume this first slowpath is rare
             * enough.
             */
            addr = shadow_bitlevel_addr();
        }
        LOG(3, "slow_path_xl8_sharing for pc="PFX" addr="PFX"\n", nxt_pc, addr);
        set_own_tls_value(SPILL_SLOT_1, (ptr_uint_t)addr);
    }
}

/* used for PR 578892: fastpath heap routine unaddr accesses */
void
client_entering_heap_routine(void)
{
#ifdef TOOL_DR_MEMORY
    if (options.shadowing)
        set_shadow_inheap(1);
#endif
}

void
client_exiting_heap_routine(void)
{
#ifdef TOOL_DR_MEMORY
    if (options.shadowing)
        set_shadow_inheap(0);
#endif
}
