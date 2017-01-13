/* **********************************************************
 * Copyright (c) 2015-2017 Google, Inc.  All rights reserved.
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
#include "fastpath_arch.h"
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
    app_pc pc;
    bool translated = true;
    ASSERT(loc != NULL && loc->type == APP_LOC_PC, "invalid param");
    pc = loc_to_pc(loc);
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

    /* We've clobbered the register holding the shared xl8 address, so we have to
     * either restore or clear for subsequent sharers.  We end up clearing in all
     * cases for simplicity (see the commit history for a big comment on how complex
     * it gets to try and restore instead of just clearing).  That clear used to be
     * done here, and it relied on writing to the spill slot xchg-ed back into the
     * reg by the 2-step return.  Moving to drreg, we do not want to rely on spill
     * slots being constant, and we want to eliminate the 2-step return, so we moved
     * the reg clear to the inlined code in instrument_slowpath() where the reg to
     * write to is known.
     */
}

/***************************************************************************
 * Fault handling
 */

#ifdef ARM
dr_isa_mode_t
get_isa_mode_from_fault_mc(dr_mcontext_t *mc)
{
    return TEST(EFLAGS_T, mc->xflags) ? DR_ISA_ARM_THUMB : DR_ISA_ARM_A32;
}
#endif

#ifdef TOOL_DR_MEMORY

/* PR 448701: handle fault on write to a special shadow block */
static byte *
compute_app_address_on_shadow_fault(void *drcontext, byte *target,
                                    dr_mcontext_t *raw_mc, dr_mcontext_t *mc,
                                    byte *pc_post_fault, bb_saved_info_t *save)
{
    app_pc addr;
    uint memopidx;
    bool write;
    instr_t *app_inst = restore_mcontext_on_shadow_fault(drcontext, raw_mc,
                                                         mc, pc_post_fault, save);
    for (memopidx = 0;
         instr_compute_address_ex(app_inst, mc, memopidx, &addr, &write);
         memopidx++) {
        LOG(3, "considering emulated target %s "PFX" => shadow "PFX" vs fault "PFX"\n",
            write ? "write" : "read", addr, shadow_translation_addr(addr), target);
        if (shadow_translation_addr(addr) == target)
            break;
    }
    ASSERT(shadow_translation_addr(addr) == target,
           "unable to compute original address on shadow fault");
    instr_destroy(drcontext, app_inst);

    return addr;
}

static void
handle_special_shadow_fault(void *drcontext, byte *target,
                            dr_mcontext_t *raw_mc, dr_mcontext_t *mc, void *tag)
{
    /* Re-execute the faulting instruction.  We have to shift the instruction's
     * base register from the special block to the new block.  An alternative is
     * to restore the app context and then re-direct execution to a new bb: but
     * that's more complex (have to decode forward and emulate all xchg +
     * restore-from-tls until next cti) and less efficient (new bb, and we'd
     * have to change two-part sub-dword dst write to get final value in reg
     * before committing).  Actually we do have to restore app state to get app
     * address -- but the other arguments still apply so sticking w/ re-execute.
     */
    app_pc pc;
    app_pc addr;
    instr_t fault_inst;
    byte *new_shadow;
    opnd_t shadowop;
    bb_saved_info_t *save;
#ifdef DEBUG
    tls_util_t *pt = PT_GET(drcontext);
#endif

    LOG(2, "write fault to special shadow @"PFX"\n", target);
    STATS_INC(num_faults);
#ifdef TOOL_DR_HEAPSTAT
    ASSERT(false, "should not get here");
#endif

    if (is_in_gencode(raw_mc->pc)) {
        /* PR 503778: the esp_adjust fastpath now touches more than just the 64K
         * region containing the app esp.  We could calculate its exact address
         * by locating the precise routine and then use the count from tls and
         * remaining count, and then below adjust the stored boundary, but
         * simpler to bail to slowpath.
         */
        byte *nxt_pc;
        instr_t inst;
        pc = raw_mc->pc;
        instr_init(drcontext, &inst);
        nxt_pc = decode(drcontext, pc, &inst);
        do {
            /* Look for the start of slowpath inside esp_adjust fastpath.
             * For simplicity we insert a nop there.
             */
            if (instr_get_opcode(&inst) == OP_nop) {
                LOG(3, "write fault in gencode "PFX" => xl8 to slowpath "PFX"\n",
                    raw_mc->pc, pc);
                raw_mc->pc = pc;
                instr_free(drcontext, &inst);
                return;
            }
            instr_reset(drcontext, &inst);
            pc = nxt_pc;
            nxt_pc = decode(drcontext, pc, &inst);
        } while (pc - raw_mc->pc < PAGE_SIZE);
        ASSERT(false, "cannot find slowpath sequence in esp fastpath!");
    }

    instr_init(drcontext, &fault_inst);
    pc = decode(drcontext, raw_mc->pc, &fault_inst);

    hashtable_lock(&bb_table);
    save = (bb_saved_info_t *) hashtable_lookup(&bb_table, tag);
    addr = compute_app_address_on_shadow_fault(drcontext, target, raw_mc, mc, pc,
                                               save);
    hashtable_unlock(&bb_table);

    /* Create a non-special shadow block */
    new_shadow = shadow_replace_special(addr);
    /* Change base register to point at it */
    shadowop = instr_get_dst(&fault_inst, 0);
    ASSERT(opnd_is_base_disp(shadowop) && opnd_get_index(shadowop) == REG_NULL,
           "emulation error");
    ASSERT(opnd_compute_address(shadowop, raw_mc) == target, "emulation error");
    reg_set_value(opnd_get_base(shadowop), raw_mc, (reg_t)new_shadow);
    DOLOG(3, {
        LOG(3, "changed base reg in ");
        opnd_disassemble(drcontext, shadowop, pt->f);
        LOG(3, " to new non-special translation "PFX"\n", new_shadow);
    });

    instr_free(drcontext, &fault_inst);
}

/* i#1015: report write-to-read-only as an unaddressable warning */
static bool
handle_possible_write_to_read_only(void *drcontext,
                                   dr_mcontext_t *raw_mc,
                                   dr_mcontext_t *mc)
{
    app_pc addr;
    bool is_write;
    uint pos;
    int  memopidx;
    app_loc_t loc;
    size_t size;
    dr_mem_info_t info;
    instr_t inst;
    bool res = false;

    /* XXX: we could try to merge some code w/ pattern_handle_segv_fault() */
    ASSERT(options.pattern == 0, "already handled in pattern_handle_segv_fault()");
    instr_init(drcontext, &inst);
    if (!safe_decode(drcontext, raw_mc->pc, &inst, NULL)) {
        instr_free(drcontext, &inst);
        return false;
    }
    /* someone could send a SIGSEGV signal, so we iterate instr opnds
     * to check possible write-to-read-only errors
     */
    for (memopidx = 0;
         instr_compute_address_ex_pos(&inst, mc, memopidx,
                                      &addr, &is_write, &pos);
         memopidx++) {
        if (!is_write)
            continue;
        if (!dr_query_memory_ex(addr, &info) ||
            info.type == DR_MEMTYPE_FREE ||
            TEST(DR_MEMPROT_WRITE, info.prot) ||
            TEST(info.prot, DR_MEMPROT_PRETEND_WRITE))
            continue;
        size = opnd_size_in_bytes(opnd_get_size(instr_get_dst(&inst, pos)));
        pc_to_loc(&loc, mc->pc);
        /* XXX: how to avoid double report on write-to-unaddressable,
         * as the shadow have been updated by the first report?
         * It should be ok since it is unlikely to have an unaddressable
         * read-only region.
         */
        report_unaddr_warning(&loc, mc, "writing to readonly memory", addr, size, true);
        res = true;
    }
    instr_free(drcontext, &inst);
    return res;
}

#endif /* TOOL_DR_MEMORY */

/* PR 448701: we fault if we write to a special block */
#ifdef UNIX
dr_signal_action_t
event_signal_instrument(void *drcontext, dr_siginfo_t *info)
{
# ifdef TOOL_DR_MEMORY
    /* Handle faults from writes to special shadow blocks */
    /* i#1488: we sometimes get SIGBUS on Mac */
    if (info->sig == SIGSEGV || info->sig == SIGBUS) {
        byte *target = info->access_address;
        /* We don't know whether a write since DR isn't providing that info but
         * shouldn't matter enough to be worth our determining
         */
        LOG(2, "SIGSEGV @"PFX" (xl8=>"PFX") accessing "PFX"\n",
            info->raw_mcontext->pc, info->mcontext->pc, target);
        if (options.pattern != 0 &&
            pattern_handle_segv_fault(drcontext, info->raw_mcontext, info->mcontext)) {
            return DR_SIGNAL_SUPPRESS;
        } else if (ZERO_STACK() &&
                   handle_zeroing_fault(drcontext, target, info->raw_mcontext,
                                        info->mcontext)) {
            return DR_SIGNAL_SUPPRESS;
        } else if (options.shadowing &&
                   is_in_special_shadow_block(target)) {
            ASSERT(info->raw_mcontext_valid, "raw mc should always be valid for SEGV");
            handle_special_shadow_fault(drcontext, target, info->raw_mcontext,
                                        info->mcontext, info->fault_fragment_info.tag);
            /* Re-execute the faulting cache instr.  If we ever change to redirect
             * to a new bb at the app instr we must change our two-part shadow
             * write for sub-dword.
             */
            return DR_SIGNAL_SUPPRESS;
        } else if (options.report_write_to_read_only &&
                   options.pattern == 0 && /* vs pattern_handle_segv_fault() */
                   handle_possible_write_to_read_only(drcontext, info->raw_mcontext,
                                                      info->mcontext)) {
            /* fall through to DR_SIGNAL_DELIVER */
        } else if (options.check_pc &&
                   /* If the pc is the target, it's an exec fault */
                   info->mcontext->pc == target) {
            /* i#1412: raise an error on executing invalid memory */
            app_loc_t loc;
            pc_to_loc(&loc, target);
            report_unaddressable_access(&loc, target, 1, DR_MEMPROT_EXEC,
                                        target, target + 1, info->mcontext);
        }
    } else if (info->sig == SIGILL) {
        LOG(2, "SIGILL @"PFX" (xl8=>"PFX")\n",
            info->raw_mcontext->pc, info->mcontext->pc);
        if (options.pattern != 0) {
            if (pattern_handle_ill_fault(drcontext, info->raw_mcontext,
                                         info->mcontext))
                return DR_SIGNAL_SUPPRESS;
            return DR_SIGNAL_DELIVER;
        } else if (handle_slowpath_fault(drcontext, info->raw_mcontext,
                                         info->mcontext,
                                         info->fault_fragment_info.tag))
            return DR_SIGNAL_SUPPRESS;
    }
# endif
    return DR_SIGNAL_DELIVER;
}
#else
bool
event_exception_instrument(void *drcontext, dr_exception_t *excpt)
{
# ifdef TOOL_DR_MEMORY
    if (options.pattern != 0 &&
        (excpt->record->ExceptionCode == STATUS_ACCESS_VIOLATION ||
         excpt->record->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)) {
        bool guard;
        app_pc target = (app_pc) excpt->record->ExceptionInformation[1];
        /* i#1070: pattern mode inserted code may cause one-shot alarm
         * guard page violation, we need actual target for restoring
         * the guard page.
         */
        guard = excpt->record->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION;
        if (pattern_handle_segv_fault(drcontext, excpt->raw_mcontext, excpt->mcontext
                                      _IF_WINDOWS(target) _IF_WINDOWS(guard)))
            return false;
    }
    if (excpt->record->ExceptionCode == STATUS_ACCESS_VIOLATION) {
        app_pc target = (app_pc) excpt->record->ExceptionInformation[1];
        if (ZERO_STACK() &&
            excpt->record->ExceptionInformation[0] == 1 /* write */ &&
            handle_zeroing_fault(drcontext, target, excpt->raw_mcontext,
                                 excpt->mcontext)) {
            return false;
        } else if (options.shadowing &&
                   excpt->record->ExceptionInformation[0] == 1 /* write */ &&
                   is_in_special_shadow_block(target)) {
            handle_special_shadow_fault(drcontext, target, excpt->raw_mcontext,
                                        excpt->mcontext, excpt->fault_fragment_info.tag);
            /* Re-execute the faulting cache instr.  If we ever change to redirect
             * to a new bb at the app instr we must change our two-part shadow
             * write for sub-dword.
             */
            return false;
        } else if (options.report_write_to_read_only &&
                   options.pattern == 0 && /* vs pattern_handle_segv_fault() */
                   excpt->record->ExceptionCode != STATUS_GUARD_PAGE_VIOLATION &&
                   handle_possible_write_to_read_only(drcontext, excpt->raw_mcontext,
                                                      excpt->mcontext)) {
            return false;
        } else if (options.check_pc &&
                   /* If the pc is the target, it's an exec fault */
                   excpt->mcontext->pc == target) {
            /* i#1412: raise an error on executing invalid memory */
            app_loc_t loc;
            pc_to_loc(&loc, target);
            report_unaddressable_access(&loc, target, 1, DR_MEMPROT_EXEC,
                                        target, target + 1, excpt->mcontext);
        }
    } else if (excpt->record->ExceptionCode == STATUS_ILLEGAL_INSTRUCTION) {
        if (options.pattern != 0) {
            return !pattern_handle_ill_fault(drcontext, excpt->raw_mcontext,
                                             excpt->mcontext);
        } else if (handle_slowpath_fault(drcontext, excpt->raw_mcontext,
                                         excpt->mcontext,
                                         excpt->fault_fragment_info.tag)) {
            return false;
        }
    }
# endif
    LOG(2, "application fault @"PFX" in module %s\n",
        excpt->mcontext->pc, module_lookup_preferred_name(excpt->mcontext->pc));
    return true;
}
#endif

/***************************************************************************
 * For PR 578892: fastpath heap routine unaddr accesses
 */

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
