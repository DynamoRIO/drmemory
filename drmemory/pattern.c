/* **********************************************************
 * Copyright (c) 2012 Google, Inc.  All rights reserved.
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
 * pattern.c: Dr. Memory pattern mode implementation
 */

#include "dr_api.h"
#include "drmemory.h"
#include "readwrite.h"
#include "pattern.h"
#include "shadow.h"
#include "stack.h"
#include "fastpath.h"
#include "alloc.h"
#include "redblack.h"
#include "report.h"
#include "alloc_drmem.h"

#ifdef LINUX
# include <signal.h> /* for SIGSEGV */
#endif

#define MAX_REFS_PER_INSTR 3
#define PATTERN_SLOT_XAX    SPILL_SLOT_1
#define PATTERN_SLOT_AFLAGS SPILL_SLOT_2

/* we use a redblack tree to keep malloc info */
static rb_tree_t *pattern_malloc_tree;
static void *pattern_malloc_tree_rwlock;

static ptr_uint_t note_base;

enum {
    NOTE_NULL = 0,
    NOTE_SAVE_AFLAGS,
    NOTE_SAVE_AFLAGS_WITH_EAX,    /* need restore app's EAX after */
    NOTE_RESTORE_AFLAGS,
    NOTE_RESTORE_AFLAGS_WITH_EAX, /* need restore aflags to EAX first */
    NOTE_MAX_VALUE,
};

/* check if the opnd should be instrumented for checks */
static bool
pattern_opnd_need_check(opnd_t opnd)
{
    if (!opnd_is_memory_reference(opnd))
        return false;
    /* We are only interested in heap objects in pattern mode, 
     * so no absolute address or pc relative address.
     */
    if (opnd_is_abs_addr(opnd))
        return false;
#ifdef X64
    if (opnd_is_rel_addr(opnd))
        return false;
#endif
    DR_ASSERT(opnd_is_base_disp(opnd));
    if (opnd_uses_nonignorable_memory(opnd))
        return true;
    return false;
}

/* Insert the code for pattern check on operand refs.
 * The instr sequence instrumented here is used in fault handling for
 * checking if it is the instrumented code. So if it is changed here,
 * the checking code in
 * - ill_instr_is_instrumented and 
 * - segv_instr_is_instrumented
 * must be updated too.
 */
static void
pattern_insert_check_code(void *drcontext, instrlist_t *ilist, 
                          instr_t *app, opnd_t ref)
{
    opnd_size_t opsz = opnd_get_size(ref);
    instr_t *label;
    int opcode = instr_get_opcode(app);
    app_pc pc = instr_get_app_pc(app);
    opnd_t opnd;

    ASSERT(opnd_is_memory_reference(ref), "non-memory-ref opnd is instrumented");
    label = INSTR_CREATE_label(drcontext);
    /* XXX: i#774, we perform 2-byte check for 1/2-byte reference and 4-byte 
     * otherwise, should we do 2 4-byte checks for case like 8-byte reference?
     */
    if (opsz > OPSZ_2) {
        opsz = OPSZ_4;
        opnd = OPND_CREATE_INT32(options.pattern);
    } else {
        opsz = OPSZ_2;
        opnd = OPND_CREATE_INT16((short)options.pattern);
    }
    opnd_set_size(&ref, opsz);
    /* special handling for xlat instr */
    if (opcode == OP_xlat) {
        /* XXX: we can avoid save xax if aflag is saved */
        /* xlat access memory (xbx, al), which is not a legeal memory operand,
         * and we use (xbx, xax) to emulate (xbx, al) instead:
         * save xax; movzx xax, al; 
         */
        spill_reg(drcontext, ilist, app, DR_REG_XAX, PATTERN_SLOT_XAX);
        PRE(ilist, app, INSTR_CREATE_movzx(drcontext,
                                           opnd_create_reg(DR_REG_XAX),
                                           opnd_create_reg(DR_REG_AL)));
    }
    /* XXX: i#775, because of using 2-byte pattern for checking, 
     * we currently do not detect some unaligned refs:
     * (a) off-by-one-byte unaligned, and 
     * (b) two-byte at begin/end of the redzone.
     * We can add off-by-one-byte checks for (a).
     * We can add more checks for (b), but it add complexity,
     * not only the instrumentation, but also the fault handling.
     */
    /* cmp ref, pattern */
    PREXL8M(ilist, app, INSTR_XL8(INSTR_CREATE_cmp(drcontext, ref, opnd), pc));
    /* jne label */
    PRE(ilist, app, INSTR_CREATE_jcc_short(drcontext, OP_jne_short,
                                           opnd_create_instr(label)));
    /* we assume that the pattern seen is rare enough, so we use ud2a to
     * cause an illegal exception to handle.
     */
    PREXL8M(ilist, app, INSTR_XL8(INSTR_CREATE_ud2a(drcontext), pc));
    /* label */
    PRE(ilist, app, label);
    if (opcode == OP_xlat) {
        /* restore xax 
         * XXX: we can avoid restore xax if aflags is to be restored.
         */
        restore_reg(drcontext, ilist, app, DR_REG_XAX, PATTERN_SLOT_XAX);
    }
}

void
pattern_instrument_check(void *drcontext, instrlist_t *ilist, instr_t *app)
{
    int num_refs = 0, num_opnds, i;
    int opcode = instr_get_opcode(app);
    instr_t *label;
    opnd_t refs[MAX_REFS_PER_INSTR];
    bool restore_eax = false;

    if (opcode == OP_lea || instr_is_prefetch(app)) {
        return;
    } else if (opcode == OP_xlat) {
        /* we use (%xbx, %xax) to emulate xlat's (%xbx, %al), which is an illegal
         * memory reference opnd except xlat.
         */
        refs[0] = opnd_create_base_disp(DR_REG_XBX,
                                        DR_REG_XAX,
                                        1, 0, OPSZ_2);
        num_refs = 1;
        restore_eax = true;
    } else {
        /* XXX: i#776, check if any of app's opnds need to be instrumented.
         * There are some possible optimizations: for example,
         * we can remember the opnds that we instrumented in the bb, and
         * keep track of the register updates, so we can avoid inserting checks
         * for the opnd that being checked earlier.
         * However, this would add large analysis overhead, which might not 
         * offset the benefit.
         * We might want to do it in trace if trace is enabled.
         */
        /* XXX: we do not handle OP_enter/OP_leave as we do not check
         * stack access.
         */
        opnd_t opnd;
        /* check every src opnd if any opnd need instrumentation. */
        num_opnds = instr_num_srcs(app);
        for (i = 0; i < num_opnds; i++) {
            opnd = instr_get_src(app, i);
            if (pattern_opnd_need_check(opnd)) {
                ASSERT(num_refs < MAX_REFS_PER_INSTR, 
                       "Too many refs in an instr");
                refs[num_refs] = opnd;
                num_refs++;
                if (opnd_uses_reg(opnd, DR_REG_XAX))
                    restore_eax = true;
            }
        }
        /* check every dst opnd if any interested opnd for instrumentation. */
        num_opnds = instr_num_dsts(app);
        for (i = 0; i < num_opnds; i++) {
            opnd = instr_get_dst(app, i);
            if (pattern_opnd_need_check(opnd)) {
                int j;
                for (j = 0; j < num_refs; j++) {
                    /* for case like ADD [mem], val => [mem] */
                    if (opnd_same(refs[j], opnd))
                        break;
                }
                if (j == num_refs) {
                    ASSERT(num_refs < MAX_REFS_PER_INSTR, 
                           "Too many refs in an instr");
                    refs[num_refs] = opnd;
                    num_refs++;
                    if (opnd_uses_reg(opnd, DR_REG_XAX)) {
                        ASSERT(opnd_is_memory_reference(opnd), "wrong opnd");
                        restore_eax = true;
                    }
                }
            }
        }
    }
    if (num_refs == 0)
        return;

    /* here we only insert aflags save/restore labels for optimizations later */
    /* aflags save label */
    label = INSTR_CREATE_label(drcontext);
    if (restore_eax)
        instr_set_note(label, (void *)(note_base + NOTE_SAVE_AFLAGS_WITH_EAX));
    else
        instr_set_note(label, (void *)(note_base + NOTE_SAVE_AFLAGS));
    PRE(ilist, app, label);
    /* pattern check code */
    for (i = 0; i < num_refs; i++)
        pattern_insert_check_code(drcontext, ilist, app, refs[i]);
    /* aflags restore label */
    label = INSTR_CREATE_label(drcontext);
    if (restore_eax)
        instr_set_note(label, (void *)(note_base + NOTE_RESTORE_AFLAGS_WITH_EAX));
    else
        instr_set_note(label, (void *)(note_base + NOTE_RESTORE_AFLAGS));
    PRE(ilist, app, label);
}

/* Update the arith flag's liveness in a backward scan. */
static int
pattern_aflags_liveness_update_on_reverse_scan(instr_t *instr, int liveness)
{
    uint flags;
    if (instr_is_cti(instr))
        return LIVE_LIVE;
    if (instr_is_interrupt(instr) || instr_is_syscall(instr))
        return LIVE_LIVE;
    flags = instr_get_arith_flags(instr);
    if (TESTANY(EFLAGS_READ_6, flags))
        return LIVE_LIVE;
    if (TESTALL(EFLAGS_WRITE_6, flags))
        return LIVE_DEAD;
    /* XXX: we can also track whether OF is live, to avoid seto/add
     * in aflags save/restore. 
     * We need refactor the existing code for easier reuse.
     */
    return liveness;
}

/* Update the reg's liveness in a backward scan */
static int
pattern_reg_liveness_update_on_reverse_scan(instr_t *instr, reg_id_t reg,
                                            int liveness)
{
    if (instr_is_cti(instr))
        return LIVE_LIVE;
    if (instr_is_interrupt(instr) || instr_is_syscall(instr))
        return LIVE_LIVE;
    if (instr_reads_from_reg(instr, reg))
        return LIVE_LIVE;
    if (instr_writes_to_exact_reg(instr, reg))
        return LIVE_DEAD;
    return liveness;
}

static instr_t *
pattern_find_aflags_save_label(instr_t *restore, ptr_uint_t note_restore,
                               ptr_uint_t *note_save)
{
    ptr_uint_t note;
    instr_t *save;
    for (save  = instr_get_prev(restore);
         save != NULL;
         save  = instr_get_prev(save)) {
        if (!instr_is_label(save))
            continue;
        note = (ptr_uint_t)instr_get_note(save);
        if (note != (note_base + NOTE_SAVE_AFLAGS) &&
            note != (note_base + NOTE_SAVE_AFLAGS_WITH_EAX))
            continue;
        ASSERT((note         == (note_base + NOTE_SAVE_AFLAGS) && 
                note_restore == (note_base + NOTE_RESTORE_AFLAGS)) ||
               (note         == (note_base + NOTE_SAVE_AFLAGS_WITH_EAX) &&
                note_restore == (note_base + NOTE_RESTORE_AFLAGS_WITH_EAX)),
               "Mis-match on eax save/restore");
        *note_save = note;
        return save;
    }
    return NULL;
}

/* remove aflags save/restore pair if aflags is dead,
 * returns the prev instr of the aflag save label instr.
 */
static instr_t *
pattern_remove_aflags_pair(void *drcontext, instrlist_t *ilist,
                           instr_t *restore, ptr_uint_t note_restore)
{
    instr_t *save, *prev;
    ptr_uint_t note_save;
    save = pattern_find_aflags_save_label(restore, note_restore, &note_save);
    ASSERT(save != NULL, "Mis-match on aflags save/restore");
    prev = instr_get_prev(save);
    instrlist_remove(ilist, restore);
    instr_destroy(drcontext, restore);
    instrlist_remove(ilist, save);
    instr_destroy(drcontext, save);
    return prev;
}

/* XXX: we should use the utility code in fastpath instead,
 * which requires scratch_reg_info to be constructed.
 */
static void
pattern_insert_save_aflags(void *drcontext, instrlist_t *ilist, instr_t *save,
                           bool save_app_xax, bool restore_app_xax)
{
    IF_DEBUG(ptr_uint_t note = (ptr_uint_t)instr_get_note(save);)
    ASSERT(note != 0 && instr_is_label(save), "wrong aflags save label");
    if (save_app_xax) {
        /* save app xax */
        spill_reg(drcontext, ilist, save, DR_REG_XAX, PATTERN_SLOT_XAX);
    }
    /* save aflags,
     * XXX: we can track oflag usage to avoid saving oflag for some cases.
     */
    insert_save_aflags_nospill(drcontext, ilist, save, true /* save oflag */);

    PRE(ilist, save, INSTR_CREATE_lahf(drcontext));
    PRE(ilist, save,
        INSTR_CREATE_setcc(drcontext, OP_seto,
                           opnd_create_reg(DR_REG_AL)));
    if (restore_app_xax) {
        /* save aflags into tls slot */
        spill_reg(drcontext, ilist, save, DR_REG_XAX, PATTERN_SLOT_AFLAGS);
        /* restore app xax */
        restore_reg(drcontext, ilist, save, DR_REG_XAX, PATTERN_SLOT_XAX);
    }
}

/* XXX: we should use the utility code in fastpath instead,
 * which requires scratch_reg_info to be constructed.
 */
static void
pattern_insert_restore_aflags(void *drcontext, instrlist_t *ilist,
                              instr_t *restore,
                              bool load_aflags, bool restore_app_xax)
{
    IF_DEBUG(ptr_uint_t note = (ptr_uint_t)instr_get_note(restore);)
    ASSERT(note != 0 && instr_is_label(restore), "wrong aflags restore label");
    if (load_aflags) {
        /* restore aflags from tls slot to xax */
        restore_reg(drcontext, ilist, restore, DR_REG_XAX, PATTERN_SLOT_AFLAGS);
    }
    /* restore aflags
     * XXX: we can track oflag usage to avoid restsoring oflag for some cases.
     */
    insert_restore_aflags_nospill(drcontext, ilist, restore, true);
    if (restore_app_xax) {
        /* restore app xax */
        restore_reg(drcontext, ilist, restore, DR_REG_XAX, PATTERN_SLOT_XAX);
    }
}

/* insert the aflags save/restore pair, return the prev instr of aflags save */
static instr_t *
pattern_insert_aflags_pair(void *drcontext, instrlist_t *ilist,
                           instr_t *restore,
                           ptr_uint_t note_restore, int eax_live)
{
    instr_t *save, *prev;
    ptr_uint_t note_save = (note_base + NOTE_NULL);
    save = pattern_find_aflags_save_label(restore, note_restore, &note_save);
    ASSERT(save != NULL, "Mis-match on aflags save/restore");
    prev = instr_get_prev(save);
    pattern_insert_save_aflags(drcontext, ilist, save, eax_live != LIVE_DEAD, 
                               note_save == (note_base + NOTE_SAVE_AFLAGS_WITH_EAX));
    pattern_insert_restore_aflags(drcontext, ilist, restore,
                                  note_restore == (note_base +
                                                   NOTE_RESTORE_AFLAGS_WITH_EAX),
                                  eax_live != LIVE_DEAD);
    instrlist_remove(ilist, restore);
    instr_destroy(drcontext, restore);
    instrlist_remove(ilist, save);
    instr_destroy(drcontext, save);
    return prev;
}

/* reverse scan for aflags save/restore instrumentation and other optimization.
 * To minimize the runtime overhead, we perform the reverse scan to update the
 * register and aflag's liveness. In forward scan, the instruction list has to be
 * traversed multiple passes for liveness analysis.
 * XXX: we might have to let reverse scan pass go away w/ drmgr, which supports 
 * forward per-instr instrumentation only.
 */
void
pattern_instrument_reverse_scan(void *drcontext, instrlist_t *ilist)
{
    instr_t *instr, *prev;
    ptr_uint_t note;
    int eax_live    = LIVE_LIVE;
    int aflags_live = LIVE_LIVE;

    for (instr  = instrlist_last(ilist);
         instr != NULL;
         instr  = prev) {
        prev = instr_get_prev(instr);
        if (instr_ok_to_mangle(instr)) {
            eax_live = pattern_reg_liveness_update_on_reverse_scan
                (instr, DR_REG_XAX, eax_live);
            aflags_live = pattern_aflags_liveness_update_on_reverse_scan
                (instr, aflags_live);
        }
        if (!instr_is_label(instr))
            continue;
        note = (ptr_uint_t)instr_get_note(instr);
        if (note == (note_base + NOTE_NULL))
            continue;
        /* XXX: i#776
         * instead of blindly insert aflags save and restore, we
         * have some possible optimizations:
         * 1. DONE: only save/restore aflags when necessary
         * 2. DONE: only save/restore eax when necessary
         * 3. TODO: fine tune the aflags liveness, i.e. overflow flags
         * 3. TODO: group aflags save/restore if aflags and eax not touched 
         *    (can be relaxed later) 
         */
        if (note == (note_base + NOTE_RESTORE_AFLAGS) ||
            note == (note_base + NOTE_RESTORE_AFLAGS_WITH_EAX)) {
            if (aflags_live == LIVE_DEAD) {
                /* aflags is dead, we do not need to save them, remove  */
                prev = pattern_remove_aflags_pair(drcontext, ilist, instr, note);
            } else {
                prev = pattern_insert_aflags_pair(drcontext, ilist, instr, note,
                                                  eax_live);
            }
        }
    }
}

static bool
pattern_ill_instr_is_instrumented(byte *pc)
{
    byte buf[6];
    /* check if our code sequence */
    if (!safe_read(pc - JNZ_SHORT_LENGTH - 2 /* 2 bytes of cmp immed value */,
                   BUFFER_SIZE_BYTES(buf), buf)   ||
        buf[0] != (byte)options.pattern           ||
        buf[1] != (byte)(options.pattern >> 8)    ||
        buf[2] != JNZ_SHORT_OPCODE                || 
        buf[3] != UD2A_LENGTH                     ||
        *(ushort *)&buf[4] != (ushort)UD2A_OPCODE)
        return false;
    return true;
}

bool
pattern_handle_ill_fault(void *drcontext,
                         dr_mcontext_t *raw_mc,
                         dr_mcontext_t *mc)
{
    app_pc addr;
    bool   is_write;
    int    memopidx;
    instr_t instr;
    uint   pos;
    ASSERT(options.pattern != 0, "incorrectly called");
    /* check if ill-instr is our code */
    if (!pattern_ill_instr_is_instrumented(raw_mc->pc))
        return false;
    /* get the information of the instr that triggered the ill fault.
     * will report on all unaddr refs in this instr and don't care
     * which one triggered the ud2a
     */
    instr_init(drcontext, &instr);
    decode(drcontext, mc->pc, &instr);
    for (memopidx = 0;
         instr_compute_address_ex_pos(&instr, mc, memopidx,
                                      &addr, &is_write, &pos);
         memopidx++) {
        app_loc_t loc;
        size_t size = 0;
        opnd_t opnd = is_write ? 
            instr_get_dst(&instr, pos) : instr_get_src(&instr, pos);
        if (!pattern_opnd_need_check(opnd))
            continue;
        size = opnd_size_in_bytes(opnd_get_size(opnd));
        pc_to_loc(&loc, mc->pc);
        pattern_handle_mem_ref(&loc, addr, size, mc, is_write);
    }
    instr_free(drcontext, &instr);
    /* we are not skipping all cmps for this instr, which is ok because we 
     * clobberred the pattern if a 2nd memref was unaddr.
     */
    LOG(2, "pattern check ud2a triggerred@"PFX" => skip to "PFX"\n",
        raw_mc->pc, raw_mc->pc + UD2A_LENGTH);
    raw_mc->pc += UD2A_LENGTH;
    STATS_INC(num_slowpath_faults);
    return true;
}

static bool
pattern_segv_instr_is_instrumented(byte *pc, byte *next_next_pc,
                                   instr_t *inst, instr_t *next)
{
    ushort ud2a;
    /* check code sequence: cmp; jne_short; ud2a */
    if (instr_get_opcode(inst) == OP_cmp &&
        instr_get_opcode(next) == OP_jne_short &&
        safe_read(next_next_pc, sizeof(ushort), &ud2a) &&
        ud2a == (ushort)UD2A_OPCODE) {
        DODEBUG({
            opnd_t opnd = instr_get_src(inst, 1);
            ASSERT(opnd_is_immed_int(opnd), "Similar code sequence is seen");
            if (opnd_get_size(opnd) == OPSZ_4) {
                ASSERT(opnd_get_immed_int(opnd) == (int)options.pattern,
                       "Similar code sequence is seen");
            } else {
                ASSERT((ushort)opnd_get_immed_int(opnd) ==
                       (ushort)options.pattern,
                       "Similar code sequence is seen");
            }
        });
        return true;
    }
    return false;
}

bool
pattern_addr_in_redzone(byte *addr)
{

    bool res = false;
    rb_node_t *node;
    dr_rwlock_read_lock(pattern_malloc_tree_rwlock);
    node = rb_in_node(pattern_malloc_tree, addr);
    if (node != NULL) {
        byte *start;
        size_t size;
        void *data;
        size_t app_size;
        rb_node_fields(node, &start, &size, &data);
        app_size = (size_t)data;
        ASSERT(app_size + options.redzone_size * 2 <= size,
               "wrong node information");
        if (addr <  start + options.redzone_size || 
            addr >= start + options.redzone_size + app_size)
            res = true;
    }
    dr_rwlock_read_unlock(pattern_malloc_tree_rwlock);
    return res;
}

/* In pattern mode, there are several possible ways that segv fault happens
 * - wrong pc
 *   + it is more possible to be a bug, do nothing and return false;
 * - app code
 *   + if it is intended segv fault, app will handle it, do not report
 *   + if it is unintended, app will crash natively, do not report either.
 *   + return false for both cases
 * - instrumented code, i.e. pattern check code
 *   + trigger the segv before app
 *   + skip the check and continue
 */
bool
pattern_handle_segv_fault(void *drcontext, dr_mcontext_t *raw_mc)
{
    bool ours = false;
    instr_t inst, next;
    byte *next_pc;

    /* check if wrong pc */
    instr_init(drcontext, &inst);
    instr_init(drcontext, &next);
    if (!safe_decode(drcontext, raw_mc->pc, &inst, &next_pc))
        goto handle_light_mode_segv_fault_done;
    if (!safe_decode(drcontext, next_pc, &next, &next_pc))
        goto handle_light_mode_segv_fault_done;
    /* check if our own code */
    if (!pattern_segv_instr_is_instrumented(raw_mc->pc, next_pc, &inst, &next))
        goto handle_light_mode_segv_fault_done;
    /* skip pattern check code */
    LOG(2, "pattern check cmp fault@"PFX" => skip to "PFX"\n",
        raw_mc->pc, next_pc + UD2A_LENGTH);
    raw_mc->pc = next_pc + UD2A_LENGTH;
    ours = true;
  handle_light_mode_segv_fault_done:
    instr_free(drcontext, &inst);
    instr_free(drcontext, &next);
    return ours;
}

void
pattern_handle_malloc(app_pc app_base,  size_t app_size,
                      app_pc real_base, size_t real_size)
{
    ASSERT(options.pattern != 0, "should not be called");
    if ((app_base - real_base) == options.redzone_size) {
        uint *redzone;
        IF_DEBUG(rb_node_t *node;)
        dr_rwlock_write_lock(pattern_malloc_tree_rwlock);
        /* due to padding, the real_size might be larger than 
         * (app_size + redzone_size*2), which makes the size of 
         * rear redzone not fixed, so store app_size in rb_tree.
         */
        IF_DEBUG(node =) rb_insert(pattern_malloc_tree, real_base,
                                   real_size, (void *)app_size);
        dr_rwlock_write_unlock(pattern_malloc_tree_rwlock);
        ASSERT(node == NULL, "error in inserting pattern malloc tree");
        ASSERT(ALIGNED(real_base, sizeof(uint)), "real base is unaligned");
        ASSERT(ALIGNED(real_size, sizeof(uint)), "real size is unaligned");
        for (redzone = (uint *)real_base; redzone < (uint *)app_base; redzone++)
            *redzone = options.pattern;
        /* the app_size might be unaligned, which will be expanded with padding
         * by allocator. We will fill the padding whenever possible.
         */
        if (!ALIGNED((app_base + app_size), 4)) {
            /* the pattern must be 2-byte aligned */
            *(ushort *)ALIGN_FORWARD((app_base + app_size), 2) = 
                (ushort)options.pattern;
        }
        for (redzone = (uint *)ALIGN_FORWARD((app_base + app_size), 4);
             redzone < (uint *)(real_base + real_size);
             redzone++)
            *redzone = options.pattern;
    } else {
        ASSERT(malloc_is_pre_us(app_base), "unknow malloc region");
    }
}

void
pattern_handle_real_free(app_pc base, size_t size, bool delayed)
{
    ASSERT(options.pattern != 0, "should not be called");
    /* XXX i#786: we should move this part to malloc hanlding if we
     * properly invalidate rbtree on malloc.
     */
    if (delayed) {
        /* if delayed, the base and size are real base and size */
        /* removing the pattern to avoid false positive faults. */
        memset(base, 0, size);
    } else {
        /* if !delayed, the base is app base, and the size is app size.
         * we can ignore the size since our rbtree holds the app_size,
         * now use passed in size for sanity check.
         */
        rb_node_t *node;
        app_pc real_base;
        size_t real_size, app_size = 0;
        void *data;

        dr_rwlock_write_lock(pattern_malloc_tree_rwlock);
        node = rb_find(pattern_malloc_tree, base - options.redzone_size);
        if (node != NULL) {
            rb_node_fields(node, &real_base, &real_size, &data);
            app_size = (size_t)data;
            ASSERT(real_base == (base - options.redzone_size) &&
                   real_size >= (app_size + options.redzone_size * 2) &&
                   size == app_size,
                   "error in pattern malloc tree node");
            /* XXX i#786: we simply remove the memory here, which can be 
             * improved by invalidating/removing malloc rbtree instead,
             * though we still need do the lookup to change the node status.
             */
            rb_delete(pattern_malloc_tree, node);
        }
        dr_rwlock_write_unlock(pattern_malloc_tree_rwlock);
        /* if !delayed, only need remove the pattern in redzone */
        if (node != NULL) {
            memset(real_base, 0, options.redzone_size);
            memset(base + app_size, 0,
                   real_size - app_size - options.redzone_size);
        } else {
            ASSERT(malloc_is_pre_us(app_base), "unknow malloc region");
        }
    }
}

void
pattern_handle_delayed_free(app_pc base, size_t size)
{
    uint *redzone;
    app_pc real_base;
    size_t real_size, app_size = 0;
    void *data;
    rb_node_t *node;
    ASSERT(options.pattern != 0, "should not be called");

    dr_rwlock_write_lock(pattern_malloc_tree_rwlock);
    node = rb_find(pattern_malloc_tree, base - options.redzone_size);
    if (node != NULL) {
        rb_node_fields(node, &real_base, &real_size, &data);
        app_size = (size_t)data;
        ASSERT(real_base == (base - options.redzone_size) &&
               real_size >= (app_size + options.redzone_size * 2) &&
               (size == 0 || size == app_size), 
               "error in pattern malloc tree node");
        /* XXX i#786: we simply remove the memory here, which can be improved
         * by invalidating/removing malloc rbtree instead, though we still 
         * need do the lookup to change the node status.
         */
        rb_delete(pattern_malloc_tree, node);
    }
    dr_rwlock_write_unlock(pattern_malloc_tree_rwlock);
    /* We assume the actually alloced block length will be 4-byte aligned,
     * e.g. if size is 2, the allocator will alloc 4 bytes instead,
     * so it is ok to fill 4-byte uint pattern.
     */
    ASSERT(ALIGNED(base, 4), "unaligned pointer for free");
    for (redzone = (uint *)ALIGN_BACKWARD(base, 4);
         redzone < (uint *)(base + app_size);
         redzone++)
        *redzone = options.pattern;
}

void
pattern_handle_realloc(app_pc old_base, size_t old_size,
                       app_pc new_base, size_t new_size, app_pc new_real_base)
{
    /* FIXME: i#779, support -no_replace_realloc for pattern mode */
    ASSERT(options.replace_realloc, "-no_replace_realloc not supported");
}

/* returns true if no errors were found */
bool
pattern_handle_mem_ref(app_loc_t *loc, app_pc addr, size_t size,
                       dr_mcontext_t *mc, bool is_write)
{
    uint val;
    size_t check_sz;
    /* XXX i#774: for ref of >4 byte, we check the starting 4-byte */
    check_sz = size < 4 ? 2 : 4;
    /* there are several memory opnd, so it should be faster to check
     * before lookup in the rbtree.
     */
    if ((safe_read(addr, check_sz, &val) &&
         (ushort)val == (ushort)options.pattern &&
         (check_sz == 4 ? val == options.pattern : true)) &&
        (pattern_addr_in_redzone(addr) ||
         overlaps_delayed_free(addr, addr + size, NULL, NULL, NULL))) {
        /* XXX: i#786: the actually freed memory is neither in malloc tree
         * nor in delayed free rbtree, in which case we cannot detect. We 
         * can maintain the information in pattern malloc tree, i.e. mark 
         * the tree node as invalid on free and remove/change the tree
         * node on re-use of the memory.
         */
        if (!check_unaddressable_exceptions(is_write, loc, addr, size,
                                            false, mc)) {
            report_unaddressable_access(loc, addr, size, is_write,
                                        addr, addr + size, mc);
        }
        /* clobber the pattern to avoid duplicate reports for this same addr
         * or possible ud2a if the 2nd memref is also unaddressable.
         */
        /* should this be a safe_write?
         * we reach here which means safe_read works and
         * it is in redzone or delayed free, so not worth the overhead.
         */
        if (check_sz == 4)
            *(uint *)addr = 0;
        else
            *(ushort *)addr = 0;
        return false;
    }
    return true;
}

void
pattern_init(void)
{
    ASSERT(options.pattern != 0, "should not be called");
    pattern_malloc_tree = rb_tree_create(NULL);
    pattern_malloc_tree_rwlock = dr_rwlock_create();

    note_base = drmgr_reserve_note_range(NOTE_MAX_VALUE);
    ASSERT(note_base != DRMGR_NOTE_NONE, "failed to get note value");
}

void
pattern_exit(void)
{
    ASSERT(options.pattern != 0, "should not be called");
    dr_rwlock_destroy(pattern_malloc_tree_rwlock);
    rb_tree_destroy(pattern_malloc_tree);
}
