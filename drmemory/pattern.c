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

/***************************************************************************
 * Pattern mode instrumentation functions
 */

#define MAX_REFS_PER_INSTR 3
#define PATTERN_SLOT_XAX    SPILL_SLOT_1
#define PATTERN_SLOT_AFLAGS SPILL_SLOT_2
#define SWAP_BYTE(x)  ((0x0ff & ((x) >> 8)) | ((0x0ff & (x)) << 8))
#define PATTERN_REVERSE(x) (SWAP_BYTE(x) | (SWAP_BYTE(x) << 16))

/* we can use a redblack tree to keep malloc info */
static rb_tree_t *pattern_malloc_tree;
static void *pattern_malloc_tree_rwlock;
static uint  pattern_reverse;

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
bool
pattern_opnd_needs_check(opnd_t opnd)
{
    ASSERT(options.pattern != 0, "should not be called");
    ASSERT(opnd_is_memory_reference(opnd), "not a memory reference");
    ASSERT(!options.check_stack_access, "no stack check");
    /* We are only interested in heap objects in pattern mode, 
     * so no absolute address or pc relative address.
     */
    if (opnd_is_abs_addr(opnd))
        return false;
#ifdef X64
    if (opnd_is_rel_addr(opnd))
        return false;
#endif
    ASSERT(opnd_is_base_disp(opnd), "not a base disp opnd");
    return true;
}

static void
pattern_handle_xlat(void *drcontext, instrlist_t *ilist, instr_t *app, bool pre)
{
    /* xlat accesses memory (xbx, al), which is not a legeal memory operand,
     * and we use (xbx, xax) to emulate (xbx, al) instead:
     * save xax; movzx xax, al; ...; restore xax; ...; xlat 
     */
    if (pre) {
        /* we do not rely on whole_bb_spills_enabled to save eax!
         * for cases like:
         * aflags save; mov 0 => [mem], mov 1 => eax; xlat;
         * the value in spill_slot_5 is out-of-date!
         */
        spill_reg(drcontext, ilist, app, DR_REG_XAX, 
                  whole_bb_spills_enabled() ?
                  /* when whole_bb_spills_enabled, app's xax value is stored
                   * in SPILL_SLOT_5 in save_aflags_if_live, so are we here
                   * for consistency.
                   */
                  SPILL_SLOT_5 : PATTERN_SLOT_XAX);
        PRE(ilist, app, INSTR_CREATE_movzx(drcontext,
                                           opnd_create_reg(DR_REG_XAX),
                                           opnd_create_reg(DR_REG_AL)));
    } else {
        /* restore xax */
        restore_reg(drcontext, ilist, app, DR_REG_XAX,
                    whole_bb_spills_enabled() ?
                    SPILL_SLOT_5 : PATTERN_SLOT_XAX);
    }
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
    opnd_size_t opsz, size = opnd_get_size(ref);
    instr_t *label;
    int opcode = instr_get_opcode(app);
    app_pc pc = instr_get_app_pc(app);
    opnd_t opnd;

    ASSERT(opnd_uses_nonignorable_memory(ref),
           "non-memory-ref opnd is instrumented");
    label = INSTR_CREATE_label(drcontext);
    /* XXX: i#774, we perform 2-byte check for 1/2-byte reference and 4-byte 
     * otherwise, should we do 2 4-byte checks for case like 8-byte reference?
     */
    if (size > OPSZ_2) {
        opsz = OPSZ_4;
        opnd = OPND_CREATE_INT32(options.pattern);
    } else {
        opsz = OPSZ_2;
        opnd = OPND_CREATE_INT16((short)options.pattern);
    }
    opnd_set_size(&ref, opsz);
    /* special handling for xlat instr */
    if (opcode == OP_xlat)
        pattern_handle_xlat(drcontext, ilist, app, true /* pre */);
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
    /* insert check for unaligned one-byte access */
    if (size == OPSZ_1) {
        opnd  = OPND_CREATE_INT16((short)pattern_reverse);
        label = INSTR_CREATE_label(drcontext);
        /* cmp ref, pattern_reverse */
        PREXL8M(ilist, app,
                INSTR_XL8(INSTR_CREATE_cmp(drcontext, ref, opnd), pc));
        /* jne label */
        PRE(ilist, app, INSTR_CREATE_jcc_short(drcontext, OP_jne_short,
                                               opnd_create_instr(label)));
        /* use ud2a to cause an illegal exception if match. */
        PREXL8M(ilist, app, INSTR_XL8(INSTR_CREATE_ud2a(drcontext), pc));
        /* label */
        PRE(ilist, app, label);
    }
    if (opcode == OP_xlat)
        pattern_handle_xlat(drcontext, ilist, app, false /* post */);
}

static void
pattern_insert_aflags_label(void *drcontext, instrlist_t *ilist, instr_t *where,
                            bool save, bool with_eax)
                            
{
    instr_t *label = INSTR_CREATE_label(drcontext);
    ptr_uint_t note = note_base;

    if (save) {
        if (with_eax)
            note = note_base + NOTE_SAVE_AFLAGS_WITH_EAX;
        else
            note = note_base + NOTE_SAVE_AFLAGS;
    } else {
        if (with_eax)
            note = note_base + NOTE_RESTORE_AFLAGS_WITH_EAX;
        else
            note = note_base + NOTE_RESTORE_AFLAGS;
    }
    instr_set_note(label, (void *)note);
    PRE(ilist, where, label);
}

static int
pattern_extract_refs(instr_t *app, bool *use_eax, opnd_t *refs
                     _IF_DEBUG(int max_num_refs))
{
    int i, j, num_refs = 0;
    opnd_t opnd;

    if (instr_get_opcode(app) == OP_xlat) {
        /* we use (%xbx, %xax) to emulate xlat's (%xbx, %al) */
        refs[0] = opnd_create_base_disp(DR_REG_XBX, DR_REG_XAX, 1, 0, OPSZ_1);
        *use_eax = true;
        return 1;
    }
    /* we do not handle stack access including OP_enter/OP_leave. */
    ASSERT(!options.check_stack_access, "no stack check");
    for (i = 0; i < instr_num_srcs(app); i++) {
        opnd = instr_get_src(app, i);
        if (opnd_uses_nonignorable_memory(opnd)) {
            ASSERT(num_refs < max_num_refs, "too many refs per instr");
            refs[num_refs] = opnd;
            num_refs++;
            if (opnd_uses_reg(opnd, DR_REG_XAX))
                *use_eax = true;
        }
    }
    for (i = 0; i < instr_num_dsts(app); i++) {
        opnd = instr_get_dst(app, i);
        if (opnd_uses_nonignorable_memory(opnd)) {
            for (j = 0; j < num_refs; j++) {
                /* skip case like ADD [mem], val => [mem] */
                if (opnd_same(refs[j], opnd))
                    break;
            }
            ASSERT(num_refs < max_num_refs, "too many refs per instr");
            refs[num_refs] = opnd;
            num_refs++;
            if (opnd_uses_reg(opnd, DR_REG_XAX))
                *use_eax = true;
        }
    }
    return num_refs;
}

void
pattern_instrument_check(void *drcontext, instrlist_t *ilist, instr_t *app,
                         bb_info_t *bi)
{
    int num_refs, i;
    opnd_t refs[MAX_REFS_PER_INSTR];
    bool use_eax = false;

    if (instr_get_opcode(app) == OP_lea || 
        instr_is_prefetch(app) ||
        instr_is_nop(app))
        return;

    num_refs = pattern_extract_refs(app, &use_eax, refs
                                    _IF_DEBUG(MAX_REFS_PER_INSTR));
    if (num_refs == 0)
        return;
    mark_eflags_used(drcontext, ilist, bi);
    bi->added_instru = true;
    if (!whole_bb_spills_enabled()) {
        /* aflags save label */
        pattern_insert_aflags_label(drcontext, ilist, app, true, use_eax);
    }
    /* pattern check code */
    for (i = 0; i < num_refs; i++)
        pattern_insert_check_code(drcontext, ilist, app, refs[i]);
    if (!whole_bb_spills_enabled()) {
        /* aflags restore label */
        pattern_insert_aflags_label(drcontext, ilist, app, false, use_eax);
    }
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
        (buf[2] != JNZ_SHORT_OPCODE) || 
        (buf[3] != UD2A_LENGTH)      ||
        ((*(ushort *)&buf[0] != (ushort)options.pattern) &&
         (*(ushort *)&buf[0] != (ushort)pattern_reverse)) ||
        (*(ushort *)&buf[4] != (ushort)UD2A_OPCODE))
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
    STATS_INC(num_slowpath_faults);
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
        if (!opnd_uses_nonignorable_memory(opnd))
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
                ASSERT(opnd_get_immed_int(opnd) == (int)options.pattern ||
                       opnd_get_immed_int(opnd) == (int)pattern_reverse,
                       "Similar code sequence is seen");
            } else {
                ASSERT((ushort)opnd_get_immed_int(opnd) ==
                       (ushort)options.pattern ||
                       (ushort)opnd_get_immed_int(opnd) ==
                       (ushort)pattern_reverse,
                       "Similar code sequence is seen");
            }
        });
        return true;
    }
    return false;
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


/***************************************************************************
 * Memory allocation bookkeeping Functions
 */

static bool
pattern_addr_in_malloc_tree(byte *addr, size_t size)
{
    rb_node_t *node;
    bool res = false;

    /* walk the pattern_malloc_tree */
    dr_rwlock_read_lock(pattern_malloc_tree_rwlock);
    node = rb_in_node(pattern_malloc_tree, addr);
    if (node != NULL) {
        byte *start;
        void *data;
        size_t real_size;
        size_t app_size;
        rb_node_fields(node, &start, &real_size, &data);
        app_size = (size_t)data;
        ASSERT(app_size + options.redzone_size * 2 <= real_size,
               "wrong node information");
        if (addr <  start + options.redzone_size || 
            addr >= start + options.redzone_size + app_size)
            res = true;
    }
    dr_rwlock_read_unlock(pattern_malloc_tree_rwlock);
    return res;
}

static void
pattern_insert_malloc_tree(byte *app_base,  size_t app_size,
                           byte *real_base, size_t real_size)
{
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
}

static void
pattern_remove_malloc_tree(app_pc app_base, size_t app_size, size_t real_size)
{
    rb_node_t *node;
    void *data;
    app_pc real_base;
    size_t size;

    dr_rwlock_write_lock(pattern_malloc_tree_rwlock);
    node = rb_find(pattern_malloc_tree, app_base - options.redzone_size);
    if (node != NULL) {
        rb_node_fields(node, &real_base, &size, &data);
        ASSERT(app_size  == (size_t)data,
               "wrong app size in pattern malloc tree");
        ASSERT(real_base == app_base - options.redzone_size,
               "wrong real_base in pattern malloc tree");
        ASSERT(real_size == size &&
               real_size >= app_size + options.redzone_size * 2,
               "Wrong real_size in pattern malloc tree");
        /* XXX i#786: we simply remove the memory here, which can be 
         * improved by invalidating/removing malloc rbtree instead,
         * though we still need do the lookup to change the node status.
         */
        rb_delete(pattern_malloc_tree, node);
    }
    dr_rwlock_write_unlock(pattern_malloc_tree_rwlock);
}

typedef struct _pattern_malloc_iter_data_t {
    byte *addr;
    size_t size;
    bool found;
} pattern_malloc_iter_data_t;

static bool
pattern_malloc_iterate_cb(app_pc start, app_pc end, app_pc real_end,
                          bool pre_us, uint client_flags,
                          void *client_data, void *iter_data)
{
    pattern_malloc_iter_data_t *data = (pattern_malloc_iter_data_t *) iter_data;
    ASSERT(iter_data != NULL, "invalid iteration data");
    ASSERT(start != NULL && start <= end, "invalid params");
    LOG(4, "malloc iter: "PFX"-"PFX"%s\n", start, end, pre_us ? ", pre-us" : "");
    ASSERT(!data->found, "the iteration should be short-circuited");
    if (pre_us)
        return true;
    if ((data->addr >= start - options.redzone_size && data->addr < start) ||
        (data->addr >= end && data->addr < real_end)) {
        data->found = true;
        return false;
    }
    return true;
}

static bool
pattern_addr_in_malloc_table(byte *addr, size_t size)
{
    pattern_malloc_iter_data_t iter_data = {addr, size, false};
    /* walk the hashtable */
    malloc_iterate(pattern_malloc_iterate_cb, &iter_data);
    if (iter_data.found)
        return true;
    return false;
}


/* If an addr contains pattern value, we check the memory before and after,
 * and return true if there are enough number of contiguous pattern value.
 * XXX: the pattern value in the redzone could be clobbered by earlier error,
 * (see pattern_handle_ill_fault,) which may cause false negative here.
 * We can put clobber value and looking for it here instead.
 */
#define ADDR_PRE_CHECK_SIZE   (options.redzone_size)
#define ADDR_PRE_CHECK_COUNT  (ADDR_PRE_CHECK_SIZE / sizeof(uint))

static bool
pattern_addr_pre_check(byte *addr)
{
    uint *val;
    uint match = 0;
    int i;

    addr = (byte *) ALIGN_BACKWARD(addr, sizeof(uint));
    /* read memory after addr */
    DR_TRY_EXCEPT(dr_get_current_drcontext(), {
        /* we check the memory after aligned addr instead of addr 
         * to handle the case like:
         * char *p = malloc(3); *(p + 3) = ...;
         */
        val = (uint *)addr + 1;
        for (i = 0; i < ADDR_PRE_CHECK_COUNT; i++) {
            if (*val != options.pattern)
                break;
            val++;
            match++;
        }
    }, { /* EXCEPT */
    });
    if (match == ADDR_PRE_CHECK_COUNT)
        return true;
    DR_TRY_EXCEPT(dr_get_current_drcontext(), {
        val = (uint *)addr;
        for (i = 0; i < ADDR_PRE_CHECK_COUNT; i++) {
            if (*val != options.pattern)
                break;
            val--;
            match++;
        }
    }, { /* EXCEPT */
    });
    if (match == ADDR_PRE_CHECK_COUNT)
        return true;
    return false;
}

bool
pattern_addr_in_redzone(byte *addr, size_t size)
{
    bool res = false;
    /* we first do a pre-check to avoid expensive lookup */
    res  = pattern_addr_pre_check(addr);
    if (!res)
        return false;
    /* expensive walk */
    LOG(3, "expensive lookup for pattern_addr_in_redzone@"PFX"\n", addr);
    if (options.pattern_use_malloc_tree)
        res = pattern_addr_in_malloc_tree(addr, size);
    else
        res = pattern_addr_in_malloc_table(addr, size);
    return res;
}

void
pattern_handle_malloc(byte *app_base,  size_t app_size,
                      byte *real_base, size_t real_size)
{
    ASSERT(options.pattern != 0, "should not be called");
    ASSERT(ALIGNED(real_base, sizeof(uint)), "real base is unaligned");
    ASSERT(ALIGNED(real_size, sizeof(uint)), "real size is unaligned");

    if ((app_base - real_base) == options.redzone_size) {
        uint *redzone;
        if (options.pattern_use_malloc_tree)
            pattern_insert_malloc_tree(app_base, app_size, real_base, real_size);
        LOG(2, "set pattern value at "PFX"-"PFX" in redzone\n",
            real_base, app_base);
        for (redzone = (uint *)real_base; redzone < (uint *)app_base; redzone++)
            *redzone = options.pattern;
        /* the app_size might be unaligned, which will be expanded with padding
         * by allocator. We will fill the padding whenever possible.
         */
        redzone = (uint *) (app_base + app_size);
        LOG(2, "set pattern value at "PFX"-"PFX" in redzone\n",
            redzone, real_base + real_size);
        if (!ALIGNED(redzone, 2)) {
            *redzone = pattern_reverse;
        } else if (!ALIGNED(redzone, 4)) {
            /* the redzone must be 2-byte aligned, fill the 2-byte 
             * if it is not 4-byte aligned
             */
            *(ushort *)redzone = (ushort)options.pattern;
        }
        
        for (redzone = (uint *)ALIGN_FORWARD((app_base + app_size), 4);
             redzone < (uint *)(real_base + real_size);
             redzone++)
            *redzone = options.pattern;
    } else {
#if 0 /* FIXME: i#832, no redzone for debug CRT, so cannot use ASSERT here */
        ASSERT(malloc_is_pre_us(app_base), "unknown malloc region");
#endif
    }
}

void
pattern_handle_real_free(app_pc base, size_t size,
                         size_t real_size, bool delayed)
{
    ASSERT(options.pattern != 0, "should not be called");
    if (delayed) {
        /* if delayed, the base and size are real base and size */
        /* removing the pattern to avoid false positive faults. */
        LOG(2, "clear pattern value "PFX"-"PFX" %d bytes in freed block\n",
            base, base + size, size);
        memset(base, 0, size);
    } else {
        if (options.pattern_use_malloc_tree) {
            /* if !delayed, the base is app base, and the size is app size.
             * we can ignore the size since our rbtree holds the app_size,
             * now use passed in size for sanity check.
             */
            pattern_remove_malloc_tree(base, size, real_size);
        }
        /* if !delayed, only need remove the pattern in redzone */
        if (real_size >= (size + 2 * options.redzone_size)) {
            IF_DEBUG(uint val;)
            ASSERT(safe_read(base - options.redzone_size, sizeof(val), &val) &&
                   val == options.pattern, "wrong free address");
            LOG(2, "clear pattern value "PFX"-"PFX" %d bytes in redzone\n",
                base - options.redzone_size, base, options.redzone_size);
            memset(base - options.redzone_size, 0, options.redzone_size);
            LOG(2, "clear pattern value "PFX"-"PFX" %d bytes in redzone\n",
                base + size,
                base + size + (real_size - (size + options.redzone_size)),
                real_size - (size + options.redzone_size));
            memset(base + size, 0, real_size - (size + options.redzone_size));
        } else {
#if 0 /* FIXME: i#832, no redzone for debug CRT, so cannot use ASSERT here */
            ASSERT(malloc_is_pre_us(app_base), "unknown malloc region");
#endif
        }
    }
}

void
pattern_handle_delayed_free(app_pc base, size_t size, size_t real_size)
{
    uint *redzone;

    ASSERT(options.pattern != 0, "should not be called");
    /* We assume that any invalid free won't come here */
    ASSERT(ALIGNED(base, 4), "unaligned pointer for free");
    if (options.pattern_use_malloc_tree)
        pattern_remove_malloc_tree(base, size, real_size);
    /* We assume the actually alloced block length will be 4-byte aligned,
     * e.g. if size is 2, the allocator will alloc 4 bytes instead,
     * so it is ok to fill 4-byte uint pattern.
     */
    ASSERT(ALIGNED(base, 4), "unaligned pointer for free");
    LOG(2, "set pattern value at "PFX"-"PFX" in delay-freed block\n",
        base, base + size);
    for (redzone = (uint *) ALIGN_BACKWARD(base, 4);
         redzone < (uint *) (base + size);
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
pattern_handle_mem_ref(app_loc_t *loc, byte *addr, size_t size,
                       dr_mcontext_t *mc, bool is_write)
{
    uint val;
    size_t check_sz;
    /* XXX i#774: for ref of >4 byte, we check the starting 4-byte only */
    check_sz = (size <= 2) ? 2 : 4;
    /* there are several memory opnd, so it should be faster to check
     * before lookup in the rbtree.
     */
    if (safe_read(addr, check_sz, &val) &&
        ((ushort)val == (ushort)options.pattern ||
         (ushort)val == (ushort)pattern_reverse) &&
        (check_sz == 4 ? 
         (val == options.pattern || val == pattern_reverse)  : true) &&
        (pattern_addr_in_redzone(addr, size) ||
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

/***************************************************************************
 * Init/exit
 */

void
pattern_init(void)
{
    ASSERT(options.pattern != 0, "should not be called");
    if (options.pattern_use_malloc_tree) {
        pattern_malloc_tree = rb_tree_create(NULL);
        pattern_malloc_tree_rwlock = dr_rwlock_create();
    }
    note_base = drmgr_reserve_note_range(NOTE_MAX_VALUE);
    ASSERT(note_base != DRMGR_NOTE_NONE, "failed to get note value");

    /* reverse the byte order for unaligned checks:
     * for example, if the pattern is 0x43214321, the reversed pattern is
     * 0x21432143. If we check both value on any memory access, we are able
     * to check both aligned and unaligned access.
     */
    pattern_reverse = PATTERN_REVERSE(options.pattern);
}

void
pattern_exit(void)
{
    ASSERT(options.pattern != 0, "should not be called");
    if (options.pattern_use_malloc_tree) {
        dr_rwlock_destroy(pattern_malloc_tree_rwlock);
        rb_tree_destroy(pattern_malloc_tree);
    }
}
