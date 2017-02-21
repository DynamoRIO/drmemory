/* **********************************************************
 * Copyright (c) 2012-2016 Google, Inc.  All rights reserved.
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
#include "drreg.h"
#include "drutil.h"
#include "drmemory.h"
#include "slowpath.h"
#include "spill.h"
#include "pattern.h"
#include "shadow.h"
#include "stack.h"
#include "fastpath.h"
#include "alloc.h"
#include "redblack.h"
#include "report.h"
#include "alloc_drmem.h"

#ifdef UNIX
# include <signal.h> /* for SIGSEGV */
#endif

/***************************************************************************
 * Pattern mode instrumentation functions
 */

#define MAX_NUM_CHECKS_PER_REF 4
#define MAX_REFS_PER_INSTR 3
#define SWAP_BYTE(x)  ((0x0ff & ((x) >> 8)) | ((0x0ff & (x)) << 8))
#define PATTERN_REVERSE(x) (SWAP_BYTE(x) | (SWAP_BYTE(x) << 16))

/* we can use a redblack tree to keep malloc info */
static rb_tree_t *pattern_malloc_tree;
static void *pattern_malloc_tree_rwlock;
static uint  pattern_reverse;
static bool  pattern_4byte_check_only = false;
static void *flush_lock;

static int num_2byte_faults = 0;

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
#if defined(X64) || defined(ARM)
    if (opnd_is_rel_addr(opnd))
        return false;
#endif
#if defined(UNIX) && defined(X86)
    /* FIXME i#1812: check app TLS accesses.
     * DynamoRIO steals both TLS segment registers and mangles all app TLS accesses.
     * To check an app TLS access, we need extra instrumentation to steal a
     * register for holding app TLS segment base.
     */
    /* Assuming all non-TLS segment bases are 0, we can check those memory
     * accesses without special handling.
     */
    if (opnd_is_far_base_disp(opnd) &&
        (opnd_get_segment(opnd) == SEG_GS || opnd_get_segment(opnd) == SEG_FS))
        return false;
#endif
    ASSERT(opnd_is_base_disp(opnd), "not a base disp opnd");
    return true;
}

#ifdef X86
static void
pattern_handle_xlat(void *drcontext, instrlist_t *ilist, instr_t *app, bool pre)
{
    /* xlat accesses memory (xbx, al), which is not a legal memory operand,
     * and we use (xbx, xax) to emulate (xbx, al) instead:
     * save xax; movzx xax, al; ...; restore xax; ...; xlat
     */
    IF_DEBUG(drreg_status_t res);
    if (pre) {
        drvector_t allowed;
        reg_id_t scratch;
        drreg_init_and_fill_vector(&allowed, false);
        drreg_set_vector_entry(&allowed, DR_REG_XAX, true);
        IF_DEBUG(res =)
            drreg_reserve_register(drcontext, ilist, app, &allowed, &scratch);
        ASSERT(res == DRREG_SUCCESS && scratch == DR_REG_XAX, "failed to reserve eax");
        drvector_delete(&allowed);
        PRE(ilist, app, INSTR_CREATE_movzx(drcontext,
                                           opnd_create_reg(DR_REG_XAX),
                                           opnd_create_reg(DR_REG_AL)));
    } else {
        /* restore xax */
        IF_DEBUG(res =)
            drreg_unreserve_register(drcontext, ilist, app, DR_REG_XAX);
        ASSERT(res == DRREG_SUCCESS, "reg unreserve should work");
    }
}
#endif

/* Insert the code for pattern check on operand refs.
 * The instr sequence instrumented here is used in fault handling for
 * checking if it is the instrumented code. So if it is changed here,
 * the checking code in
 * - ill_instr_is_instrumented and
 * - segv_instr_is_instrumented
 * must be updated too.
 * The caller is responsible for preserving aflags.
 */
static void
pattern_insert_cmp_jne_ud2a(void *drcontext, instrlist_t *ilist, instr_t *app,
                            opnd_t ref, opnd_t pattern)
{
    instr_t *label;
    app_pc pc = instr_get_app_pc(app);
    IF_DEBUG(drreg_status_t res;)
#ifdef ARM
    uint i;
    reg_id_t scratch, scratch2;
    dr_pred_type_t pred = instr_get_predicate(app);
    instr_t *in;
    uint val = opnd_get_immed_int(pattern);
#endif

    label = INSTR_CREATE_label(drcontext);
    /* cmp ref, pattern */
#ifdef X86
    IF_DEBUG(res =)
        drreg_restore_app_values(drcontext, ilist, app, ref, NULL);
    ASSERT(res == DRREG_SUCCESS, "should restore memref regs");
    PREXL8M(ilist, app,
            INSTR_XL8(INSTR_CREATE_cmp(drcontext, ref, pattern), pc));
#elif defined(ARM)
    /* We use an inefficient but simple 2-scratch-reg scheme for now.
     * XXX: if we limit the pattern value to a 1-byte value we can do a direct
     * cmp in thumb mode via a repeated-4-times immed and avoid scratch2.
     * XXX: we could try sub;cbnz in an IT block to avoid clobbering the
     * flags, though cbnz requires r0-r7.
     * XXX: for ARM, there are no multi-byte immediates, but subX4 is faster
     * than movw,movt if there's no dead scratch2.
     */
    IF_DEBUG(res =)
        drreg_reserve_register(drcontext, ilist, app, NULL, &scratch);
    ASSERT(res == DRREG_SUCCESS, "should always find scratch reg");
    IF_DEBUG(res =)
        drreg_reserve_register(drcontext, ilist, app, NULL, &scratch2);
    ASSERT(res == DRREG_SUCCESS, "should always find 2nd scratch reg");
    /* To handle a predicated memref, because we can't predicate a conditional
     * branch nor OP_udf, we need an explicit branch to skip the OP_udf if the
     * app pred doesn't match.  We just skip all the instru and don't predicate.
     */
    if (pred != DR_PRED_NONE && pred != DR_PRED_AL) {
        PRE(ilist, app, INSTR_PRED
            (XINST_CREATE_jump_short(drcontext, opnd_create_instr(label)),
             instr_invert_predicate(pred)));
    }
    /* ldr scratch, ref */
    for (i = 0; i < opnd_num_regs_used(ref); i++) {
        reg_id_t reg = opnd_get_reg_used(ref, i);
        if (reg != dr_get_stolen_reg()) { /* stolen handled below */
            IF_DEBUG(res =)
                drreg_get_app_value(drcontext, ilist, app, reg, reg);
            ASSERT(res == DRREG_SUCCESS, "should get app value");
        }
    }
    /* XXX DRi#1834: sthg like drx_load_from_app_mem() would make this simpler if
     * it handled the stolen reg plus pc-relative (and far refs on x86).
     */
    if (opnd_uses_reg(ref, dr_get_stolen_reg())) {
        reg_id_t swap = opnd_uses_reg(ref, scratch) ? scratch2 : scratch;
        IF_DEBUG(bool ok;)
        ASSERT(!opnd_uses_reg(ref, swap), "opnd uses 3 different regs?!");
        IF_DEBUG(ok =)
            dr_insert_get_stolen_reg_value(drcontext, ilist, app, swap);
        ASSERT(ok, "failed to handle stolen register");
        IF_DEBUG(ok =)
            opnd_replace_reg(&ref, dr_get_stolen_reg(), swap);
        ASSERT(ok, "failed to replace reg");
    }
    if (opnd_get_size(ref) == OPSZ_1) {
        in = INSTR_CREATE_ldrb(drcontext, opnd_create_reg(scratch), ref);
    } else if (opnd_get_size(ref) == OPSZ_2) {
        in = INSTR_CREATE_ldrh(drcontext, opnd_create_reg(scratch), ref);
        if (!instr_is_encoding_possible(in)) {
            /* i#1879: the ISA is not symmetric and there is not a 2-byte
             * equivalent for every 1-byte load or store.
             */
            IF_DEBUG(bool ok = )
                drutil_insert_get_mem_addr(drcontext, ilist, app, ref, scratch,
                                           scratch2);
            ASSERT(ok, "failed to handle unusual sub-word memref");
            instr_destroy(drcontext, in);
            in = INSTR_CREATE_ldrh(drcontext, opnd_create_reg(scratch),
                                   OPND_CREATE_MEM16(scratch, 0));
        }
    } else {
        ASSERT(opnd_get_size(ref) == OPSZ_4, "unsupported ARM memref size");
        in = INSTR_CREATE_ldr(drcontext, opnd_create_reg(scratch), ref);
    }
    PREXL8M(ilist, app, INSTR_XL8(in, pc));
    /* movw+movt pattern to scratch2 */
    in = INSTR_CREATE_movw(drcontext, opnd_create_reg(scratch2),
                           OPND_CREATE_INT(val & 0xffff));
    PREXL8M(ilist, app, INSTR_XL8(in, pc));
    if (opnd_get_size(ref) == OPSZ_4) {
        in = INSTR_CREATE_movt(drcontext, opnd_create_reg(scratch2),
                               OPND_CREATE_INT(val >> 16));
        PREXL8M(ilist, app, INSTR_XL8(in, pc));
    }
    /* cmp scratch to scratch2 */
    /* XXX: we should switch to OP_teq to avoid clobbering the V flag, but
     * we'd need drreg to support granular flag reservations (DRi#1886) to
     * avoid an aflags spill.  Xref DRi#1877.
     */
    in = INSTR_CREATE_cmp(drcontext, opnd_create_reg(scratch),
                          opnd_create_reg(scratch2));
    PREXL8M(ilist, app, INSTR_XL8(in, pc));
    IF_DEBUG(res =)
        drreg_unreserve_register(drcontext, ilist, app, scratch2);
    ASSERT(res == DRREG_SUCCESS, "should always succeed");
    IF_DEBUG(res =)
        drreg_unreserve_register(drcontext, ilist, app, scratch);
    ASSERT(res == DRREG_SUCCESS, "should always succeed");
#endif

    /* jne label */
    /* XXX: add XINST_CREATE_xxxx cross-platform cbr macro to DR */
#ifdef X86
    PRE(ilist, app, INSTR_CREATE_jcc_short(drcontext, OP_jne_short,
                                           opnd_create_instr(label)));
#elif defined(ARM)
    PRE(ilist, app, INSTR_PRED
        (XINST_CREATE_jump_short(drcontext, opnd_create_instr(label)), DR_PRED_NE));
#endif
    /* we assume that the pattern seen is rare enough, so we use ud2a or udf to
     * cause an illegal exception on a match.
     */
#ifdef X86
    PREXL8M(ilist, app, INSTR_XL8(INSTR_CREATE_ud2a(drcontext), pc));
#elif defined(ARM)
    PREXL8M(ilist, app, INSTR_XL8(INSTR_CREATE_udf(drcontext, OPND_CREATE_INT32(0)), pc));
#endif
    /* label */
    PRE(ilist, app, label);
}

static int
pattern_create_check_opnds(bb_info_t *bi, opnd_t *refs, opnd_t *opnds
                           _IF_DEBUG(int max_refs /* size for both arrays */))
{
    opnd_size_t ref_size;

    ASSERT(max_refs >= 4 /* the max refs we might fill in */,
           "refs/opnds array is too small");
    /* refs[0] holds the actual app's memory reference opnd */
    ASSERT(opnd_is_base_disp(refs[0]), "wrong app's memory reference");
    /* XXX i#774: we perform 2-byte check for 1-byte or 2-byte reference and
     * 4-byte check for others.
     * Should we do something like 2 4-byte checks for 8-byte reference?
     */
    /* XXX i#881: detect access boundary of the redzone in pattern mode */
    ref_size = opnd_get_size(refs[0]);
    if (ref_size > OPSZ_2) {
        /* cmp [ref], pattern */
        opnd_set_size(&refs[0], OPSZ_4);
        opnds[0] = OPND_CREATE_INT32((int)options.pattern);
        return 1;
    }

    if (ref_size == OPSZ_2) {
        if (!bi->pattern_4byte_check_only) {
            /* cmp [ref], pattern */
            opnds[0] = OPND_CREATE_INT16((short)options.pattern);
            return 1;
        } else { /* 4byte_check_only mode */
            /* for a 2-byte ref, we assume it is aligned and
             * insert two 4-byte checks on [mem] and [mem-2].
             */
            /* cmp [ref], pattern */
            opnd_set_size(&refs[0], OPSZ_4);
            opnds[0] = OPND_CREATE_INT32((int)options.pattern);
            if (opnd_get_disp(refs[0]) < INT_MIN + 2) {
                /* In the case of wraparound, we give up the check on [mem-2],
                 * so there are possible false negatives on accessing the last
                 * 2 bytes of the redzone.
                 */
                return 1;
            }
            /* cmp [ref-2], pattern */
            refs[1]  = refs[0];
            opnd_set_disp(&refs[1], opnd_get_disp(refs[0]) - 2);
            opnds[1] = opnds[0];
            return 2;
        }
    }

    /* XXX i#811: because of using 2-byte pattern for checking,
     * we currently do not detect some boundary refs, e.g.
     * a single byte reference at the end of the redzone.
     */
    if (ref_size == OPSZ_1) {
        if (!bi->pattern_4byte_check_only) {
            /* cmp [ref], pattern */
            opnd_set_size(&refs[0], OPSZ_2);
            opnds[0] = OPND_CREATE_INT16((short)options.pattern);
            /* cmp [ref], pattern_reverse */
            refs[1]  = refs[0];
            opnds[1] = OPND_CREATE_INT16((short)pattern_reverse);
            return 2;
        } else { /* 4byte_check_only mode */
            /* for a 1-byte ref, we do not assume it is aligned and
             * insert 4 4-byte checks on [mem] and [mem-2] with
             * pattern and pattern_reverse.
             * It is possible to insert 3 4-byte checks on [mem], [mem-1],
             * and [mem-2] with pattern, but it will have false negative
             * in the malloc test case.
             */
            /* cmp [ref], pattern */
            opnd_set_size(&refs[0], OPSZ_4);
            opnds[0] = OPND_CREATE_INT32((int)options.pattern);
            /* cmp [ref], pattern_reverse */
            refs[1]  = refs[0];
            opnds[1] = OPND_CREATE_INT32((int)pattern_reverse);
            if (opnd_get_disp(refs[0]) < INT_MIN + 2) {
                /* In the case of wraparound, we give up the check on [mem-2]
                 * possible false negative on accessing the last 2-byte of
                 * the redzone.
                 */
                return 2;
            }
            /* cmp [ref - 2], pattern */
            refs[2]  = refs[0];
            opnd_set_disp(&refs[1], opnd_get_disp(refs[0]) - 2);
            opnds[2] = opnds[0];
            /* cmp [ref - 2], pattern_reverse */
            refs[3]  = refs[2];
            opnds[3] = opnds[1];
            return 4;
        }
    }
    return -1;
}

/* If not called during drmgr's insert phase, the caller must preserve aflags */
static void
pattern_insert_check_code(void *drcontext, instrlist_t *ilist,
                          instr_t *app, opnd_t ref, bb_info_t *bi)
{
    opnd_t refs[MAX_NUM_CHECKS_PER_REF], opnds[MAX_NUM_CHECKS_PER_REF];
    int num_checks, i;
    IF_DEBUG(drreg_status_t res);

    if (drmgr_current_bb_phase(drcontext) == DRMGR_PHASE_INSERTION) {
        IF_DEBUG(res =)
            drreg_reserve_aflags(drcontext, ilist, app);
        ASSERT(res == DRREG_SUCCESS, "reserve of aflags should work");
    }
    ASSERT(opnd_uses_nonignorable_memory(ref),
           "non-memory-ref opnd is instrumented");
#ifdef X86
    /* special handling for xlat instr */
    if (instr_get_opcode(app) == OP_xlat)
        pattern_handle_xlat(drcontext, ilist, app, true /* pre */);
#endif

    refs[0] = ref;
    num_checks = pattern_create_check_opnds(bi, refs, opnds
                                            _IF_DEBUG(MAX_NUM_CHECKS_PER_REF));
    ASSERT(num_checks > 0 && num_checks <= MAX_NUM_CHECKS_PER_REF,
           "Wrong number of checks created");
    for (i = 0; i < num_checks; i++)
        pattern_insert_cmp_jne_ud2a(drcontext, ilist, app, refs[i], opnds[i]);

#ifdef X86
    if (instr_get_opcode(app) == OP_xlat)
        pattern_handle_xlat(drcontext, ilist, app, false /* post */);
#endif

    if (drmgr_current_bb_phase(drcontext) == DRMGR_PHASE_INSERTION) {
        IF_DEBUG(res =)
            drreg_unreserve_aflags(drcontext, ilist, app);
        ASSERT(res == DRREG_SUCCESS, "unreserve of aflags should work");
    }
}

static int
pattern_extract_refs(instr_t *app, opnd_t *refs _IF_DEBUG(int max_num_refs))
{
    int i, j, num_refs = 0;
    opnd_t opnd;

#ifdef X86
    if (instr_get_opcode(app) == OP_xlat) {
        /* we use (%xbx, %xax) to emulate xlat's (%xbx, %al) */
        refs[0] = opnd_create_base_disp(DR_REG_XBX, DR_REG_XAX, 1, 0, OPSZ_1);
        return 1;
    }
#endif
    /* we do not handle stack access including OP_enter/OP_leave. */
    ASSERT(!options.check_stack_access, "no stack check");
    for (i = 0; i < instr_num_srcs(app); i++) {
        opnd = instr_get_src(app, i);
        if (opnd_uses_nonignorable_memory(opnd)) {
            ASSERT(num_refs < max_num_refs, "too many refs per instr");
            refs[num_refs] = opnd;
            num_refs++;
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
            if (j < num_refs)
                continue;
            ASSERT(num_refs < max_num_refs, "too many refs per instr");
            refs[num_refs] = opnd;
            num_refs++;
        }
    }
    return num_refs;
}

/* remove the instrumented check instructions between start and end */
static void
pattern_remove_check(void *drcontext, instrlist_t *ilist,
                     instr_t *start, instr_t *end)
{
    instr_t *instr, *next;
    ASSERT(start != NULL && instr_is_label(start) &&
           end != NULL   && instr_is_label(end),
           "missing start/end label");
    for (instr = start; instr != end; instr = next) {
        next = instr_get_next(instr);
        instrlist_remove(ilist, instr);
        instr_destroy(drcontext, instr);
    }
    ASSERT(instr == end, "wrong end label");
    instrlist_remove(ilist, end);
    instr_destroy(drcontext, end);
}

/* invalidate stored check info that its base reg is overwritten by the app */
static void
pattern_opt_elide_overlap_update_regs(instr_t *app, bb_info_t *bi)
{
    int i;
    elide_reg_cover_info_t *reg_cover = bi->reg_cover;
    for (i = 0; i < NUM_LIVENESS_REGS; i++) {
        if (reg_cover[i].status != ELIDE_REG_COVER_STATUS_NONE &&
            instr_writes_to_reg(app, REG_START + i, DR_QUERY_INCLUDE_ALL)) {
            /* the base reg is overwritten, invalidate it */
            reg_cover[i].status = ELIDE_REG_COVER_STATUS_NONE;
        }
    }
}

/* check if we can skip instrumenting the checks for refs */
static bool
pattern_opt_elide_overlap_ignore_refs(bb_info_t *bi, int num_refs, opnd_t *refs)
{
    elide_reg_cover_info_t *reg_cover;
    reg_id_t base;
    int disp;

    ASSERT(options.pattern_opt_elide_overlap, "should not be called");
    if (num_refs == 0)
        return true;
    if (num_refs > 1)
        return false;
    /* only care about [base + disp] refs */
    if (!opnd_is_near_base_disp(refs[0]) ||
        opnd_get_index(refs[0]) != DR_REG_NULL)
        return false;

    base = opnd_get_base(refs[0]);
    disp = opnd_get_disp(refs[0]);
    if (!IF_X64_ELSE(reg_is_64bit(base), reg_is_32bit(base))) {
        ASSERT(false, "wrong base register");
        return false;
    }
    reg_cover = &bi->reg_cover[base - REG_START];
    if (reg_cover->status == ELIDE_REG_COVER_STATUS_NONE) {
        /* no previous check */
        return false;
    } else if (reg_cover->status == ELIDE_REG_COVER_STATUS_LEFT &&
               reg_cover->left.disp == disp) {
        /* the same ref as the left. */
        /* XXX: we ignore the size difference. */
        return true;
    } else if (reg_cover->status == ELIDE_REG_COVER_STATUS_BOTH &&
               (reg_cover->left.disp  == disp ||
                reg_cover->right.disp == disp)) {
        /* the same ref as the right. */
        /* XXX: we ignore the size difference. */
        return true;
    } else if (reg_cover->status == ELIDE_REG_COVER_STATUS_BOTH &&
               (reg_cover->right.disp - reg_cover->left.disp) <=
               options.redzone_size &&
               disp > reg_cover->left.disp && disp < reg_cover->right.disp) {
        /* check if in between */
        return true;
    }
    return false;
}

/* optimize the checks by removing un-necessary checks,
 * The heuristic is that if there are two checks closer to each other
 * than redzone size, there are no checks needed in between.
 */
/* it returns the check info, and the caller stores the instr bounds so
 * it can be removed later
 */
static elide_ref_check_info_t *
pattern_opt_elide_overlap_update_checks(void *drcontext, bb_info_t *bi,
                                        instrlist_t *ilist, int num_refs,
                                        opnd_t *refs)
{
    elide_reg_cover_info_t *reg_cover;
    reg_id_t base;
    int disp;

    /* the case not handled */
    if (num_refs != 1 || !opnd_is_near_base_disp(refs[0]) ||
        opnd_get_index(refs[0]) != DR_REG_NULL)
        return NULL;

    base = opnd_get_base(refs[0]);
    disp = opnd_get_disp(refs[0]);
    if (!IF_X64_ELSE(reg_is_64bit(base), reg_is_32bit(base))) {
        ASSERT(false, "wrong base register");
        return NULL;
    }

    reg_cover = &bi->reg_cover[base - REG_START];
    if (reg_cover->status == ELIDE_REG_COVER_STATUS_NONE) {
        /* the first check, simply add at left */
        reg_cover->status = ELIDE_REG_COVER_STATUS_LEFT;
        reg_cover->left.disp = disp;
        return &reg_cover->left;
    } else if (reg_cover->status == ELIDE_REG_COVER_STATUS_LEFT) {
        /* the second check, add in sorted order */
        reg_cover->status = ELIDE_REG_COVER_STATUS_BOTH;
        ASSERT(disp != reg_cover->left.disp, "ref should be ignored");
        if (disp > reg_cover->left.disp) { /* add to right */
            reg_cover->right.disp = disp;
            return &reg_cover->right;
        } else { /* add to left */
            reg_cover->right = reg_cover->left;
            reg_cover->left.disp = disp;
            return &reg_cover->left;
        }
    }
    /* two already, replace one */
    ASSERT(reg_cover->status == ELIDE_REG_COVER_STATUS_BOTH,
           "wrong elide cover status");
    ASSERT((reg_cover->right.disp - reg_cover->left.disp) > 0,
           "wrong order of checks");
    if (disp < reg_cover->left.disp) {
        /* on the left */
        if ((reg_cover->right.disp - disp) <= options.redzone_size) {
            /* remove the left one's instrumentation */
            pattern_remove_check(drcontext, ilist,
                                 reg_cover->left.start, reg_cover->left.end);
        } else {
            /* move the left one to right */
            reg_cover->right = reg_cover->left;
        }
        reg_cover->left.disp = disp;
        return &reg_cover->left;
    } else if (disp > reg_cover->right.disp) {
        /* on the right */
        if ((disp - reg_cover->left.disp) <= options.redzone_size) {
            /* remove the right one's instrumentation*/
            pattern_remove_check(drcontext, ilist,
                                 reg_cover->right.start, reg_cover->right.end);
        } else {
            /* move the right one to left */
            reg_cover->left = reg_cover->right;
        }
        reg_cover->right.disp = disp;
        return &reg_cover->right;
    } else {
        /* in between */
        ASSERT(disp > reg_cover->left.disp && disp < reg_cover->right.disp,
               "wrong order of reg_covers");
        ASSERT((reg_cover->right.disp - reg_cover->left.disp) > options.redzone_size,
               "ref should be ignored");
        if ((disp - reg_cover->left.disp) >= (reg_cover->right.disp - disp)) {
            if ((disp - reg_cover->left.disp) <= options.redzone_size) {
                /* the large gap is smaller than the redzone size */
                reg_cover->right.disp = disp;
                return &reg_cover->right;
            } else {
                /* pick the small gap. */
                reg_cover->left.disp = disp;
                return &reg_cover->left;
            }
        } else {
            if ((reg_cover->right.disp - disp) <= options.redzone_size) {
                /* the large gap is smaller than the redzone size */
                reg_cover->left.disp = disp;
                return &reg_cover->left;
            } else {
                /* pick the small gap. */
                reg_cover->right.disp = disp;
                return &reg_cover->right;
            }
        }
    }
    ASSERT(false, "should not reach here");
    return NULL;
}

/* If not called during drmgr's insert phase, the caller must preserve aflags */
instr_t *
pattern_instrument_check(void *drcontext, instrlist_t *ilist, instr_t *app,
                         bb_info_t *bi, bool translating)
{
    int num_refs, i;
    opnd_t refs[MAX_REFS_PER_INSTR];
    instr_t *label;
    elide_ref_check_info_t *check = NULL;

    ASSERT(options.pattern != 0, "should not be called");
    if (options.pattern_opt_elide_overlap)
        pattern_opt_elide_overlap_update_regs(app, bi);

    if (IF_X86(instr_get_opcode(app) == OP_lea ||)
        instr_is_prefetch(app) ||
        instr_is_nop(app))
        return NULL;

    num_refs = pattern_extract_refs(app, refs _IF_DEBUG(MAX_REFS_PER_INSTR));
    if (num_refs == 0)
        return NULL;
    if (!translating)
        bi->pattern_4byte_check_only = pattern_4byte_check_only;
    else {
        ASSERT(bi->pattern_4byte_check_field_set,
               "pattern_4byte_check_only is not initialized");
    }
    if (options.pattern_opt_elide_overlap) {
        if (pattern_opt_elide_overlap_ignore_refs(bi, num_refs, refs))
            return NULL;
        check = pattern_opt_elide_overlap_update_checks
            (drcontext, bi, ilist, num_refs, refs);
    }
    bi->added_instru = true;
    /* pattern check code */
    label = INSTR_CREATE_label(drcontext);
    PRE(ilist, app, label);
    for (i = 0; i < num_refs; i++) {
        if (check != NULL) {
            check->start = INSTR_CREATE_label(drcontext);
            PRE(ilist, app, check->start);
        }
        pattern_insert_check_code(drcontext, ilist, app, refs[i], bi);
        if (check != NULL) {
            check->end = INSTR_CREATE_label(drcontext);
            PRE(ilist, app, check->end);
        }
    }
    return label;
}

#ifdef X86
/* An aggressive optimization to optimize the loop expanded from rep string
 * by introducing an inner loop to avoid the unncessary aflags save/restore.
 * XXX: adding a loop inside bb violates DR's bb constraints:
 * - a non-meta cbr must end the block
 *   we insert a fake non-meta jmp instead
 * - violates assumptions in many parts of DR: non-precise flushing,
 *   signal delivery, trace building, etc..
 *   + We add translation to all the related instructions to make sure the
 *   translation for signal delivery work.
 *   + For non-precise flush, we have to wait till the exit of the bb,
 *   which is similar to not expanding rep-string.
 *   + Such loop optimization should NOT be applied in a trace.
 *
 * The optimization relies on how drutil (a DynamoRIO extension) expands
 * a rep string into a loop, the loop should look exactly the same as below:
 *    rep movs
 * =>
 *    jecxz  zero
 *    jmp    iter
 *  zero:
 *    mov    $0x00000001 -> %ecx
 *    jmp    pre_loop
 *  iter:
 *    movs   %ds:(%esi) %esi %edi -> %es:(%edi) %esi %edi
 *  pre_loop:
 *    loop
 *
 * The instrumented code would be something like:
 *    jecxz  zero
 *    jmp    iter
 *  zero:
 *    jmp    post_loop
 *  iter:
 *    # save aflags if necessary
 *    # first iteration check
 *  check:
 *    cmp %ds:(%esi) $pattern
 *    ...
 *    cmp %es:(%edi) $pattern
 *    ...
 *    movs   %ds:(%esi) %esi %edi -> %es:(%edi) %esi %edi
 *  pre_loop:
 *    loop check
 *    # restore aflags if necessary
 *  post_loop:
 *    jmp    next_pc
 * The transformation is only performed at instru2instru phase to
 * avoid confusing other passes.
 */
void
pattern_instrument_repstr(void *drcontext, instrlist_t *ilist,
                          bb_info_t *bi, bool translating)
{
    instr_t *jecxz = NULL, *mov_1 = NULL, *jmp_skip = NULL;
    IF_DEBUG(instr_t *jmp_iter = NULL;)
    IF_DEBUG(drreg_status_t res;)
    instr_t *stringop = NULL, *loop = NULL, *post_loop, *instr, *jmp;
    instr_t *check = NULL;
    app_pc next_pc;

    ASSERT(bi->is_repstr_to_loop && options.pattern_opt_repstr,
           "should not be here");
    /* find all instr */
    instr = instrlist_first(ilist);
    for (; instr != NULL; instr = instr_get_next(instr)) {
        if (instr_is_app(instr) &&
            instr_get_opcode(instr) == OP_jecxz) {
            jecxz = instr;
            break;
        }
    }
    for (; instr != NULL; instr = instr_get_next(instr)) {
        if (instr_is_app(instr) &&
            instr_get_opcode(instr) == OP_jmp_short) {
            IF_DEBUG(jmp_iter = instr;)
            break;
        }
    }
    for (; instr != NULL; instr = instr_get_next(instr)) {
        if (instr_is_app(instr) &&
            instr_get_opcode(instr) == OP_mov_imm) {
            mov_1 = instr;
            break;
        }
    }
    for (; instr != NULL; instr = instr_get_next(instr)) {
        if (instr_is_app(instr) &&
            instr_get_opcode(instr) == OP_jmp) {
            jmp_skip = instr;
            break;
        }
    }
    for (; instr != NULL; instr = instr_get_next(instr)) {
        if (instr_is_app(instr) &&
            opc_is_stringop(instr_get_opcode(instr))) {
            stringop = instr;
            break;
        }
    }
    for (; instr != NULL; instr = instr_get_next(instr)) {
        if (instr_is_app(instr) &&
            opc_is_loopcc(instr_get_opcode(instr))) {
            loop = instr;
            break;
        }
    }
    ASSERT(jecxz != NULL && jmp_iter != NULL && mov_1 != NULL &&
           jmp_skip != NULL && stringop != NULL && loop != NULL,
           "wrong rep sring to loop code");
    ASSERT(loop == instrlist_last(ilist), "wrong last instr in loop");
    /* adjust jeczx target */
    instr_set_target(jecxz, opnd_create_instr(jmp_skip));
    /* remove mov_1 */
    instrlist_remove(ilist, mov_1);
    instr_destroy(drcontext, mov_1);
    /* adjust jmp_skip target */
    post_loop = INSTR_CREATE_label(drcontext);
    instr_set_target(jmp_skip, opnd_create_instr(post_loop));
    /* insert checks */
    /* the pattern checks will suspend their own aflags saves b/c it's not insert phase */
    IF_DEBUG(res =)
        drreg_reserve_aflags(drcontext, ilist, stringop);
    ASSERT(res == DRREG_SUCCESS, "should reserve aflags");
    /* As we're in instru2instru, we have to manually restore app-used regs. */
    if (instr_uses_reg(stringop, DR_REG_XAX)) {
        IF_DEBUG(res =)
            drreg_get_app_value(drcontext, ilist, stringop, DR_REG_XAX, DR_REG_XAX);
        ASSERT(res == DRREG_SUCCESS, "should restore xax");
    }
    check = pattern_instrument_check
        (drcontext, ilist, stringop, bi, translating);
    ASSERT(check != NULL, "check label must not be NULL");
    /* set loop target to check */
    instr_set_target(loop, opnd_create_instr(check));
    instr_set_meta(loop);
    /* post_loop */
    PRE(ilist, NULL, post_loop);
    next_pc = instr_get_app_pc(stringop) +
        instr_length(drcontext, stringop) + 1 /* rep prefix */;
    /* restore aflags before post_loop if necessary */
    IF_DEBUG(res =)
        drreg_unreserve_aflags(drcontext, ilist, post_loop);
    ASSERT(res == DRREG_SUCCESS, "should unreserve aflags");
    /* jmp next_pc */
    jmp = INSTR_XL8(INSTR_CREATE_jmp(drcontext, opnd_create_pc(next_pc)),
                    instr_get_app_pc(loop));
    PREXL8(ilist, NULL, jmp);
}
#endif /* X86 */

/* Assumes the caller has set the ISA mode to match the fault point */
static bool
pattern_ill_instr_is_instrumented(void *drcontext, byte *pc)
{
#ifdef X86
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
#elif defined(ARM)
    /* For Thumb:
     *  +30   m4 @0x4f7d2008  f8d3 c004  ldr    +0x04(%r3)[4byte] -> %r12
     *  +34   m4 @0x4f7d1f70  f24f 14fd  movw   $0x0000f1fd -> %r4
     *  +38   m4 @0x4f7d1f24  f2cf 14fd  movt   $0x0000f1fd -> %r4
     *  +42   m4 @0x4f7d1ee4  ebbc 0f04  cmp    %r12 %r4  $0x00
     *  +46   m4 @0x537a1ea4  d100       b.ne   @0x537a20a0[4byte]
     *  +48   m4 @0x537a1bb0  de00       udf    $0x00000000
     *  +50   m4 @0x537a20a0             <label>
     * When the app memref is predicated, we add a b.!pred at the top, so the
     * rest does not change.
     * For ARM:
     *  +20   m4 @0x4f3fe0f4  e5901000   ldr    (%r0)[4byte] -> %r1
     *  +24   m4 @0x4f3fe180  e30f21fd   movw   $0x0000f1fd -> %r2
     *  +28   m4 @0x4f3fdee8  e34f21fd   movt   $0x0000f1fd -> %r2
     *  +32   m4 @0x4f3fdf28  e1510002   cmp    %r1 %r2  $0x00
     *  +36   m4 @0x4f3fdf68  1a000000   b.ne   @0x4f3fdc34[4byte]
     *  +40   m4 @0x4f3fdb50  e7f000f0   udf    $0x00000000
     *  +44   m4 @0x4f3fdc34             <label>
     * For 2-byte or 1-byte memrefs, there is no movt.
     */
    if (dr_get_isa_mode(drcontext) == DR_ISA_ARM_THUMB) {
        byte buf[12]; /* 12 bytes from movt (or movw for <4byte) through udf */
#       define BNE_THUMB_OPCODE 0xd100
        int immed;
        if (!safe_read(pc + UDF_THUMB_LENGTH - sizeof(buf), sizeof(buf), buf))
            return false;
        immed = ((buf[0] & 0xf) << 12) | ((buf[1] & 0x4) << 9) |
            ((buf[3] & 0x70) << 4) | buf[2];
        DOLOG(3, {
            int i;
            LOG(3, "%s: read ", __FUNCTION__);
            for (i = 0; i < sizeof(buf); i++)
                LOG(3, " %02x", buf[i]);
            LOG(3, "\n\timmed=0x%x, bne=0x%x, udf=0x%x\n", immed,
                *(ushort *)&buf[8], *(ushort *)&buf[10]);
        });
        if ((immed != (options.pattern & 0xffff) &&
             immed != (pattern_reverse & 0xffff)) ||
            *(ushort *)&buf[8] != (ushort)BNE_THUMB_OPCODE ||
            *(ushort *)&buf[10] != (ushort)UDF_THUMB_OPCODE)
            return false;
    } else {
        byte buf[16]; /* 16 bytes from movt (or movw for <4byte) through udf */
#       define BNE_ARM_OPCODE 0x1a000000
        int immed;
        if (!safe_read(pc + UDF_ARM_LENGTH - sizeof(buf), sizeof(buf), buf))
            return false;
        immed = ((buf[2] & 0xf) << 12) | ((buf[1] & 0xf) << 8) | buf[0];
        if ((immed != (options.pattern & 0xffff) &&
             immed != (pattern_reverse & 0xffff)) ||
            *(ushort *)&buf[8] != (ushort)BNE_ARM_OPCODE ||
            *(ushort *)&buf[12] != (ushort)UDF_ARM_OPCODE)
            return false;
    }
#endif
    return true;
}

/* switch to 4-byte-check only mode */
static void
pattern_switch_instrumentation_style(void)
{
    if (num_2byte_faults >= options.pattern_max_2byte_faults &&
        dr_mutex_trylock(flush_lock) /* to avoid flush storm */) {
        if (num_2byte_faults >= options.pattern_max_2byte_faults) {
            pattern_4byte_check_only = true;
            num_2byte_faults = 0;
            dr_delay_flush_region(0, (size_t)-1, 0, NULL);
        }
        dr_mutex_unlock(flush_lock);
    }
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
    uint   pos, skip;
    ASSERT(options.pattern != 0, "incorrectly called");
    STATS_INC(num_slowpath_faults);
#ifdef ARM
    dr_isa_mode_t old_mode;
    dr_isa_mode_t fault_mode = get_isa_mode_from_fault_mc(raw_mc);
    dr_set_isa_mode(drcontext, fault_mode, &old_mode);
#endif

    /* check if ill-instr is our code */
    if (!pattern_ill_instr_is_instrumented(drcontext, raw_mc->pc)) {
        IF_ARM(dr_set_isa_mode(drcontext, old_mode, NULL));
        return false;
    }
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
        size_t size;
        opnd_t opnd = is_write ?
            instr_get_dst(&instr, pos) : instr_get_src(&instr, pos);
        if (!opnd_uses_nonignorable_memory(opnd))
            continue;
        size = opnd_size_in_bytes(opnd_get_size(opnd));
        if (size <= 2) {
            /* it is ok to have racy update here */
            num_2byte_faults++;
        }
        pc_to_loc(&loc, mc->pc);
        pattern_handle_mem_ref(&loc, addr, size, mc, is_write);
    }
    instr_free(drcontext, &instr);
    /* we are not skipping all cmps for this instr, which is ok because we
     * clobberred the pattern if a 2nd memref was unaddr.
     */
    skip = IF_ARM_ELSE(fault_mode == DR_ISA_ARM_THUMB ?
                       UDF_THUMB_LENGTH : UDF_ARM_LENGTH, UD2A_LENGTH);
    LOG(2, "pattern check ud2a triggered@"PFX" => skip to "PFX"\n",
        raw_mc->pc, raw_mc->pc + skip);
    raw_mc->pc += skip;

    if (options.pattern_max_2byte_faults > 0 &&
        num_2byte_faults >= options.pattern_max_2byte_faults) {
        /* 2-byte checks caused too many faults, switch instrumentation style */
        pattern_switch_instrumentation_style();
    }
    IF_ARM(dr_set_isa_mode(drcontext, old_mode, NULL));
    return true;
}

/* Assumes the caller has set the ISA mode to match the fault point */
static bool
pattern_segv_instr_is_instrumented(byte *pc, byte *next_next_pc,
                                   instr_t *inst, instr_t *next)
{
#ifdef X86
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
#elif defined(ARM)
    /* check code sequence: ldr; movw+movt; cmp; b.ne; udf */
    if ((instr_get_opcode(inst) == OP_ldr ||
         instr_get_opcode(inst) == OP_ldrb ||
         instr_get_opcode(inst) == OP_ldrh) &&
        instr_get_opcode(next) == OP_movw &&
        opnd_is_immed_int(instr_get_src(next, 0))) {
        uint imm = opnd_get_immed_int(instr_get_src(next, 0));
        if (imm == (ushort)options.pattern ||
            imm == (ushort)pattern_reverse)
            return true;
    }
#endif
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
 *
 * i#1070: this function is also used for guard page violation handling,
 * in which case, we should restore the guard page if the violation is caused
 * by us.
 */
bool
pattern_handle_segv_fault(void *drcontext, dr_mcontext_t *raw_mc,
                          dr_mcontext_t *mc
                          _IF_WINDOWS(app_pc target)
                          _IF_WINDOWS(bool guard))
{
    bool ours = false;
    instr_t inst, next;
    byte *next_pc;
#ifdef ARM
    dr_isa_mode_t old_mode;
    dr_isa_mode_t fault_mode = get_isa_mode_from_fault_mc(raw_mc);
    dr_set_isa_mode(drcontext, fault_mode, &old_mode);
#endif

    /* check if wrong pc */
    instr_init(drcontext, &inst);
    instr_init(drcontext, &next);
    if (!safe_decode(drcontext, raw_mc->pc, &inst, &next_pc))
        goto handle_light_mode_segv_fault_done;
    if (!safe_decode(drcontext, next_pc, &next, &next_pc))
        goto handle_light_mode_segv_fault_done;
    /* check if our own code */
    if (!pattern_segv_instr_is_instrumented(raw_mc->pc, next_pc, &inst, &next)) {
        app_pc addr;
        bool is_write;
        uint pos;
        int  memopidx;
        app_loc_t loc;
        size_t size;
        opnd_t opnd;
        dr_mem_info_t info;
        for (memopidx = 0;
             instr_compute_address_ex_pos(&inst, mc, memopidx,
                                          &addr, &is_write, &pos);
             memopidx++) {
            if (dr_query_memory_ex(addr, &info)) {
                if (info.type == DR_MEMTYPE_FREE) {
                    opnd = is_write ?
                        instr_get_dst(&inst, pos) : instr_get_src(&inst, pos);
                    size = opnd_size_in_bytes(opnd_get_size(opnd));
                    pc_to_loc(&loc, mc->pc);
                    report_unaddressable_access(&loc, addr, size,
                                                is_write ? DR_MEMPROT_WRITE :
                                                DR_MEMPROT_READ,
                                                addr, addr + size, mc);
                } else if (is_write && options.report_write_to_read_only &&
                           !TEST(DR_MEMPROT_WRITE, info.prot)) {
                    if (IF_WINDOWS(guard ||) TEST(info.prot, DR_MEMPROT_PRETEND_WRITE))
                        continue;
                    opnd = instr_get_dst(&inst, pos);
                    size = opnd_size_in_bytes(opnd_get_size(opnd));
                    pc_to_loc(&loc, mc->pc);
                    report_unaddr_warning(&loc, mc, "writing to readonly memory",
                                          addr, size, true);
                }
                /* FIXME i#1015: report unaddr error for write on read-only */
            }
        }
        goto handle_light_mode_segv_fault_done;
    }
#ifdef WINDOWS
    if (guard) {
        /* violation caused by us, restore the guard page.
         * XXX: there could be a race here. Because the guard page is a
         * one-shot alarm, there might be another thread touches that page
         * without exception before we restore it, and behave incorrectly.
         */
        uint prot;
# ifdef DEBUG /* some sanity checks */
        bool ok;
        opnd_t mem  = instr_get_src(&inst, 0);
        size_t size = opnd_size_in_bytes(opnd_get_size(mem));
        ASSERT(opnd_uses_nonignorable_memory(mem), "wrong cmp opnd");
        ASSERT(opnd_compute_address(mem, raw_mc) <= target &&
               opnd_compute_address(mem, raw_mc) + size > target,
               "wrong exception address");
# endif
        /* get prot of that page */
        IF_DEBUG(ok = )
            dr_query_memory((byte *)target, NULL, NULL, &prot);
        ASSERT(ok, "failed to get prot on guarded page");
        /* restore GUARD_PAGE */
        IF_DEBUG(ok = )
            dr_memory_protect((byte *)target, 1, prot | DR_MEMPROT_GUARD);
        ASSERT(ok, "failed to restore guard page");
    }
#endif
    /* skip pattern check code */
#ifdef X86
    LOG(2, "pattern check cmp fault@"PFX" => skip to "PFX"\n",
        raw_mc->pc, next_pc + UD2A_LENGTH);
    raw_mc->pc = next_pc + UD2A_LENGTH;
#elif defined(ARM)
    instr_reset(drcontext, &next);
    if (!safe_decode(drcontext, next_pc, &next, &next_pc))
        goto handle_light_mode_segv_fault_done;
    if (instr_get_opcode(&next) == OP_movt) {
        instr_reset(drcontext, &next);
        if (!safe_decode(drcontext, next_pc, &next, &next_pc))
            goto handle_light_mode_segv_fault_done;
    }
    ASSERT(instr_get_opcode(&next) == OP_cmp, "invalid pattern instru");
    instr_reset(drcontext, &next);
    if (!safe_decode(drcontext, next_pc, &next, &next_pc))
        goto handle_light_mode_segv_fault_done;
    ASSERT(instr_is_cbr(&next), "invalid pattern instru");
    instr_reset(drcontext, &next);
    if (!safe_decode(drcontext, next_pc, &next, &next_pc))
        goto handle_light_mode_segv_fault_done;
    ASSERT(instr_get_opcode(&next) == OP_udf, "invalid pattern instru");
    LOG(2, "pattern check fault@"PFX" => skip to "PFX"\n", raw_mc->pc, next_pc);
    raw_mc->pc = next_pc;
#endif
    ours = true;
  handle_light_mode_segv_fault_done:
    IF_ARM(dr_set_isa_mode(drcontext, old_mode, NULL));
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
pattern_insert_malloc_tree(malloc_info_t *info)
{
    IF_DEBUG(rb_node_t *node;)
    /* only used to find redzone overlap of live allocs */
    if (!info->has_redzone)
        return;
    dr_rwlock_write_lock(pattern_malloc_tree_rwlock);
    /* due to padding, the real_size might be larger than
     * (app_size + redzone_size*2), which makes the size of
     * rear redzone not fixed, so store app_size in rb_tree.
     */
    IF_DEBUG(node =)
        rb_insert(pattern_malloc_tree, info->base - options.redzone_size,
                  info->pad_size + options.redzone_size*2, (void *)info->request_size);
    dr_rwlock_write_unlock(pattern_malloc_tree_rwlock);
    ASSERT(node == NULL, "error in inserting pattern malloc tree");
}

static void
pattern_remove_malloc_tree(malloc_info_t *info)
{
    rb_node_t *node;
    void *data;
    app_pc real_base;
    size_t size;

    /* only used to find redzone overlap of live allocs */
    if (!info->has_redzone)
        return;
    dr_rwlock_write_lock(pattern_malloc_tree_rwlock);
    node = rb_find(pattern_malloc_tree, info->base - options.redzone_size);
    if (node != NULL) {
        rb_node_fields(node, &real_base, &size, &data);
        ASSERT(info->request_size  == (size_t)data,
               "wrong app size in pattern malloc tree");
        ASSERT(real_base == info->base - options.redzone_size,
               "wrong real_base in pattern malloc tree");
        ASSERT(size == info->pad_size + options.redzone_size * 2,
               "Wrong real_size in pattern malloc tree");
        /* XXX i#786: we simply remove the memory here, which can be
         * improved by invalidating/removing malloc rbtree instead,
         * though we still need do the lookup to change the node status.
         */
        rb_delete(pattern_malloc_tree, node);
    }
    dr_rwlock_write_unlock(pattern_malloc_tree_rwlock);
}



/* If an addr contains pattern value, we check the memory before and after,
 * and return true if there are enough number of contiguous pattern value.
 * XXX: the pattern value in the redzone could be clobbered by earlier error,
 * (see pattern_handle_ill_fault,) which may cause false negative here,
 * e.g. test case registers.
 * Now we return true if see more than half are pattern values.
 */
#define ADDR_PRE_CHECK_SIZE   (options.redzone_size)
#define ADDR_PRE_CHECK_COUNT  (ADDR_PRE_CHECK_SIZE / sizeof(uint))
#define ADDR_PRE_CHECK_THRESHOLD (ADDR_PRE_CHECK_COUNT/2)

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
    if (match > ADDR_PRE_CHECK_THRESHOLD)
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
    if (match > ADDR_PRE_CHECK_THRESHOLD)
        return true;
    return false;
}

/* Checks whether [addr, addr+size) overlaps a redzone or padding */
static bool
pattern_addr_in_redzone(byte *addr, size_t size)
{
    bool res = false;
    LOG(3, "%s: "PFX"-"PFX"\n", __FUNCTION__, addr, addr+size);
    if (options.pattern_use_malloc_tree)
        res = pattern_addr_in_malloc_tree(addr, size);
    else
        res = region_in_redzone(addr, size, NULL, NULL, NULL, NULL, NULL);
    return res;
}

/* Assumes that it's ok to write the pattern value beyond end!
 * I.e., if a small region is passed in, assumes there's already a
 * redzone beyond it.
 */
static void
pattern_write_pattern(byte *start, byte *end _IF_DEBUG(const char *description))
{
    /* gcc -O3 loads from options.pattern every iter of the loop so we
     * explicitly put into a local.
     */
    register uint *addr = (uint *) start;
    register uint pattern_val = options.pattern;
    LOG(2, "set pattern value at "PFX"-"PFX" in %s\n",
        start, end, description);
    if (!ALIGNED(addr, 2)) {
        *addr = pattern_reverse;
    } else if (!ALIGNED(addr, 4)) {
        /* the addr must be 2-byte aligned, fill the 2-byte
         * if it is not 4-byte aligned
         */
        *(ushort *)addr = (ushort)options.pattern;
    }
    for (addr = (uint *)ALIGN_FORWARD(start, 4);
         addr < (uint *)end; /* we assume ok to write past end! */
         addr++)
        *addr = pattern_val;
}

void
pattern_handle_malloc(malloc_info_t *info)
{
    ASSERT(options.pattern != 0, "should not be called");
    ASSERT(ALIGNED(info->base, sizeof(uint)), "base is unaligned");
    ASSERT(ALIGNED(info->pad_size, sizeof(uint)), "pad size is unaligned");

    if (info->has_redzone) {
        if (options.pattern_use_malloc_tree)
            pattern_insert_malloc_tree(info);
        pattern_write_pattern(info->base - options.redzone_size, info->base
                              _IF_DEBUG("malloc pre-redzone"));
        /* the app_size might be unaligned, which will be expanded with padding
         * by allocator. We will fill the padding whenever possible.
         */
        pattern_write_pattern(info->base + info->request_size,
                              info->base + info->pad_size + options.redzone_size
                              _IF_DEBUG("malloc padding + post-redzone"));
    } else {
#if 0 /* FIXME: i#832, no redzone for debug CRT, so cannot use ASSERT here */
        ASSERT(malloc_is_pre_us(app_base), "unknown malloc region");
#endif
    }
}

void
pattern_handle_real_free(malloc_info_t *info, bool delayed)
{
    size_t rz_sz = options.redzone_size;
    ASSERT(options.pattern != 0, "should not be called");
    if (delayed) {
        /* removing the pattern to avoid false positive faults. */
        byte *rz_start = info->base - (info->has_redzone ? rz_sz : 0);
        size_t tot_sz = info->pad_size + (info->has_redzone ? rz_sz*2 : 0);
        LOG(2, "clear pattern value "PFX"-"PFX" %d bytes in freed block\n",
            rz_start, rz_start + tot_sz, tot_sz);
        memset(rz_start, 0, tot_sz);
    } else {
        if (options.pattern_use_malloc_tree) {
            /* if !delayed, the base is app base, and the size is app size.
             * we can ignore the size since our rbtree holds the app_size,
             * now use passed in size for sanity check.
             */
            pattern_remove_malloc_tree(info);
        }
        /* if !delayed, only need remove the pattern in redzone */
        if (info->has_redzone) {
            IF_DEBUG(uint val;)
            ASSERT(safe_read(info->base - rz_sz, sizeof(val), &val) &&
                   val == options.pattern, "wrong free address");
            LOG(2, "clear pattern value "PFX"-"PFX" %d bytes in pre-redzone\n",
                info->base - rz_sz, info->base, rz_sz);
            memset(info->base - rz_sz, 0, rz_sz);
            LOG(2, "clear pattern value "PFX"-"PFX" %d bytes in post-redzone\n",
                info->base + info->pad_size, info->base + info->pad_size + rz_sz, rz_sz);
            memset(info->base + info->pad_size, 0, rz_sz);
        } else {
#if 0 /* FIXME: i#832, no redzone for debug CRT, so cannot use ASSERT here */
            ASSERT(info->pre_us, "unknown malloc region");
#endif
        }
    }
}

void
pattern_handle_delayed_free(malloc_info_t *info)
{
    ASSERT(options.pattern != 0, "should not be called");
    /* We assume that any invalid free won't come here */
    if (options.pattern_use_malloc_tree)
        pattern_remove_malloc_tree(info);
    /* We assume the actually alloced block length will be 4-byte aligned,
     * e.g. if size is 2, the allocator will alloc 4 bytes instead,
     * so it is ok to fill 4-byte uint pattern.
     */
    ASSERT(ALIGNED(info->base, 4), "unaligned pointer for free");
    pattern_write_pattern(info->base, info->base + info->request_size
                          _IF_DEBUG("delay-freed block"));
}

void
pattern_handle_realloc(malloc_info_t *old_info, malloc_info_t *new_info,
                       bool for_reuse)
{
    LOG(2, "%s: "PFX"-"PFX", "PFX"-"PFX"\n", __FUNCTION__,
        old_info->base, old_info->base + old_info->request_size,
        new_info->base, new_info->base + new_info->request_size);
    if (new_info->base != old_info->base) {
        /* treat as free+malloc */
        if (options.replace_malloc) {
            if (!for_reuse)
                pattern_handle_delayed_free(old_info);
        } else {
            /* XXX: with wrapping, we can have a race here with -no_replace_realloc.
             * That option combo is just unsafe: pattern + wrap + -no_replace_realloc!
             */
            pattern_handle_real_free(old_info, false);
        }
        pattern_handle_malloc(new_info);
    } else {
        if (new_info->request_size > old_info->request_size) {
            /* clear pattern from padding + trailing redzone */
            size_t rm_sz = old_info->pad_size - old_info->request_size +
                (old_info->has_redzone ? options.redzone_size : 0);
            size_t add_sz = new_info->pad_size - new_info->request_size +
                (new_info->has_redzone ? options.redzone_size : 0);
            LOG(2, "clear pattern value "PFX"-"PFX" %d bytes on in-place realloc\n",
                old_info->base + old_info->request_size,
                old_info->base + old_info->request_size + rm_sz, rm_sz);
            memset(old_info->base + old_info->request_size, 0, rm_sz);
            pattern_write_pattern(new_info->base + new_info->request_size,
                                  new_info->base + new_info->request_size + add_sz
                                  _IF_DEBUG("realloc in-place new pad + post-redzone"));
        } else if (new_info->request_size < old_info->request_size) {
            pattern_write_pattern(new_info->base + new_info->request_size,
                                  new_info->base + old_info->request_size
                                  _IF_DEBUG("realloc shrunk in-place new pad"));
        }
    }
}

void
pattern_new_redzone(app_pc start, size_t size)
{
    ASSERT(options.pattern != 0, "should not be called");
    /* We assume the redzone will be 4-byte aligned */
    ASSERT(ALIGNED(start, 4), "unaligned redzone start");
    ASSERT(ALIGNED(size, 4), "unaligned redzone size");
    pattern_write_pattern(start, start + size _IF_DEBUG("new redzone"));
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
        /* we first do a pre-check to avoid expensive lookup
         * XXX: we might miss the use-after-free error that accessing
         * a freed pre-us block with smaller-than-redzone size.
         */
        pattern_addr_pre_check(addr) &&
        /* We don't have alloc_ops.global_lock set, but by iterating for
         * live chunks before freed, we shouldn't miss anything: even
         * chunk re-use should still show up, and we will synchronize
         * with a split or coalesce.
         */
        (pattern_addr_in_redzone(addr, size) ||
         overlaps_delayed_free(addr, addr + size, NULL, NULL, NULL, false/*any*/))) {
        /* XXX: i#786: the actually freed memory is neither in malloc tree
         * nor in delayed free rbtree, in which case we cannot detect. We
         * can maintain the information in pattern malloc tree, i.e. mark
         * the tree node as invalid on free and remove/change the tree
         * node on re-use of the memory.
         */
        if (!check_unaddressable_exceptions(is_write, loc, addr, size,
                                            false, mc)) {
            report_unaddressable_access(loc, addr, size,
                                        is_write ? DR_MEMPROT_WRITE : DR_MEMPROT_READ,
                                        addr, addr + size, mc);
        }
        /* clobber the pattern to avoid duplicate reports for this same addr
         * or possible ud2a if the 2nd memref is also unaddressable.
         * XXX i#1476: full mode no longer avoids dup reports for unaddr:
         * so we could perhaps remove this, though I don't know what the
         * 2nd half of the above sentence means.  Plus, pattern can't detect
         * any more errors after a write, as the app clobbers the pattern value.
         */
        /* should this be a safe_write?
         * we reach here which means safe_read works and
         * it is in redzone or delayed free, so not worth the overhead.
         */
        /* i#902: it is only safe to set one byte here since the memory
         * [addr, addr + size] might be partial buffer underflow.
         */
        *(byte *)addr = 0;
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

    /* reverse the byte order for unaligned checks:
     * for example, if the pattern is 0x43214321, the reversed pattern is
     * 0x21432143. If we check both value on any memory access, we are able
     * to check both aligned and unaligned access.
     */
    pattern_reverse = PATTERN_REVERSE(options.pattern);
    /* do we use 4-byte checks only */
    if (options.pattern_max_2byte_faults == 0)
        pattern_4byte_check_only = true;
    flush_lock = dr_mutex_create();
}

void
pattern_exit(void)
{
    ASSERT(options.pattern != 0, "should not be called");
    if (options.pattern_use_malloc_tree) {
        dr_rwlock_destroy(pattern_malloc_tree_rwlock);
        rb_tree_destroy(pattern_malloc_tree);
    }
    dr_mutex_destroy(flush_lock);
}
