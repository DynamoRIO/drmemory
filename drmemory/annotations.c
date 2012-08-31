/* **********************************************************
 * Copyright (c) 2011-2012 Google, Inc.  All rights reserved.
 * **********************************************************/

/* Dr. Memory: the memory debugger
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License, and no later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/***************************************************************************
 * annotations.c: Support for application annotations.
 *
 * FIXME: This is a quick implementation of Valgrind client requests.  There are
 * many more things we should do:
 * - i#283: Make cross-tool compatible annotations.
 * - i#572: Design our own low-impact annotations.
 * - i#573: Provide additional annotations, ie support for JITs flushing the
 *   code cache.
 * - i#61: Implement AmIRunningUnderDrMemory() or RunningUnderValgrind().
 * - i#311: Annotate which part of the subprogram is running, for mapping
 *   allocation sites to test cases.
 */

#include "dr_api.h"
#include "drmgr.h"
#include "drmemory.h"
#include "annotations.h"
#include "utils.h"
#include "shadow.h"
#include "options.h"

/* For VG_USERREQ__* enums. */
#include "valgrind.h"
#include "memcheck.h"

static ptr_uint_t note_annotate_here;

enum {
    VG_PATTERN_LENGTH = 5,
    VG_NUM_ARGS = 5,
};

typedef struct {
    ptr_uint_t request;
    ptr_uint_t args[VG_NUM_ARGS];
    ptr_uint_t default_result;
} vg_client_request_t;

static ptr_uint_t
handle_make_mem_defined_if_addressable(vg_client_request_t *request)
{
#ifdef TOOL_DR_MEMORY
    app_pc start = (app_pc)request->args[0];
    ptr_uint_t len = request->args[1];

    /* No-op if we're not tracking definedness. */
    if (!options.shadowing || !options.check_uninitialized)
        return 1;

    shadow_set_non_matching_range(start, len, SHADOW_DEFINED,
                                  SHADOW_UNADDRESSABLE);
#endif

    /* XXX: Not sure what the proper return code is for this request, and most
     * apps don't care.
     */
    return 1;
}

/* Handles a valgrind client request, if we understand it.
 */
static void
handle_vg_annotation(app_pc request_args)
{
    vg_client_request_t request;
    void *dc;
    dr_mcontext_t mcontext;
    ptr_uint_t result;

    if (!safe_read(request_args, sizeof(request), &request))
        return;

    /* FIXME: Add support for more requests, such as discard_translations and
     * running_on_valgrind.
     */
    switch (request.request) {
    case VG_USERREQ__MAKE_MEM_DEFINED_IF_ADDRESSABLE:
        result = handle_make_mem_defined_if_addressable(&request);
        break;
    default:
        WARN("Unknown Valgrind client request: %x\n", request.request);
        result = request.default_result;
    }

    /* The result code goes in xbx. */
    mcontext.size = sizeof(mcontext);
    mcontext.flags = DR_MC_INTEGER;
    dc = dr_get_current_drcontext();
    dr_get_mcontext(dc, &mcontext);
    mcontext.xbx = result;
    dr_set_mcontext(dc, &mcontext);
}

/* Special pattern opcodes.
 * See __SPECIAL_INSTRUCTION_PREAMBLE in valgrind.h.
 */
static const int expected_opcodes[VG_PATTERN_LENGTH] = {
    OP_rol,
    OP_rol,
    OP_rol,
    OP_rol,
    OP_xchg
};

/* Immediate operands to the special rol instructions. */
static const int
expected_rol_immeds[VG_PATTERN_LENGTH] = {
    3,
    13,
    29,
    19,
    0
};

/*   Return true if
 * the replacement occurred, and set next_instr to the first instruction after
 * the annotation sequence.
 *
 * Example Valgrind annotation sequence from annotations test:
 * <C code to fill _zzq_args>
 *             lea    0xffffffe4(%ebp) -> %eax      ; lea _zzq_args -> %eax
 *             mov    0x08(%ebp) -> %edx            ; mov _zzq_default -> %edx
 * instrs[0] = rol    $0x00000003 %edi -> %edi      ; Special sequence to replace
 * instrs[1] = rol    $0x0000000d %edi -> %edi
 * instrs[2] = rol    $0x0000001d %edi -> %edi
 * instrs[3] = rol    $0x00000013 %edi -> %edi
 * instrs[4] = xchg   %ebx %ebx -> %ebx %ebx
 *
 * FIXME: If the pattern gets split up by -max_bb_instrs, we will not be able to
 * match it.  If the application is built without optimizations, the client
 * request will not be inlined, so it is unlikely that it will be in a bb bigger
 * than 256 instrs.
 */
static bool
match_valgrind_pattern(void *dc, instrlist_t *bb, instr_t *instr,
                       instr_t **next_instr)
{
    instr_t *instrs[VG_PATTERN_LENGTH];
    uint i;
    bool found_xax, found_xdx;
    instr_t *label;

    instrs[0] = instr;
    for (i = 0; i < BUFFER_SIZE_ELEMENTS(instrs); i++) {
        if (i > 0) {
            instrs[i] = instr_get_next(instrs[i - 1]);
        }
        if (instrs[i] == NULL) {
            return false;
        }
        /* Perf: Check each instruction before iterating further. */
        if (instr_get_opcode(instrs[i]) != expected_opcodes[i]) {
            return false;
        }

        if (0 <= i && i < 4) {
            /* Check the rol instr operands. */
            opnd_t src = instr_get_src(instrs[i], 0);
            opnd_t dst = instr_get_dst(instrs[i], 0);
            if (!opnd_is_immed(src) ||
                opnd_get_immed_int(src) != expected_rol_immeds[i]) {
                return false;
            }
            if (!opnd_same(dst, opnd_create_reg(DR_REG_EDI))) {
                return false;
            }
        } else if (i == 4) {
            /* Check xchg operangs. */
            opnd_t src = instr_get_src(instrs[i], 0);
            opnd_t dst = instr_get_dst(instrs[i], 0);
            opnd_t xbx = opnd_create_reg(DR_REG_XBX);
            if (!opnd_same(src, xbx) || !opnd_same(dst, xbx))
                return false;
        }
    }

    /* We have matched the pattern. */
    DOLOG(2, {
        LOG(2, "Matched valgrind client request pattern at "PFX":\n",
            instr_get_app_pc(instrs[0]));
        for (i = 0; i < BUFFER_SIZE_ELEMENTS(instrs); i++) {
            instr_disassemble(dc, instrs[i], LOGFILE_LOOKUP());
            LOG(2, "\n");
        }
        LOG(2, "\n");
    });

    /* Scan backwards to mark "lea _zzq_args -> %xax" and "mov _zzq_default ->
     * %xdx" as meta.  On gcc, valgrind.h uses asm constraints to materialize
     * %xax and %xdx, so we just mark the first two instructions that store to
     * %xax and %xdx as meta.
     */
    found_xax = false;
    found_xdx = false;
    for (instr = instrs[0]; instr != NULL; instr = instr_get_prev(instr)) {
        opnd_t dst;
        if (instr_num_dsts(instr) != 1)
            continue;
        dst = instr_get_dst(instr, 0);
        if (!found_xax && opnd_same(dst, opnd_create_reg(DR_REG_XAX))) {
            instr_set_ok_to_mangle(instr, false);
            found_xax = true;
        }
        if (!found_xdx && opnd_same(dst, opnd_create_reg(DR_REG_XDX))) {
            instr_set_ok_to_mangle(instr, false);
            found_xdx = true;
        }
        if (found_xax && found_xdx)
            break;
    }

    /* Delete rol and xchg instructions. */
    *next_instr = instr_get_next(instrs[VG_PATTERN_LENGTH - 1]);
    for (i = 0; i < BUFFER_SIZE_ELEMENTS(instrs); i++) {
        instrlist_remove(bb, instrs[i]);
        instr_destroy(dc, instrs[i]);
    }

    /* Leave label so insert phase knows where to insert clean call */
    label = INSTR_CREATE_label(dc);
    instr_set_note(label, (void *)note_annotate_here);
    instrlist_meta_preinsert(bb, *next_instr, label);

    return true;
}

/* Replace Valgrind annotations with an appropriate clean call.
 *
 * FIXME: If we switch to drmgr, we need to match the application pattern up
 * front, remove the instrs, and add the clean call in a later pass.
 *
 * XXX: match_valgrind_pattern was designed to be used inside of another bb pass
 * to minimize linked list iteration, but it has to run before
 * fastpath_top_of_bb picks scratch registers.  If we ever get a chance, we
 * should try to combine this pass over the bb with another.
 */
static dr_emit_flags_t
annotate_event_bb_app2app(void *drcontext, void *tag, instrlist_t *bb,
                          bool for_trace, bool translating)
{
    instr_t *instr;
    instr_t *next_instr;
    for (instr = instrlist_first(bb); instr != NULL; instr = next_instr) {
        next_instr = instr_get_next(instr);
        (void)match_valgrind_pattern(drcontext, bb, instr, &next_instr);
    }
    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
annotate_event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb,
                           bool for_trace, bool translating, void **user_data)
{
    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
annotate_event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                         bool for_trace, bool translating, void *user_data)
{
    /* app2app left a label where clean call should go */
    if (instr_is_label(inst) && instr_get_note(inst) == (void *)note_annotate_here) {
        /* Insert clean call and pass &_zzq_args. */
        dr_insert_clean_call(drcontext, bb, inst, (void*)handle_vg_annotation,
                             /*fpstate=*/false, 1, opnd_create_reg(DR_REG_EAX));
    }
    return DR_EMIT_DEFAULT;
}

void
annotate_init(void)
{
    drmgr_priority_t pri_app2app = {sizeof(pri_app2app), "drmemory.annotate", NULL, NULL,
                                    DRMGR_PRIORITY_APP2APP_ANNOTATE};
    drmgr_priority_t pri_insert = {sizeof(pri_insert), "drmemory.annotate", NULL, NULL,
                                   DRMGR_PRIORITY_INSERT_ANNOTATE};
    if (!drmgr_register_bb_app2app_event(annotate_event_bb_app2app, &pri_app2app))
        ASSERT(false, "drmgr registration failed");
    if (!drmgr_register_bb_instrumentation_event(annotate_event_bb_analysis,
                                                 annotate_event_bb_insert,
                                                 &pri_insert))
        ASSERT(false, "drmgr registration failed");
    note_annotate_here = drmgr_reserve_note_range(1);
    ASSERT(note_annotate_here != DRMGR_NOTE_NONE, "failed to reserve note value");
}

void
annotate_exit(void)
{
}
