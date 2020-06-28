/* **************************************************************
 * Copyright (c) 2017 Google, Inc.  All rights reserved.
 * **************************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of Google, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* tests umbra's umbra_insert_app_to_shadow() method */

#include <string.h>
#include <signal.h>

#include "dr_api.h"
#include "drmgr.h"
#include "umbra.h"
#include "drreg.h"
#include "drutil.h"

#include "umbra_test_shared.h"

#ifndef X64
/* Denotes whether redundant blocks were ever cleared. */
static bool was_redundant_cleared = false;
#endif

static umbra_map_t *umbra_map;

static dr_emit_flags_t
event_app_analysis(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
                   bool translating, OUT void **user_data);

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where,
                      bool for_trace, bool translating, void *user_data);

#ifdef WINDOWS
static bool
event_exception_instrumentation(void *drcontext, dr_exception_t *excpt);
#else
static dr_signal_action_t
event_signal_instrumentation(void *drcontext, dr_siginfo_t *info);
#endif

static void
exit_event(void);

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    drreg_options_t ops = { sizeof(ops), 4, true };
    umbra_map_options_t umbra_map_ops;

    drmgr_init();
    drreg_init(&ops);

    memset(&umbra_map_ops, 0, sizeof(umbra_map_ops));
    umbra_map_ops.scale = UMBRA_MAP_SCALE_DOWN_4X;
    umbra_map_ops.flags =
        UMBRA_MAP_CREATE_SHADOW_ON_TOUCH | UMBRA_MAP_SHADOW_SHARED_READONLY;
    umbra_map_ops.default_value = 0;
    umbra_map_ops.default_value_size = 1;

    if (umbra_init(id) != DRMF_SUCCESS)
        DR_ASSERT_MSG(false, "fail to init umbra");
    if (umbra_create_mapping(&umbra_map_ops, &umbra_map) != DRMF_SUCCESS)
        DR_ASSERT_MSG(false, "fail to create shadow memory mapping");
    drmgr_register_bb_instrumentation_event(event_app_analysis, event_app_instruction,
                                            NULL);
#ifdef WINDOWS
    drmgr_register_exception_event(event_exception_instrumentation);
#else
    drmgr_register_signal_event(event_signal_instrumentation);
#endif
    dr_register_exit_event(exit_event);
}

#ifndef X64
static void
clear_redundant_block(void)
{
    void **drcontexts = NULL;
    uint num_threads = 0;
    uint count = 0;

    /* Prevent repeating the test if already done once. */
    if (!was_redundant_cleared) {
        was_redundant_cleared = true;
        dr_suspend_all_other_threads(&drcontexts, &num_threads, NULL);
        drmf_status_t status = umbra_clear_redundant_blocks(umbra_map, &count);
        DR_ASSERT_MSG(status == DRMF_SUCCESS, "should succeed");
        DR_ASSERT_MSG(count == 1, "should have cleared one block");
        if (drcontexts != NULL) {
            bool okay = dr_resume_all_other_threads(drcontexts, num_threads);
            DR_ASSERT_MSG(okay, "failed to resume threads");
        }
    }
}
#endif

static void
instrument_mem(void *drcontext, instrlist_t *ilist, instr_t *where, opnd_t ref)
{
    reg_id_t regaddr;
    reg_id_t scratch;
    bool ok;

    if (drreg_reserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &regaddr) !=
            DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &scratch) !=
            DRREG_SUCCESS) {
        DR_ASSERT(false); /* can't recover */
        return;
    }

    ok = drutil_insert_get_mem_addr(drcontext, ilist, where, ref, regaddr, scratch);
    DR_ASSERT(ok);
    /* Save the app address to a well-known spill slot, so that the fault handler
     * can recover if no shadow memory was installed yet.
     */
    dr_save_reg(drcontext, ilist, where, regaddr, SPILL_SLOT_2);
    if (umbra_insert_app_to_shadow(drcontext, umbra_map, ilist, where, regaddr, &scratch,
                                   1) != DRMF_SUCCESS)
        DR_ASSERT(false);

    /* trigger a fault to the shared readonly shadow page */
    instrlist_meta_preinsert(
        ilist, where,
        INSTR_XL8(XINST_CREATE_store_1byte(
                      drcontext, OPND_CREATE_MEM8(regaddr, 0),
                      opnd_create_reg(reg_resize_to_opsz(scratch, OPSZ_1))),
                  instr_get_app_pc(where)));

#ifndef X64
    /* Clear shadow byte to zero. */
    instrlist_meta_preinsert(
        ilist, where,
        INSTR_XL8(XINST_CREATE_store_1byte(drcontext, OPND_CREATE_MEM8(regaddr, 0),
                                           opnd_create_immed_int(0, OPSZ_1)),
                  instr_get_app_pc(where)));

    /* Insert clean call to clear redundant block. */
    dr_insert_clean_call(drcontext, ilist, where, clear_redundant_block, false, 0);
#endif

    if (drreg_unreserve_register(drcontext, ilist, where, regaddr) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, scratch) != DRREG_SUCCESS ||
        drreg_unreserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS)
        DR_ASSERT(false);
}

static dr_emit_flags_t
event_app_analysis(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
                   bool translating, OUT void **user_data)
{
    instr_t *inst;
    bool prev_was_mov_const = false;
    ptr_int_t val1, val2;
    *user_data = NULL;
    /* Look for duplicate mov immediates telling us which subtest we're in */
    for (inst = instrlist_first_app(bb); inst != NULL; inst = instr_get_next_app(inst)) {
        if (instr_is_mov_constant(inst, prev_was_mov_const ? &val2 : &val1)) {
            if (prev_was_mov_const && val1 == val2 &&
                val1 != 0 && /* rule out xor w/ self */
                opnd_is_reg(instr_get_dst(inst, 0))) {
                *user_data = (void *)val1;
                instrlist_meta_postinsert(bb, inst, INSTR_CREATE_label(drcontext));
            } else
                prev_was_mov_const = true;
        } else
            prev_was_mov_const = false;
    }
    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where,
                      bool for_trace, bool translating, void *user_data)
{
    ptr_int_t subtest = (ptr_int_t)user_data;
    int i;

    if (subtest != UMBRA_TEST_1_C && subtest != UMBRA_TEST_2_C)
        return DR_EMIT_DEFAULT;

    for (i = 0; i < instr_num_srcs(where); i++) {
        if (opnd_is_memory_reference(instr_get_src(where, i)))
            instrument_mem(drcontext, ilist, where, instr_get_src(where, i));
    }
    for (i = 0; i < instr_num_dsts(where); i++) {
        if (opnd_is_memory_reference(instr_get_dst(where, i)))
            instrument_mem(drcontext, ilist, where, instr_get_dst(where, i));
    }

    return DR_EMIT_DEFAULT;
}

static void
exit_event(void)
{
#ifndef X64
    DR_ASSERT_MSG(was_redundant_cleared,
                  "The clearing of redundant blocks was never called.");
#endif
    if (umbra_destroy_mapping(umbra_map) != DRMF_SUCCESS)
        DR_ASSERT(false);

    umbra_exit();
    drmgr_exit();
    drreg_exit();
}

static reg_id_t
get_faulting_shadow_reg(void *drcontext, dr_mcontext_t *mc)
{
    instr_t inst;
    reg_id_t reg;

    instr_init(drcontext, &inst);
    decode(drcontext, mc->pc, &inst);
    reg = opnd_get_base(instr_get_dst(&inst, 0));
    instr_free(drcontext, &inst);
    return reg;
}

static bool
handle_special_shadow_fault(void *drcontext, dr_mcontext_t *raw_mc, app_pc app_shadow)
{
    umbra_shadow_memory_type_t shadow_type;
    app_pc app_target;
    reg_id_t reg;

    dr_printf("Handling a fault...\n");

    /* If a fault occured, it is probably because we computed the
     * address of shadow memory which was initialized to a shared
     * readonly shadow block. We allocate a shadow page there and
     * replace the reg value used by the faulting instr.
     */
    /* handle faults from writes to special shadow blocks */
    if (umbra_shadow_memory_is_shared(umbra_map, app_shadow, &shadow_type) !=
        DRMF_SUCCESS) {
        DR_ASSERT(false);
        return true;
    }
    if (shadow_type != UMBRA_SHADOW_MEMORY_TYPE_SHARED)
        return true;

    /* Grab the original app target out of the spill slot so we
     * don't have to compute the app target ourselves (this is
     * difficult).
     */
    app_target = (app_pc)dr_read_saved_reg(drcontext, SPILL_SLOT_2);
    dr_printf("Original app memory:         %p\n"
              "Got fault at shadow memory:  %p\n",
              app_target, app_shadow);

    /* replace the shared block, and record the new app shadow */
    if (umbra_replace_shared_shadow_memory(umbra_map, app_target, &app_shadow) !=
        DRMF_SUCCESS) {
        DR_ASSERT(false);
        return true;
    }

    /* Replace the faulting register value to reflect the new shadow
     * memory.
     */
    reg = get_faulting_shadow_reg(drcontext, raw_mc);
    reg_set_value(reg, raw_mc, (reg_t)app_shadow);

    dr_printf("Installed new shadow memory: %p\n", app_shadow);
    return false;
}

#ifdef WINDOWS
bool
event_exception_instrumentation(void *drcontext, dr_exception_t *excpt)
{
    if (excpt->record->ExceptionCode != STATUS_ACCESS_VIOLATION)
        return true;
    return handle_special_shadow_fault(drcontext, excpt->raw_mcontext,
                                       (byte *)excpt->record->ExceptionInformation[1]);
}
#else
static dr_signal_action_t
event_signal_instrumentation(void *drcontext, dr_siginfo_t *info)
{
    if (info->sig != SIGSEGV && info->sig != SIGBUS)
        return DR_SIGNAL_DELIVER;
    DR_ASSERT(info->raw_mcontext_valid);
    return handle_special_shadow_fault(drcontext, info->raw_mcontext,
                                       info->access_address)
        ? DR_SIGNAL_DELIVER
        : DR_SIGNAL_SUPPRESS;
}
#endif
