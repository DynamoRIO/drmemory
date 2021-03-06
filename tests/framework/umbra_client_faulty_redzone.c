/* **************************************************************
 * Copyright (c) 2020 Google, Inc.  All rights reserved.
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

/* Tests umbra's faulty redzone option. */

#include <signal.h>
#include <string.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"
#include "umbra.h"

#define TEST(mask, var) (((mask) & (var)) != 0)

static umbra_map_t *umbra_map;
/* Denotes whether redzone faults were ever handled during the run. */
static bool *did_redzone_fault;

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

    /* Initialise reachable flag. */
    did_redzone_fault = dr_global_alloc(sizeof(bool));
    *did_redzone_fault = false;

    memset(&umbra_map_ops, 0, sizeof(umbra_map_ops));
    umbra_map_ops.scale = UMBRA_MAP_SCALE_DOWN_4X;
    umbra_map_ops.flags =
        UMBRA_MAP_CREATE_SHADOW_ON_TOUCH | UMBRA_MAP_SHADOW_SHARED_READONLY;
    umbra_map_ops.default_value = 0;
    umbra_map_ops.default_value_size = 1;
    /* Enable redzones and make them faulty. */
    umbra_map_ops.make_redzone_faulty = true;
    if (umbra_init(id) != DRMF_SUCCESS)
        DR_ASSERT_MSG(false, "fail to init umbra");
    if (umbra_create_mapping(&umbra_map_ops, &umbra_map) != DRMF_SUCCESS)
        DR_ASSERT_MSG(false, "fail to create shadow memory mapping");
    drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL);
#ifdef WINDOWS
    drmgr_register_exception_event(event_exception_instrumentation);
#else
    drmgr_register_signal_event(event_signal_instrumentation);
#endif
    dr_register_exit_event(exit_event);
}

static void
insert_redzone_entry(void *drcontext, instrlist_t *ilist, instr_t *where, opnd_t ref,
                     reg_id_t scratch_reg, reg_id_t scratch_reg2)
{
    bool ok;

    // Get app address.
    ok = drutil_insert_get_mem_addr(drcontext, ilist, where, ref, scratch_reg, scratch_reg2);
    DR_ASSERT(ok);
    /* Save the app address to a well-known spill slot, so that the fault handler
     * can recover if no shadow memory was installed yet.
     */
    dr_save_reg(drcontext, ilist, where, scratch_reg, SPILL_SLOT_2);

    if (umbra_insert_app_to_shadow(drcontext, umbra_map, ilist, where, scratch_reg, &scratch_reg2,
                                   1) != DRMF_SUCCESS) {
        DR_ASSERT(false);
    }

    /* Use a displacement of a page size to access ahead and try to hit a faulty
     * redzone. Naturally, this does not guarantee that the red-zone will always
     * be accessed, but we hope that it will hit at least once to trigger a fault.
     */
    instrlist_meta_preinsert(
        ilist, where,
        INSTR_XL8(XINST_CREATE_store_1byte(
                      drcontext,
                      OPND_CREATE_MEM8(scratch_reg, dr_page_size() /* try enter redzone */),
                      opnd_create_reg(reg_resize_to_opsz(scratch_reg2, OPSZ_1))),
                  instr_get_app_pc(where)));
}

static bool
instrument_mem(void *drcontext, instrlist_t *ilist, instr_t *where,
               reg_id_t scratch_reg, reg_id_t scratch_reg2)
{
    int i;
    for (i = 0; i < instr_num_srcs(where); i++) {
        if (opnd_is_memory_reference(instr_get_src(where, i))) {
            insert_redzone_entry(drcontext, ilist, where, instr_get_src(where, i),
                                 scratch_reg, scratch_reg2);
            return true;
        }
    }
    for (i = 0; i < instr_num_dsts(where); i++) {
        if (opnd_is_memory_reference(instr_get_dst(where, i))) {
            insert_redzone_entry(drcontext, ilist, where, instr_get_dst(where, i),
                                 scratch_reg, scratch_reg2);
            return true;
        }
    }

    // Found no memory operand to instrument.
    return false;
}

static bool
instr_uses_mem(instr_t *where)
{
    int i;
    for (i = 0; i < instr_num_srcs(where); i++) {
        if (opnd_is_memory_reference(instr_get_src(where, i)))
          return true;
    }
    for (i = 0; i < instr_num_dsts(where); i++) {
        if (opnd_is_memory_reference(instr_get_dst(where, i)))
            return true;
    }

    return false;
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where,
                      bool for_trace, bool translating, void *user_data)
{
    reg_id_t scratch_reg = DR_REG_NULL;
    reg_id_t scratch_reg2 = DR_REG_NULL;
    instr_t *label = NULL;
    bool uses_mem = instr_uses_mem(where);

    if (!uses_mem)
        return DR_EMIT_DEFAULT;

#   ifdef X86
    drvector_t allowed;
    drreg_init_and_fill_vector(&allowed, false);
    drreg_set_vector_entry(&allowed, DR_REG_XCX, true);
#   endif

    if (drreg_reserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, IF_X86_ELSE(&allowed, NULL),
                               &scratch_reg2) != DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &scratch_reg) !=
            DRREG_SUCCESS) {
        DR_ASSERT(false); /* Can't recover. */
    }
#   ifdef X86
    drvector_delete(&allowed);
#   endif

    DR_ASSERT_MSG(scratch_reg != DR_REG_NULL,
                  "First scratch register should not be NULL");
    DR_ASSERT_MSG(scratch_reg2 != DR_REG_NULL,
                  "Second scratch register should not be NULL");

    opnd_t flag_opnd = opnd_create_abs_addr(did_redzone_fault, OPSZ_1);
    instr_t *load_instr = XINST_CREATE_load_1byte_zext4(drcontext,
                                                        opnd_create_reg(scratch_reg),
                                                        flag_opnd);
    instrlist_meta_preinsert(ilist, where, load_instr);

    instr_t * check_instr = XINST_CREATE_cmp(drcontext, opnd_create_reg(scratch_reg),
                                             opnd_create_immed_int(0, OPSZ_1));
    instrlist_meta_preinsert(ilist, where, check_instr);

    label = INSTR_CREATE_label(drcontext);
    instr_t * jmp_instr = XINST_CREATE_jump_cond(drcontext, DR_PRED_NE,
                                                 opnd_create_instr(label));
    instrlist_meta_preinsert(ilist, where, jmp_instr);

    /* We need to calculate addresses. Restore scratch registers
     * back to their original values.
     */
    drreg_status_t status =
    drreg_get_app_value(drcontext, ilist, where, scratch_reg, scratch_reg);
    DR_ASSERT_MSG(status == DRREG_SUCCESS, "failed to restore scratch reg");

    status =
    drreg_get_app_value(drcontext, ilist, where, scratch_reg2, scratch_reg2);
    DR_ASSERT_MSG(status == DRREG_SUCCESS, "failed to restore scratch reg");

    bool ok = instrument_mem(drcontext, ilist, where, scratch_reg, scratch_reg2);
    DR_ASSERT_MSG(ok, "failed to instrument a memory operand");

    instrlist_meta_preinsert(ilist, where, label);

    if (drreg_unreserve_register(drcontext, ilist, where, scratch_reg) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, scratch_reg2) != DRREG_SUCCESS ||
        drreg_unreserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS)
        DR_ASSERT(false);

    return DR_EMIT_DEFAULT;
}

static void
exit_event(void)
{
    if (umbra_destroy_mapping(umbra_map) != DRMF_SUCCESS)
        DR_ASSERT(false);

    DR_ASSERT_MSG(*did_redzone_fault, "no redzone faults have been handled");

    dr_global_free(did_redzone_fault, sizeof(bool));

    umbra_exit();
    drreg_exit();
    drmgr_exit();
}

static bool
handle_special_shadow_fault(void *drcontext, dr_mcontext_t *raw_mc, app_pc app_shadow)
{
    umbra_shadow_memory_type_t shadow_type;
    app_pc app_target;
    instr_t inst;
    reg_id_t reg;
    bool is_page_disp;

    instr_init(drcontext, &inst);
    decode(drcontext, raw_mc->pc, &inst);
    is_page_disp = opnd_get_disp(instr_get_dst(&inst, 0)) == dr_page_size();
    reg = opnd_get_base(instr_get_dst(&inst, 0));
    instr_free(drcontext, &inst);

    if (umbra_get_shadow_memory_type(umbra_map, app_shadow, &shadow_type) !=
        DRMF_SUCCESS) {
        DR_ASSERT(false);
        return true;
    }

    if (!TEST(UMBRA_SHADOW_MEMORY_TYPE_SHARED, shadow_type) &&
        !TEST(UMBRA_SHADOW_MEMORY_TYPE_REDZONE, shadow_type) && !is_page_disp) {
        return true;
    } else if (!TEST(UMBRA_SHADOW_MEMORY_TYPE_SHARED, shadow_type) &&
               !TEST(UMBRA_SHADOW_MEMORY_TYPE_REDZONE, shadow_type) && is_page_disp) {
        /* Something weird has happened. Unlikely that a fault with a page size
         * displacement is triggered not due to special or redzone regions.
         */
        DR_ASSERT(false);
        return true;
    } else if ((!TEST(UMBRA_SHADOW_MEMORY_TYPE_SHARED, shadow_type) ||
                TEST(UMBRA_SHADOW_MEMORY_TYPE_REDZONE, shadow_type)) &&
               !is_page_disp) {
        /* Something weird has happened. Unlikely that a fault
         * is triggered due to special or redzone regions where no page size
         * displacement is present.
         */
        DR_ASSERT(false);
        return true;
    }

    if (TEST(UMBRA_SHADOW_MEMORY_TYPE_REDZONE, shadow_type)) {
        *did_redzone_fault = true;
        /* Fetch the base and cancel out the displacement so that we do
         * not hit the redzone again.
         */
        app_pc base_addr = (app_pc)(reg_t)reg_get_value(reg, raw_mc);
        app_shadow = base_addr - dr_page_size();
    } else {
        /* This fault does not concern redzone handling. Instead, we need to create
         * shadow memory on demand.
         */
        DR_ASSERT(shadow_type == UMBRA_SHADOW_MEMORY_TYPE_SHARED);

        app_target = (app_pc)dr_read_saved_reg(drcontext, SPILL_SLOT_2);
        if (umbra_replace_shared_shadow_memory(umbra_map, app_target, &app_shadow) !=
            DRMF_SUCCESS) {
            DR_ASSERT(false);
            return true;
        }
    }

    reg_set_value(reg, raw_mc, (reg_t)app_shadow);

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
