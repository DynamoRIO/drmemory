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

/* Tests for consistency between umbra_insert_app_to_shadow() and
 * umbra_get_shadow_memory().
 */

#include <string.h>

#include "dr_api.h"
#include "drmgr.h"
#include "umbra.h"
#include "drreg.h"
#include "drutil.h"

#include "umbra_test_shared.h"

static umbra_map_t *umbra_map;

static dr_emit_flags_t
event_app_analysis(void *drcontext, void *tag, instrlist_t *bb,
                   bool for_trace, bool translating, OUT void **user_data);

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where,
                      bool for_trace, bool translating, void *user_data);

static void
exit_event(void);

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    drreg_options_t ops = {sizeof(ops), 4, true};
    umbra_map_options_t umbra_map_ops;

    drmgr_init();
    drreg_init(&ops);

    memset(&umbra_map_ops, 0, sizeof(umbra_map_ops));
    umbra_map_ops.scale              = UMBRA_MAP_SCALE_DOWN_4X;
    umbra_map_ops.flags              = UMBRA_MAP_CREATE_SHADOW_ON_TOUCH |
                                       UMBRA_MAP_SHADOW_SHARED_READONLY;
    umbra_map_ops.default_value      = 0;
    umbra_map_ops.default_value_size = 1;

    if (umbra_init(id) != DRMF_SUCCESS)
        DR_ASSERT_MSG(false, "fail to init umbra");
    if (umbra_create_mapping(&umbra_map_ops, &umbra_map) != DRMF_SUCCESS)
        DR_ASSERT_MSG(false, "fail to create shadow memory mapping");
    drmgr_register_bb_instrumentation_event(event_app_analysis,
                                            event_app_instruction, NULL);
    dr_register_exit_event(exit_event);
}

static void
test_shadow(app_pc shadow)
{
    void *drcontext = dr_get_current_drcontext();
    app_pc target = (app_pc)dr_read_saved_reg(drcontext, SPILL_SLOT_2);
    app_pc shadow_expect;
    umbra_shadow_memory_info_t info;

    info.struct_size = sizeof(info);
    if (umbra_get_shadow_memory(umbra_map, target,
                                &shadow_expect, &info) != DRMF_SUCCESS) {
        DR_ASSERT(false);
    }
    DR_ASSERT(shadow == shadow_expect);
}

static void
instrument_mem(void *drcontext, instrlist_t *ilist, instr_t *where, opnd_t ref,
               bool write)
{
    reg_id_t regaddr;
    reg_id_t scratch;
    bool ok;

    if (drreg_reserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &regaddr)
        != DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &scratch)
        != DRREG_SUCCESS) {
        DR_ASSERT(false); /* can't recover */
        return;
    }

    ok = drutil_insert_get_mem_addr(drcontext, ilist, where, ref, regaddr, scratch);
    DR_ASSERT(ok);

    /* save the app address for our clean call so we don't have to spill more registers */
    dr_save_reg(drcontext, ilist, where, regaddr, SPILL_SLOT_2);
    if (umbra_insert_app_to_shadow(drcontext, umbra_map, ilist, where, regaddr,
                                   &scratch, 1) != DRMF_SUCCESS)
        DR_ASSERT(false);
    dr_insert_clean_call(drcontext, ilist, where, test_shadow, false, 1,
                         opnd_create_reg(regaddr));

    if (drreg_unreserve_register(drcontext, ilist, where, regaddr) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, scratch) != DRREG_SUCCESS ||
        drreg_unreserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS)
        DR_ASSERT(false);
}

static dr_emit_flags_t
event_app_analysis(void *drcontext, void *tag, instrlist_t *bb,
                   bool for_trace, bool translating, OUT void **user_data)
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
                *user_data = (void *) val1;
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
    ptr_int_t subtest = (ptr_int_t) user_data;
    int i;

    if (subtest != UMBRA_TEST_1_C && subtest != UMBRA_TEST_2_C)
        return DR_EMIT_DEFAULT;

    for (i = 0; i < instr_num_srcs(where); i++) {
        if (opnd_is_memory_reference(instr_get_src(where, i)))
            instrument_mem(drcontext, ilist, where, instr_get_src(where, i), false);
    }
    for (i = 0; i < instr_num_dsts(where); i++) {
        if (opnd_is_memory_reference(instr_get_dst(where, i)))
            instrument_mem(drcontext, ilist, where, instr_get_dst(where, i), true);
    }

    return DR_EMIT_DEFAULT;
}

static void
exit_event(void)
{
    if (umbra_destroy_mapping(umbra_map) != DRMF_SUCCESS)
        DR_ASSERT(false);

    umbra_exit();
    drmgr_exit();
    drreg_exit();
}
