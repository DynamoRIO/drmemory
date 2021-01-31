/* **************************************************************
 * Copyright (c) 2017-2019 Google, Inc.  All rights reserved.
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

/* Tests that there are no conflicts in any scale factor with the target
 * application.
 */
#include <signal.h>
#include <string.h>
#include  <stdint.h> // for intptr_t

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"
#include "umbra.h"

static void
exit_event(void);
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

static umbra_map_t *umbra_map;
// Flag denoting whether check done via clean call is done.
static bool check_called = false;

/* We don't want a popup so we don't use DR_ASSERT_MSG. */
#define CHECK(cond, msg) ((void)((cond) ? 0 :                   \
    (dr_fprintf(STDERR,  "ASSERT FAILURE: %s:%d: %s (%s)\n",    \
                __FILE__, __LINE__, #cond, msg), dr_abort(), 0)))

#define TEST(mask, var) (((mask) & (var)) != 0)
#ifdef X64
#define SHDW_VAL (void *) 0x111111111111
#else
#define SHDW_VAL (void *) 0x11111111
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    drreg_options_t ops = { sizeof(ops), 4, true };
    umbra_map_options_t umbra_map_ops;

    drmgr_init();
    drreg_init(&ops);

    memset(&umbra_map_ops, 0, sizeof(umbra_map_ops));
    umbra_map_ops.scale = IF_X64_ELSE(UMBRA_MAP_SCALE_UP_8X, UMBRA_MAP_SCALE_UP_4X);
    umbra_map_ops.flags =
        UMBRA_MAP_CREATE_SHADOW_ON_TOUCH | UMBRA_MAP_SHADOW_SHARED_READONLY;
    umbra_map_ops.default_value = 0;
    umbra_map_ops.default_value_size = 1;
#   ifndef X64
    umbra_map_ops.make_redzone_faulty = false;
#    endif
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


static void check()
{
    void *drcontext = dr_get_current_drcontext();
    app_pc app_target = (app_pc)dr_read_saved_reg(drcontext, SPILL_SLOT_2);

    drmf_status_t status;

    // Read shadow value.
    void *data = NULL;
    size_t shdw_size = sizeof(void *);
    status = umbra_read_shadow_memory(umbra_map, app_target, 1, &shdw_size,
                                      (void *) &data);
    CHECK(status == DRMF_SUCCESS, "Failed to read");
    dr_fprintf(STDERR, "SIZES: %p %u %u\n", app_target, shdw_size, sizeof(void *));
    CHECK(shdw_size == sizeof(void *), "read shadow size should be pointer-sized");
    CHECK(data == SHDW_VAL, "read shadow size should be pointer-sized");

    // Write NULL.
    data = NULL;
    status = umbra_write_shadow_memory(umbra_map, app_target, 1, &shdw_size,
                                       (void *) &data);
    CHECK(status == DRMF_SUCCESS, "Failed to write");
    CHECK(shdw_size == sizeof(void *), "write shadow size should be pointer-sized");

    // Set flag.
    check_called = true;
}

static bool get_mem_src_opnd(instr_t * instr, opnd_t *src_mem_opnd)
{
    DR_ASSERT(src_mem_opnd != NULL);
    int src_num = instr_num_srcs(instr);

    for (int i = 0; i < src_num; i++) {
        opnd_t src_opnd = instr_get_src(instr, i);
        if (opnd_is_memory_reference(src_opnd)) {
            *src_mem_opnd = src_opnd;
            return true;
        }
    }

    return false;
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where,
                      bool for_trace, bool translating, void *user_data)
{
    if (instr_reads_memory(where)) {
        // Get src mem operand.
        opnd_t src_mem_opnd;
        bool succ = get_mem_src_opnd(where, &src_mem_opnd);
        if (!succ)
            return DR_EMIT_DEFAULT;

        // Spill scratch registers.
        reg_id_t scratch_reg = DR_REG_NULL;
        reg_id_t scratch_reg2 = DR_REG_NULL;

#       ifdef X86
        drvector_t allowed;
        drreg_init_and_fill_vector(&allowed, false);
        drreg_set_vector_entry(&allowed, DR_REG_XCX, true);
#       endif

        if (drreg_reserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS ||
            drreg_reserve_register(drcontext, ilist, where, IF_X86_ELSE(&allowed, NULL),
                                   &scratch_reg2) != DRREG_SUCCESS ||
            drreg_reserve_register(drcontext, ilist, where, NULL, &scratch_reg) !=
                DRREG_SUCCESS) {
            DR_ASSERT(false); /* Can't recover. */
        }
#       ifdef X86
        drvector_delete(&allowed);
#       endif

        succ = drutil_insert_get_mem_addr(drcontext, ilist, where, src_mem_opnd,
                                          scratch_reg, scratch_reg2);
        DR_ASSERT(succ);

        /* Save the app address to a well-known spill slot, so that the fault handler
         * can recover if no shadow memory was installed yet.
         */
        dr_save_reg(drcontext, ilist, where, scratch_reg, SPILL_SLOT_2);

        drmf_status_t status = umbra_insert_app_to_shadow(drcontext, umbra_map, ilist,
                                                          where, scratch_reg,
                                                          &scratch_reg2, 1);
        DR_ASSERT_MSG(status == DRMF_SUCCESS, "fail to insert translation");

        instr_t *instr;

        // Load shadow value to reg.
        opnd_t reg_opnd = opnd_create_reg(scratch_reg);
        instrlist_insert_mov_immed_ptrsz(drcontext, (ptr_int_t) SHDW_VAL, reg_opnd,
                                         ilist, where, NULL, NULL);

        opnd_t shadow_opnd = opnd_create_base_disp(scratch_reg, DR_REG_NULL, 0, 0,
                                                   OPSZ_PTR);
        opnd_t src_opnd = opnd_create_reg(scratch_reg2);
        instr = XINST_CREATE_store(drcontext, shadow_opnd, src_opnd);
        instr_set_translation(instr, instr_get_app_pc(where));
        instrlist_meta_preinsert(ilist, where, instr);

        // Use a clean call to check write and refresh shadow value.
        dr_insert_clean_call(drcontext, ilist, where, check, false, 0);

        if (drreg_unreserve_register(drcontext, ilist,
                                     where, scratch_reg) != DRREG_SUCCESS ||
            drreg_unreserve_register(drcontext, ilist,
                                     where, scratch_reg2) != DRREG_SUCCESS ||
            drreg_unreserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS)
            DR_ASSERT(false);
    }

    return DR_EMIT_DEFAULT;
}

static bool
handle_special_shadow_fault(void *drcontext, dr_mcontext_t *raw_mc, app_pc app_shadow)
{
    umbra_shadow_memory_type_t shadow_type;
    app_pc app_target;
    instr_t inst;
    reg_id_t reg;
    opnd_t opnd;

    instr_init(drcontext, &inst);
    decode(drcontext, raw_mc->pc, &inst);
    opnd = instr_get_dst(&inst, 0);
    DR_ASSERT_MSG(opnd_is_base_disp(opnd),
                  "faulty instr should have a mem operand as a destination.");
    reg = opnd_get_base(opnd);
    instr_free(drcontext, &inst);

    if (umbra_get_shadow_memory_type(umbra_map, app_shadow, &shadow_type) !=
        DRMF_SUCCESS) {
        DR_ASSERT(false);
        return true;
    }

    if (TEST(UMBRA_SHADOW_MEMORY_TYPE_SHARED, shadow_type)) {
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

static void
exit_event(void)
{
    DR_ASSERT_MSG(check_called, "check was never performed");

    if (umbra_destroy_mapping(umbra_map) != DRMF_SUCCESS)
        DR_ASSERT(false);

    umbra_exit();
    drreg_exit();
    drmgr_exit();
}
