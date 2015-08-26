/* **************************************************************
 * Copyright (c) 2015 Google, Inc.  All rights reserved.
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

/* Test of fault handling in the Dr. Fuzz Extension */

#include "dr_api.h"
#include <string.h>
#include "drmgr.h"
#include "drsyms.h"
#include "drwrap.h"
#include "drfuzz.h"

/* Finds the print_data() function in the target app. */
#ifdef UNIX
# define TARGET_SYMBOL "drfuzz_app_segfault!print_data"
#else
# define TARGET_SYMBOL "print_data"
#endif

#undef EXPECT /* we don't want msgbox */
#define EXPECT(cond, msg) \
    ((void)((!(cond)) ? \
     (dr_fprintf(STDERR, "EXPECT FAILURE: %s:%d: %s (%s)", \
                 __FILE__,  __LINE__, #cond, msg), \
      dr_abort(), 0) : 0))

/* Some fake user data to attach to fuzzer data structures. */
static const char *fake_stack_trace = "fake stack trace";
static const char *fake_per_thread_data = "fake per thread data";
static const char *fake_target_data = "fake target data";

/* Trivial state for driving the test. */
static bool invoke_crash;
static bool invoke_abort;
static bool per_thread_is_null = true;
static bool fault_delete_occurred = false;
static bool repeating_target = false;
static uint repeat_index = 0;

/* Report to STDERR when a critical fault occurs in a fuzz target. */
static void
fault_event(void *fuzzcxt, drfuzz_fault_t *fault, drfuzz_fault_ex_t *fault_ex)
{
    drfuzz_target_frame_t *target_frame;
    drfuzz_target_iterator_t *iter = drfuzz_target_iterator_start(fuzzcxt);

    while ((target_frame = drfuzz_target_iterator_next(iter)) != NULL) {
        uint i;
        dr_fprintf(STDERR, "Fault occured in target "PIFX" with %d args: ",
               (ptr_uint_t) target_frame->func_pc, target_frame->arg_count);
        for (i = 0; i < target_frame->arg_count; i++) {
            dr_fprintf(STDERR, PIFX, target_frame->arg_values[i]);
            if (i < (target_frame->arg_count - 1))
                dr_fprintf(STDERR, ", ");
        }
        dr_fprintf(STDERR, "\n");
    }
    drfuzz_target_iterator_stop(iter);

    fault->user_data = (void *) fake_stack_trace;
}

/* Make sure the fake user data is still set on the segfault instance. */
static void
fault_deleted(void *fuzzcxt, drfuzz_fault_t *fault)
{
    EXPECT(fault->user_data == fake_stack_trace, "user data is incorrect");
    fault_delete_occurred = true;
}

/* Make sure the fake user data is still set on the fuzz target per-thread instance. */
static void
delete_per_thread_data(void *fuzzcxt, void *per_thread_data)
{
    EXPECT(per_thread_data == (per_thread_is_null ? NULL : fake_per_thread_data),
                               "per-thread user data is incorrect");
}

/* Make sure the fake user data is still set on the fuzz target instance. */
static void
delete_per_target_data(void *per_target_data)
{
    EXPECT(per_target_data == fake_target_data, "per-target user data is incorrect");
}

/* Find the fuzz target. */
static generic_func_t
find_target_pc()
{
    size_t symbol_offset;
    drsym_debug_kind_t kind;
    drsym_error_t result;
    generic_func_t target;
    module_data_t *module = dr_get_main_module();

    EXPECT(module != NULL, "Main module not initialized");

    /* give a meaningful error message if the module doesn't have symbols */
    if (drsym_get_module_debug_kind(module->full_path, &kind) != DRSYM_SUCCESS)
        EXPECT(false, "module does not have symbols");

    result = drsym_lookup_symbol(module->full_path, TARGET_SYMBOL, &symbol_offset, 0);
    EXPECT(result == DRSYM_SUCCESS && symbol_offset > 0, "cannot find symbol");

    target = (generic_func_t) (module->start + symbol_offset);
    dr_free_module_data(module);
    return target;
}

/* When the app crashes, report the live fuzz targets and args to STDERR. */
static void
thread_crash(void *fuzzcxt, drfuzz_fault_thread_state_t *state)
{
    drfuzz_target_frame_t *target_frame;

    EXPECT(state->targets != NULL, "fuzz targets are missing from the crash state");
    while ((target_frame = drfuzz_target_iterator_next(state->targets)) != NULL) {
        uint i;
        dr_fprintf(STDERR, "Crash originated in target "PIFX" with %d args: ",
               (ptr_uint_t) target_frame->func_pc, target_frame->arg_count);
        for (i = 0; i < target_frame->arg_count; i++) {
            dr_fprintf(STDERR, PIFX, (ptr_uint_t) target_frame->arg_values[i]);
            if (i < (target_frame->arg_count - 1))
                dr_fprintf(STDERR, ", ");
        }
        dr_fprintf(STDERR, "\n");
    }
}

/* Fuzz driver. When the target app is executed natively, it will invoke the fuzz target
 * (print_data()) 10 times. This driver repeats each of those invocations 3 times without
 * changing the arguments, to test the scope and release of the per-target per-thread user
 * data. Then on the last iteration (where the app's index arg is 9), the index is changed
 * to 100000, causing a segfault by attempting to read a static array way out of bounds.
 */
static void
pre_fuzz(void *fuzzcxt, generic_func_t target_pc, dr_mcontext_t *mc)
{
    drmf_status_t res;
    const char *user_data;
    ptr_uint_t index_arg;

    if (drfuzz_get_arg(fuzzcxt, target_pc, 0, true, (void *) &index_arg) != DRMF_SUCCESS)
        EXPECT(false, "failed to get fuzz target's arg value");

    if (repeating_target) {
        res = drfuzz_get_target_per_thread_user_data(fuzzcxt, target_pc,
                                                     (void *) &user_data);
        EXPECT(res == DRMF_SUCCESS, "failed to get target per-thread data");
        EXPECT(user_data == fake_per_thread_data, "incorrect target per-thread data");
    } else {
        res = drfuzz_set_target_per_thread_user_data(fuzzcxt, target_pc,
                                                     (void *) fake_per_thread_data,
                                                     delete_per_thread_data);
        EXPECT(res == DRMF_SUCCESS, "failed to set target per-thread data");
        per_thread_is_null = false;
    }

    repeating_target = (repeat_index++ < 3);

    if (!repeating_target) {
        res = drfuzz_set_target_per_thread_user_data(fuzzcxt, target_pc, NULL,
                                                     delete_per_thread_data);
        EXPECT(res == DRMF_SUCCESS, "failed to clear the target per-thread data");
        per_thread_is_null = true;
        res = drfuzz_get_target_per_thread_user_data(fuzzcxt, target_pc,
                                                     (void *) &user_data);
        EXPECT(res == DRMF_SUCCESS, "failed to get the cleared target per-thread data");
        EXPECT(user_data == NULL, "incorrect target per-thread data");
    }

    if (invoke_crash && index_arg == 9)
        drfuzz_set_arg(fuzzcxt, 0, (void *) 10000000);
    if (invoke_abort && index_arg == 9)
        drfuzz_set_arg(fuzzcxt, 0, (void *) 11);
}

/* Just checks the per-target user data and directs drfuzz as decided in pre-fuzz. */
static bool
post_fuzz(void *fuzzcxt, generic_func_t target_pc)
{
    drmf_status_t res;
    const char *user_data;

    res = drfuzz_get_target_user_data(target_pc, (void *) &user_data);
    EXPECT(res == DRMF_SUCCESS, "failed to get the target data");
    EXPECT(user_data == fake_target_data, "failed to get the target data");

    return repeating_target;
}

/* Test passes if none of the EXPECT statements fail. */
static
void exit_event(void)
{
    EXPECT(!invoke_crash || fault_delete_occurred, "fault user data was not deleted");
    EXPECT(invoke_crash || !fault_delete_occurred, "unexpected fault delete callback");
    if (drfuzz_exit() != DRMF_SUCCESS)
        EXPECT(false, "drfuzz failed to exit");
    dr_fprintf(STDERR, "TEST PASSED\n");
    drmgr_exit();
    drsym_exit();

    dr_exit_process(0); /* change the exit code so ctest believes the test passed */
}

/* Initialize drfuzz, register the fuzz target and related callbacks, and set some
 * fake data in the per-target user data field.
 */
DR_EXPORT
void dr_client_main(client_id_t id, int argc, const char *argv[])
{
    generic_func_t target_pc;

    invoke_crash = (argc > 1 && strcmp(argv[1], "-crash") == 0);
    invoke_abort = (argc > 1 && strcmp(argv[1], "-abort") == 0);

    drmgr_init();
    drsym_init(0);
    dr_register_exit_event(exit_event);

    if (drfuzz_init(id) != DRMF_SUCCESS)
        EXPECT(false, "drfuzz failed to init");
    if (drfuzz_register_fault_event(fault_event) != DRMF_SUCCESS)
        EXPECT(false, "failed to register the fault event");
    if (drfuzz_register_fault_delete_callback(fault_deleted) != DRMF_SUCCESS)
        EXPECT(false, "failed to register the fault delete callback");
    if (drfuzz_register_crash_thread_event(thread_crash) != DRMF_SUCCESS)
        EXPECT(false, "failed to register the thread crash event");

    target_pc = find_target_pc();
    if (drfuzz_fuzz_target(target_pc, 1, 0, DRWRAP_CALLCONV_DEFAULT,
                           pre_fuzz, post_fuzz) != DRMF_SUCCESS)
        EXPECT(false, "failed to register the fuzz target");

    drfuzz_set_target_user_data(target_pc, (void *) fake_target_data,
                                delete_per_target_data);
}
