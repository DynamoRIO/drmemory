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

/* Test of the Dr. Fuzz Extension */

#include "dr_api.h"
#include "drmgr.h"
#include "drfuzz.h"

#undef EXPECT /* we don't want msgbox */
#define EXPECT(cond, msg) \
    ((void)((!(cond)) ? \
     (dr_fprintf(STDERR, "EXPECT FAILURE: %s:%d: %s (%s)", \
                 __FILE__,  __LINE__, #cond, msg), \
      dr_abort(), 0) : 0))

static void
pre_fuzz_cb(void *fuzzcxt, generic_func_t target_pc, dr_mcontext_t *mc)
{
    ptr_uint_t arg_value;

    if (drfuzz_get_arg(fuzzcxt, target_pc, 0, false/*cur*/,
                       (void **) &arg_value) != DRMF_SUCCESS)
        EXPECT(false, "drfuzz failed to get arg");
    arg_value = (arg_value + 1);
    if (drfuzz_set_arg(fuzzcxt, 0, (void *)arg_value) != DRMF_SUCCESS)
        EXPECT(false, "drfuzz failed to set arg");
}

static bool
post_fuzz_cb(void *fuzzcxt, generic_func_t target_pc)
{
    ptr_uint_t arg_value;

    if (drfuzz_get_arg(fuzzcxt, target_pc, 0, false/*cur*/,
                       (void **) &arg_value) != DRMF_SUCCESS)
        EXPECT(false, "drfuzz failed to get arg");
    if (arg_value == 5)
        return false; /* stop */
    return true; /* repeat */
}

static void
exit_event(void)
{
    if (drfuzz_exit() != DRMF_SUCCESS)
        EXPECT(false, "drfuzz failed to exit");
    dr_fprintf(STDERR, "TEST PASSED\n");
    drmgr_exit();
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    module_data_t *app;
    generic_func_t repeatme_addr;
    drmgr_init();
    if (drfuzz_init(id) != DRMF_SUCCESS)
        EXPECT(false, "drfuzz failed to init");
    dr_register_exit_event(exit_event);

    /* fuzz repeatme */
    app = dr_get_main_module();
    if (app == NULL)
        EXPECT(false, "failed to get application module");
    repeatme_addr = dr_get_proc_address(app->handle, "repeatme");
    if (repeatme_addr == NULL)
        EXPECT(false, "failed to find function repeatme");
    if (drfuzz_fuzz_target(repeatme_addr, 1, 0, DRWRAP_CALLCONV_DEFAULT,
                           pre_fuzz_cb, post_fuzz_cb) != DRMF_SUCCESS)
        EXPECT(false, "drfuzz failed to fuzz function repeatme");
    dr_free_module_data(app);
}
