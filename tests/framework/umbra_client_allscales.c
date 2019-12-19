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

#include <string.h>

#include "dr_api.h"
#include "umbra.h"

/* We don't want a popup so we don't use DR_ASSERT_MSG. */
#define CHECK(cond, msg) ((void)((cond) ? 0 :                   \
    (dr_fprintf(STDERR,  "ASSERT FAILURE: %s:%d: %s (%s)\n",    \
                __FILE__, __LINE__, #cond, msg), dr_abort(), 0)))

static void
test_umbra_mapping(client_id_t id, umbra_map_scale_t scale, const char *label)
{
    dr_printf("\n====================\ntesting scale %d == %s\n", scale, label);
    umbra_map_t *umbra_map;
    umbra_map_options_t umbra_map_ops;
    memset(&umbra_map_ops, 0, sizeof(umbra_map_ops));
    umbra_map_ops.scale = scale;
    umbra_map_ops.flags = UMBRA_MAP_CREATE_SHADOW_ON_TOUCH |
        UMBRA_MAP_SHADOW_SHARED_READONLY;
    umbra_map_ops.default_value = 0;
    umbra_map_ops.default_value_size = 1;
    if (umbra_init(id) != DRMF_SUCCESS)
        CHECK(false, "failed to init umbra");
    if (umbra_create_mapping(&umbra_map_ops, &umbra_map) != DRMF_SUCCESS)
        CHECK(false, "failed to create shadow memory mapping");
    if (umbra_destroy_mapping(umbra_map) != DRMF_SUCCESS)
        CHECK(false, "failed to destroy shadow memory mapping");
    umbra_exit();
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    test_umbra_mapping(id, UMBRA_MAP_SCALE_DOWN_8X, "down 8x");
    test_umbra_mapping(id, UMBRA_MAP_SCALE_DOWN_4X, "down 4x");
    test_umbra_mapping(id, UMBRA_MAP_SCALE_DOWN_2X, "down 2x");
    test_umbra_mapping(id, UMBRA_MAP_SCALE_SAME_1X, "one-to-one");
    test_umbra_mapping(id, UMBRA_MAP_SCALE_UP_2X, "up 2x");
}
