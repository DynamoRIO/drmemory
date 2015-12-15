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

/* Dr. Fuzz custom mutator for testing purposes */

#include "dr_api.h"
#include <string.h>
#include "drfuzz_mutator.h"

typedef struct _mutator_t {
    size_t size;
    void *input_seed;
    void *current_value;
    uint toadd;
} mutator_t;

#define DEFAULT_TOADD 0xf0f00a0a

LIB_EXPORT drmf_status_t
drfuzz_mutator_start(OUT drfuzz_mutator_t **mutator_out, IN void *input_seed,
                     IN size_t size, IN int argc, IN const char *argv[])
{
    mutator_t *mutator;
    int i;

    if (mutator_out == NULL || input_seed == NULL || size == 0 ||
        (argv == NULL && argc > 0))
        return DRMF_ERROR_INVALID_PARAMETER;

    /* For testing we only support an int */
    if (size < sizeof(int))
        return DRMF_ERROR_INVALID_PARAMETER;

    mutator = dr_global_alloc(sizeof(mutator_t));
    memset(mutator, 0, sizeof(mutator_t));
    mutator->size = size;
    mutator->toadd = DEFAULT_TOADD;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-add") == 0) {
            if (i >= argc - 1) {
                dr_global_free(mutator, sizeof(mutator_t));
                return DRMF_ERROR_INVALID_PARAMETER;
            }
            mutator->toadd = strtoul(argv[++i], NULL, 0);
        } else {
            dr_global_free(mutator, sizeof(mutator_t));
            return DRMF_ERROR_INVALID_PARAMETER;
        }
    }

    mutator->input_seed = dr_global_alloc(size);
    memcpy(mutator->input_seed, input_seed, size);
    mutator->current_value = dr_global_alloc(size);
    memcpy(mutator->current_value, input_seed, size);

    *mutator_out = (drfuzz_mutator_t *) mutator;
    return DRMF_SUCCESS;
}

LIB_EXPORT bool
drfuzz_mutator_has_next_value(drfuzz_mutator_t *mutator_in)
{
    return true;
}

LIB_EXPORT drmf_status_t
drfuzz_mutator_get_current_value(IN drfuzz_mutator_t *mutator_in, OUT void *buffer)
{
    mutator_t *mutator = (mutator_t *) mutator_in;
    memcpy(buffer, mutator->current_value, mutator->size);
    return DRMF_SUCCESS;
}

LIB_EXPORT drmf_status_t
drfuzz_mutator_get_next_value(drfuzz_mutator_t *mutator_in, IN void *buffer)
{
    mutator_t *mutator = (mutator_t *) mutator_in;
    int val = *(int *)mutator->current_value;
    val += mutator->toadd;
    *(int *)mutator->current_value = val;
    memcpy(buffer, mutator->current_value, mutator->size);
    return DRMF_SUCCESS;
}

LIB_EXPORT drmf_status_t
drfuzz_mutator_stop(drfuzz_mutator_t *mutator_in)
{
    mutator_t *mutator = (mutator_t *) mutator_in;
    dr_global_free(mutator->input_seed, mutator->size);
    dr_global_free(mutator->current_value, mutator->size);
    dr_global_free(mutator, sizeof(mutator_t));
    return DRMF_SUCCESS;
}

LIB_EXPORT drmf_status_t
drfuzz_mutator_feedback(drfuzz_mutator_t *mutator_in, int feedback)
{
    /* do nothing */
    return DRMF_SUCCESS;
}
