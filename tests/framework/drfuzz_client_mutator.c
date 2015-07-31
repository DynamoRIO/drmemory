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

/* Test of the Dr. Fuzz Default Mutator */

#include "dr_api.h"
#include "drfuzz_mutator.h"
#include "drfuzz.h"

#undef EXPECT /* we don't want msgbox */
#define EXPECT(cond, msg) \
    ((void)((!(cond)) ? \
     (dr_fprintf(STDERR, "EXPECT FAILURE: %s:%d: %s (%s)", \
                 __FILE__,  __LINE__, #cond, msg), \
      dr_abort(), 0) : 0))

#define MAX_BUFFER_LENGTH 256

static drfuzz_mutator_t *mutator_rand, *mutator_iter;
static byte current_value_buffer[MAX_BUFFER_LENGTH];
static void *current_value = current_value_buffer;

static bool
is_bitwise_identical(void *first, void *second, size_t size)
{
    uint i;
    byte *a = (byte *) first, *b = (byte *) second;

    for (i = 0; i < size; i++) {
        if (a[i] != b[i])
            return false;
    }
    return true;
}

static bool
is_all_zero(void *buffer_in, size_t size)
{
    uint i;
    byte *buffer = (byte *) buffer_in;

    for (i = 0; i < size; i++) {
        if (buffer[i] != 0)
            return false;
    }
    return true;
}

static inline uint64
get_random_value()
{
    return ((uint64) dr_get_random_value(0xffffffff) << 0x20 |
            (uint64) dr_get_random_value(0xffffffff));
}

static uint64
choose_max_value(size_t size)
{
    if (size == 8) {
        return get_random_value();
    } else {
        uint64 max_value, max_value_within_capacity;
        uint64 capacity = 1ULL << ((uint64) size * 8ULL);
        do {
            max_value = get_random_value();
            max_value_within_capacity = max_value % capacity;
        } while (max_value_within_capacity < 2ULL); /* need something non-trivial */
        return max_value_within_capacity;
    }
}

static void
test_default_mutator()
{
    drmf_status_t res;
    char string_buffer[16];
    const drfuzz_mutator_options_t backward_compatibility_options = {
        sizeof(drfuzz_mutator_options_t) + 1,
        0
    };

    res = drfuzz_mutator_start(&mutator_rand, &string_buffer, 16,
                               &DRFUZZ_MUTATOR_DEFAULT_OPTIONS);
    EXPECT(res == DRMF_SUCCESS, "failed to start a mutator with default options");
    res = drfuzz_mutator_set_options(mutator_rand, &backward_compatibility_options);
    EXPECT(res == DRMF_SUCCESS, "failed to set backward-compatible options");
    res = drfuzz_mutator_stop(mutator_rand);
    EXPECT(res == DRMF_SUCCESS, "failed to cleanup mutator");

    res = drfuzz_mutator_start(&mutator_rand, &string_buffer, 16,
                               &backward_compatibility_options);
    EXPECT(res == DRMF_SUCCESS, "failed to start a backward-compatible mutator");
    res = drfuzz_mutator_stop(mutator_rand);
    EXPECT(res == DRMF_SUCCESS, "failed to cleanup mutator");
}

static void
test_scalar_mutation(size_t size, uint64 max)
{
    drmf_status_t res;
    uint64 i, step = 1;
    uint64 buffer_rand = 0, buffer_iter = 0;
    drfuzz_mutator_options_t options = {
        sizeof(drfuzz_mutator_options_t),
        MUTATOR_ALG_RANDOM,
        MUTATOR_UNIT_NUM,
        0,
        0,
        max,
        get_random_value()
    };

    if (max > 1 && size > 2) /* reduce test time for large spans */
        step = (max >> 9ULL) - (1ULL << (((uint64) size - 1ULL) * 3ULL));

    /* interleave the mutator calls to test independent operation */
    res = drfuzz_mutator_start(&mutator_rand, &buffer_rand, size, &options);
    EXPECT(res == DRMF_SUCCESS, "failed to start the mutator");

    options.alg = MUTATOR_ALG_ORDERED;
    res = drfuzz_mutator_start(&mutator_iter, &buffer_iter, size, &options);
    EXPECT(res == DRMF_SUCCESS, "failed to start the mutator");

    for (i = 0; i < max; i += step) {
        EXPECT(drfuzz_mutator_has_next_value(mutator_rand),
                      "mutator should have next value");
        EXPECT(drfuzz_mutator_has_next_value(mutator_iter),
                      "mutator should have next value");
        res = drfuzz_mutator_get_next_value(mutator_rand, &buffer_rand);
        EXPECT(res == DRMF_SUCCESS, "failed to get next fuzz value");
        EXPECT(buffer_rand >= 0 && buffer_rand < max, "mutation out of range");
        if (size < 8)
            EXPECT((buffer_rand >> (size * 8)) == 0, "mutator overwrote buffer");
        res = drfuzz_mutator_get_next_value(mutator_iter, &buffer_iter);
        EXPECT(res == DRMF_SUCCESS, "failed to get next fuzz value");
        EXPECT(buffer_iter >= 0 && buffer_iter < max, "mutation out of range");
        if (size < 8)
            EXPECT((buffer_iter >> (size * 8)) == 0, "mutator overwrote buffer");
        res = drfuzz_mutator_get_current_value(mutator_rand, current_value);
        EXPECT(res == DRMF_SUCCESS, "failed to get current fuzz value");
        EXPECT(is_bitwise_identical(&buffer_rand, current_value, size),
                      "current fuzz value doesn't match");
        res = drfuzz_mutator_get_current_value(mutator_iter, current_value);
        EXPECT(res == DRMF_SUCCESS, "failed to get current fuzz value");
        EXPECT(is_bitwise_identical(&buffer_iter, current_value, size),
                      "current fuzz value doesn't match");
    }
    EXPECT(drfuzz_mutator_has_next_value(mutator_rand),
                  "random mutator should never be exhausted");
    if (step == 1 && max > 0) {
        EXPECT(!drfuzz_mutator_has_next_value(mutator_iter),
                      "mutator should be exhausted");
    }
    res = drfuzz_mutator_stop(mutator_rand);
    EXPECT(res == DRMF_SUCCESS, "failed to cleanup mutator");
    res = drfuzz_mutator_stop(mutator_iter);
    EXPECT(res == DRMF_SUCCESS, "failed to cleanup mutator");
}

static void
test_buffer_mutation(size_t size)
{
    uint i;
    drmf_status_t res;
    char string_buffer[MAX_BUFFER_LENGTH] = {0};
    drfuzz_mutator_options_t options = {
        sizeof(drfuzz_mutator_options_t),
        MUTATOR_ALG_RANDOM,
        MUTATOR_UNIT_NUM,
        0,
        0,
        0,
        get_random_value()
    };

    res = drfuzz_mutator_start(&mutator_rand, &string_buffer, size, &options);
    EXPECT(res == DRMF_SUCCESS, "failed to start the mutator with default options");
    for (i = 0; i < 100000; i++) {
        EXPECT(drfuzz_mutator_has_next_value(mutator_rand),
                      "mutator should have next value");
        res = drfuzz_mutator_get_next_value(mutator_rand, &string_buffer);
        EXPECT(res == DRMF_SUCCESS, "failed to get next fuzz value");
        res = drfuzz_mutator_get_current_value(mutator_iter, current_value);
        EXPECT(res == DRMF_SUCCESS, "failed to get current fuzz value");
        EXPECT(is_bitwise_identical(string_buffer, current_value, size),
                      "current fuzz value doesn't match");
        EXPECT(is_all_zero(string_buffer + size, MAX_BUFFER_LENGTH - size),
                      "mutator overwrote buffer");
    }
    EXPECT(drfuzz_mutator_has_next_value(mutator_rand),
                  "random mutator should never be exhausted");
    res = drfuzz_mutator_stop(mutator_rand);
    EXPECT(res == DRMF_SUCCESS, "failed to cleanup mutator");
}

DR_EXPORT
void dr_client_main(client_id_t id, int argc, const char *argv[])
{
    uint i;

    dr_set_random_seed(dr_get_milliseconds());

    test_default_mutator();

    for (i = 1; i <= 8; i++) {
        test_scalar_mutation(i, choose_max_value(i)); /* avoids edge cases */
        test_scalar_mutation(i, 0);                   /* now test edge cases */
        test_scalar_mutation(i, 1);
    }

    for (i = 0; i < 10; i++)
        test_buffer_mutation(dr_get_random_value(128) + 16); /* some non-scalar size */

    dr_fprintf(STDOUT, "TEST PASSED\n"); /* must use STDOUT for correct ouptut sequence */
}
