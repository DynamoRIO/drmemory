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

/* Default mutation driver for Dr. Fuzz. */

#include "dr_api.h"
#include "utils.h"
#include <string.h>
#include <stddef.h>
#include "drfuzz_mutator.h"

#define MUTATOR_MAX_INDEX 0xffffffffffffffffLL
#define MAX_NUMERIC_SIZE 8

/* These constants were taken from the single-state xorshift algorithm on Wikipedia
 * (https://en.wikipedia.org/wiki/Xorshift). The algorithm is reported to pass all
 * tests in TestU01's BigCrush suite except MatrixRank. If this becomes an issue with
 * mutating large matrix buffers, we can upgrade to the version with 128-byte state.
 */
#define XORSHIFT_A 12
#define XORSHIFT_B 25
#define XORSHIFT_C 27
#define XORSHIFT_MULTIPLIER 0x2545f4914f6cdd1dULL

#define EXCEEDS_CAPACITY(x, size) ((size) == sizeof(uint64) ? \
                                   false : \
                                   (x) > (1ULL << ((uint64) (size) * 8ULL)))

typedef struct _mutator_t  {
    void *current_value;      /* private copy of the mutation buffer's current value */
    void *input_seed;         /* the input seed for mutation */
    size_t size;              /* number of bytes in the buffer */
    uint64 index;             /* value counter for MUTATOR_ALG_ORDERED */
    drfuzz_mutator_options_t options; /* mutator option values */
} mutator_t;

static drmf_status_t
get_next_random_bits(mutator_t *mutator, void *buffer);

static uint64
generate_random_number(mutator_t *mutator);

static drmf_status_t
get_next_random_number(mutator_t *mutator, void *buffer);

static drmf_status_t
get_next_random_value(mutator_t *mutator, void *buffer);

static drmf_status_t
get_next_ordered_bits(mutator_t *mutator, void *buffer);

static drmf_status_t
get_next_ordered_number(mutator_t *mutator, void *buffer);

static drmf_status_t
get_next_ordered_value(mutator_t *mutator, void *buffer);

static drmf_status_t
write_scalar(void *buffer, size_t size, uint64 value);

DR_EXPORT drmf_status_t
drfuzz_mutator_start(OUT drfuzz_mutator_t **mutator_out, IN void *input_seed,
                     IN size_t size, IN const drfuzz_mutator_options_t *options)
{
    mutator_t *mutator;
    drmf_status_t res;

    if (mutator_out == NULL || input_seed == NULL || size == 0 || options == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;

    mutator = global_alloc(sizeof(mutator_t), HEAPSTAT_MISC);
    memset(mutator, 0, sizeof(mutator_t));
    mutator->size = size;

    res = drfuzz_mutator_set_options((drfuzz_mutator_t *)mutator, options);
    if (res != DRMF_SUCCESS) {
        global_free(mutator, sizeof(mutator_t), HEAPSTAT_MISC);
        return res;
    }

    mutator->input_seed = global_alloc(size, HEAPSTAT_MISC);
    memcpy(mutator->input_seed, input_seed, size);
    mutator->current_value = global_alloc(size, HEAPSTAT_MISC);
    memcpy(mutator->current_value, input_seed, size);

    *mutator_out = (drfuzz_mutator_t *) mutator;
    return DRMF_SUCCESS;
}

DR_EXPORT drmf_status_t
drfuzz_mutator_set_options(drfuzz_mutator_t *mutator_in,
                           const drfuzz_mutator_options_t *options)
{
    mutator_t *mutator = (mutator_t *) mutator_in;

    if (options->struct_size < sizeof(drfuzz_mutator_options_t))
        return DRMF_ERROR_INVALID_PARAMETER;

    if (TEST(MUTATOR_FLAG_BITFLIP_SEED_CENTRIC, options->flags) &&
        options->unit != MUTATOR_UNIT_BITS)
        return DRMF_ERROR_INVALID_PARAMETER;
    if (options->sparsity > 0 &&
        (options->alg != MUTATOR_ALG_RANDOM || options->unit != MUTATOR_UNIT_BITS))
        return DRMF_ERROR_INVALID_PARAMETER;
    if (options->max_value > 0 && mutator->size > MAX_NUMERIC_SIZE)
        return DRMF_ERROR_INVALID_PARAMETER;

    if (mutator->index == 0) {
        memcpy(&mutator->options, options, sizeof(drfuzz_mutator_options_t));
    } else { /* copy everything from the flags down (can't change alg or unit anymore) */
        size_t flags_offset = offsetof(drfuzz_mutator_options_t, flags);
        memcpy(&mutator->options + flags_offset, options + flags_offset,
               sizeof(drfuzz_mutator_options_t) - flags_offset);
    }

    if (EXCEEDS_CAPACITY(mutator->options.max_value, mutator->size))
        mutator->options.max_value = 0; /* out of range: can allow all values */

    return DRMF_SUCCESS;
}

DR_EXPORT bool
drfuzz_mutator_has_next_value(drfuzz_mutator_t *mutator_in)
{
    mutator_t *mutator = (mutator_t *) mutator_in;
    if (mutator->options.alg == MUTATOR_ALG_RANDOM &&
        mutator->options.unit == MUTATOR_UNIT_NUM) {
        return true;
    } else {
        if (mutator->options.max_value == 0)
            return mutator->index < MUTATOR_MAX_INDEX;
        else
            return mutator->index < mutator->options.max_value;
    }
}

DR_EXPORT drmf_status_t
drfuzz_mutator_get_current_value(IN drfuzz_mutator_t *mutator_in, OUT void *buffer)
{
    mutator_t *mutator = (mutator_t *) mutator_in;
    memcpy(buffer, mutator->current_value, mutator->size);
    return DRMF_SUCCESS;
}

DR_EXPORT drmf_status_t
drfuzz_mutator_get_next_value(drfuzz_mutator_t *mutator_in, IN void *buffer)
{
    mutator_t *mutator = (mutator_t *) mutator_in;
    drmf_status_t res;

    switch (mutator->options.alg) {
    case MUTATOR_ALG_RANDOM:
        res = get_next_random_value(mutator, buffer);
        break;
    case MUTATOR_ALG_ORDERED:
        res = get_next_ordered_value(mutator, buffer);
        break;
    default:
        return DRMF_ERROR;
    }

    if (res == DRMF_SUCCESS)
        memcpy(mutator->current_value, buffer, mutator->size);

    return res;
}

DR_EXPORT drmf_status_t
drfuzz_mutator_stop(drfuzz_mutator_t *mutator_in)
{
    mutator_t *mutator = (mutator_t *) mutator_in;
    global_free(mutator->input_seed, mutator->size, HEAPSTAT_MISC);
    global_free(mutator->current_value, mutator->size, HEAPSTAT_MISC);
    global_free(mutator, sizeof(mutator_t), HEAPSTAT_MISC);
    return DRMF_SUCCESS;
}

static drmf_status_t
get_next_random_bits(mutator_t *mutator, void *buffer)
{
    /* XXX i#1734: NYI */
    return DRMF_ERROR_NOT_IMPLEMENTED;
}

/* xorshift algorithm via https://en.wikipedia.org/wiki/Xorshift */
static uint64
generate_random_number(mutator_t *mutator)
{
    mutator->options.random_seed ^= (mutator->options.random_seed >> XORSHIFT_A);
    mutator->options.random_seed ^= (mutator->options.random_seed >> XORSHIFT_B);
    mutator->options.random_seed ^= (mutator->options.random_seed >> XORSHIFT_C);
    return (mutator->options.random_seed * XORSHIFT_MULTIPLIER);
}

static drmf_status_t
get_next_random_number(mutator_t *mutator, void *buffer)
{
    uint value;

    if (mutator->options.max_value == 0) {
        drmf_status_t res;
        uint i, remainder;
        uint64 mask;

        for (i = 0; (i + 7) < mutator->size; i += 8) { /* step 8 bytes while available */
            value = generate_random_number(mutator);
            res = write_scalar((void *) ((ptr_uint_t) buffer + i), 8, value);
            if (res != DRMF_SUCCESS)
                return res;
        }
        remainder = mutator->size - i;          /* calculate remaining bytes */
        mask = (2 << (remainder * 8)) - 1;      /* set up mask */
        value = generate_random_number(mutator) & mask;
        return write_scalar((void *) ((ptr_uint_t) buffer + i), remainder, value);
    } else {
        if (mutator->size > sizeof(uint64))
            return DRMF_ERROR; /* cannot cap a non-integer value */
        value = generate_random_number(mutator) % mutator->options.max_value;
        return write_scalar(buffer, mutator->size, value);
    }
}

static drmf_status_t
get_next_random_value(mutator_t *mutator, void *buffer)
{
    switch (mutator->options.unit) {
    case MUTATOR_UNIT_BITS:
        return get_next_random_bits(mutator, buffer);
    case MUTATOR_UNIT_NUM:
        return get_next_random_number(mutator, buffer);
    }
    return DRMF_ERROR;
}

static drmf_status_t
get_next_ordered_bits(mutator_t *mutator, void *buffer)
{
    return DRMF_ERROR_NOT_IMPLEMENTED;
}

static drmf_status_t
get_next_ordered_number(mutator_t *mutator, void *buffer)
{
    return write_scalar(buffer, mutator->size, mutator->index++);
}

static drmf_status_t
get_next_ordered_value(mutator_t *mutator, void *buffer)
{
    switch (mutator->options.unit) {
    case MUTATOR_UNIT_BITS:
        return get_next_ordered_bits(mutator, buffer);
    case MUTATOR_UNIT_NUM:
        return get_next_ordered_number(mutator, buffer);
    }
    return DRMF_ERROR;
}

static drmf_status_t
write_scalar(void *buffer, size_t size, uint64 value)
{
    ASSERT(size <= sizeof(uint64), "size must be <= sizeof(uint64)");
    switch (size) {
    case 1:
        *(byte *) buffer = (byte) value;
        break;
    case 2:
        *(ushort *) buffer = (ushort) value;
        break;
    case 4:
        *(uint *) buffer = (uint) value;
        break;
    case 8:
        *(uint64 *) buffer = value;
        break;
    default: {
        /* XXX: for big-endian, adjust with: src_start += (sizeof(uint64) - size); */
        memcpy(buffer, &value, size);
    }
    }
    return DRMF_SUCCESS;
}
