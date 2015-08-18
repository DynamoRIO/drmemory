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

typedef struct _bitflip_t bitflip_t; /* bitflip defined under its own banner below */

typedef struct _mutator_t  {
    void *current_value;      /* private copy of the mutation buffer's current value */
    void *input_seed;         /* the input seed for mutation */
    size_t size;              /* number of bytes in the buffer */
    uint64 index;             /* counter for MUTATOR_ALG_ORDERED | MUTATOR_UNIT_NUM */
    drfuzz_mutator_options_t options; /* mutator option values */
    bitflip_t *bitflip;
} mutator_t;

static bitflip_t *
bitflip_create(mutator_t *mutator);

static void
bitflip_destroy(bitflip_t *f);

static inline bool
bitflip_has_next_value(bitflip_t *f);

static void
bitflip_increment(mutator_t *mutator);

static void
bitflip_shuffle_and_flip(mutator_t *mutator, void *buffer);

static inline void
bitflip_distribute_index_and_flip(mutator_t *mutator, void *buffer);

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

    if (options->unit == MUTATOR_UNIT_BITS)
        mutator->bitflip = bitflip_create(mutator);

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
    if (options->sparsity > 0 && options->unit == MUTATOR_UNIT_NUM)
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
    if (mutator->options.unit == MUTATOR_UNIT_NUM) {
        if (mutator->options.alg == MUTATOR_ALG_RANDOM) {
            return true;
        } else {
            ASSERT(mutator->options.alg == MUTATOR_ALG_ORDERED, "unknown mutator alg");
            if (mutator->options.max_value == 0)
                return mutator->index < MUTATOR_MAX_INDEX;
            else
                return mutator->index < mutator->options.max_value;
        }
    } else {
        ASSERT(mutator->options.unit == MUTATOR_UNIT_BITS, "unknown mutator unit");
        return bitflip_has_next_value(mutator->bitflip);
    }
}

DR_EXPORT drmf_status_t
drfuzz_mutator_get_current_value(IN drfuzz_mutator_t *mutator_in, OUT void *buffer)
{
    mutator_t *mutator = (mutator_t *) mutator_in;
    memcpy(buffer, mutator->current_value, mutator->size);
    return DRMF_SUCCESS;
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

static drmf_status_t
get_next_ordered_bits(mutator_t *mutator, void *buffer)
{
    bitflip_distribute_index_and_flip(mutator, buffer);
    bitflip_increment(mutator);
    return DRMF_SUCCESS;
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

/* Randomly pick n bits to flip, where n is `mutator->bitflip->bits_to_flip`, as
 * maintained using the normal ordered sequence; i.e., wherever get_next_ordered_bits()
 * would have flipped n bits, this function randomly flips that same number of bits.
 */
static drmf_status_t
get_next_random_bits(mutator_t *mutator, void *buffer)
{
    bitflip_shuffle_and_flip(mutator, buffer);
    bitflip_increment(mutator); /* use the ordered flip mechanism as a counter */
    return DRMF_SUCCESS;
}

/* xorshift algorithm via https://en.wikipedia.org/wiki/Xorshift */
static uint64
generate_random_number(mutator_t *mutator)
{
    mutator->options.random_seed ^= (mutator->options.random_seed >> XORSHIFT_A);
    mutator->options.random_seed ^= (mutator->options.random_seed << XORSHIFT_B);
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

DR_EXPORT drmf_status_t
drfuzz_mutator_get_next_value(drfuzz_mutator_t *mutator_in, IN void *buffer)
{
    mutator_t *mutator = (mutator_t *) mutator_in;
    drmf_status_t res;

    if (TEST(MUTATOR_FLAG_BITFLIP_SEED_CENTRIC, mutator->options.flags))
        memcpy(buffer, mutator->input_seed, mutator->size);

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
    if (mutator->bitflip != NULL)
        bitflip_destroy(mutator->bitflip);
    global_free(mutator->input_seed, mutator->size, HEAPSTAT_MISC);
    global_free(mutator->current_value, mutator->size, HEAPSTAT_MISC);
    global_free(mutator, sizeof(mutator_t), HEAPSTAT_MISC);
    return DRMF_SUCCESS;
}

/***************************************************************************************
 * BIT FLIP ALGORITHM
 */

/* Combinatoric bit flipper that explores all permutations of bit flips in a buffer of
 * size `bit_count` by ordered iteration. The flipper always starts by flipping just
 * one bit at a time, and increases the `bits_to_flip` as permutations are exhausted.
 * The bit flipper can also randomly choose which bits to flip. In this configuration,
 * it uses the ordered iteration as a counter to determine how many bits to flip at
 * each iteration ; i.e., if an ordered instance flips 4 bits at iteration 47, then a
 * random instance will also flip 4 bits at iteration 47, but those 4 bits will be
 * selected randomly instead of by index position.
 */

#define SIZEOF_SHUFFLE(f) (f->bit_count * sizeof(short))

struct _bitflip_t {
    uint bit_count;    /* total bits in the target buffer (derived from mutator->size) */
    uint bits_to_flip; /* number of bits to flip during the current phase */
    uint *index;       /* array of bit positions to flip next */
    uint *last_index;  /* cached reference to the most frequently accessed bit index */
    short *shuffle;    /* workspace for Fisher-Yates shuffle, used for random flip */
};

/* Start a new traversal of the loops iterated by `loop_index` and all indexes that
 * are "more inner" than it. For each index from `loop_index` to the innermost index,
 * set its position to the leftmost position allowed by the next "more outer" index.
 */
static void
bitflip_start_inner_loops(bitflip_t *f, uint loop_index)
{
    uint i;

    for (i = loop_index; i < f->bits_to_flip; i++)
        f->index[i] = f->index[i-1] + 1;
}

/* Start a new traversal of all permutations of n bit flips, where n is `bits_to_flip`.
 */
static void
bitflip_init_bits_to_flip(bitflip_t *f, uint bits_to_flip)
{
    if (f->index != NULL)
        global_free(f->index, sizeof(uint) * f->bits_to_flip, HEAPSTAT_MISC);

    f->bits_to_flip = bits_to_flip;
    f->index = global_alloc(sizeof(uint) * bits_to_flip, HEAPSTAT_MISC);
    f->last_index = &f->index[bits_to_flip-1];
    f->index[0] = 0;
    bitflip_start_inner_loops(f, 1);
}

/* Create a new bit flipper and start it at the first permutation (flip bit 0). */
static bitflip_t *
bitflip_create(mutator_t *mutator)
{
    bitflip_t *f = global_alloc(sizeof(bitflip_t), HEAPSTAT_MISC);
    memset(f, 0, sizeof(bitflip_t));
    f->bit_count = 8 * mutator->size * sizeof(byte);
    bitflip_init_bits_to_flip(f, 1);
    if (mutator->options.alg == MUTATOR_ALG_RANDOM)
        f->shuffle = global_alloc(SIZEOF_SHUFFLE(f), HEAPSTAT_MISC);
    return f;
}

/* Free a bit flipper and all temporary workspaces it may have allocated. */
static void
bitflip_destroy(bitflip_t *f)
{
    if (f->index != NULL)
        global_free(f->index, sizeof(uint) * f->bits_to_flip, HEAPSTAT_MISC);
    if (f->shuffle != NULL)
        global_free(f->shuffle, SIZEOF_SHUFFLE(f), HEAPSTAT_MISC);
    global_free(f, sizeof(bitflip_t), HEAPSTAT_MISC);
}

static inline void
flip_bit(byte *b, uint i)
{
    b[i>>3] ^= (1 << (i & 7));
}

/* Randomly flip n bits in `buffer`, where n is the `bits_to_flip` of the ordered walk. */
static void
bitflip_shuffle_and_flip(mutator_t *mutator, void *buffer)
{
    bitflip_t *f = mutator->bitflip;
    uint i, pick, pick_count, total_picks = (f->bit_count - f->bits_to_flip);

    /* N.B.: To facilitate quick reset of the `f->shuffle` workspace, the value of each
     *       element in `f->shuffle` is relative to its index. For example:
     *           - If the array contains relative values      [0, 0, 0, 0],
     *             then the corresponding absolute values are [1, 2, 3, 4].
     *           - If the array contains relative values      [2,-1, 3,-2],
     *             then the corresponding absolute values are [2, 0, 5, 1].
     */
    #define SHUFFLE_ABSOLUTE_VALUE(k) ((k) + f->shuffle[k])
    #define SHUFFLE_RELATIVE_VALUE(k, v) ((short) ((v) - k))

    memset(f->shuffle, 0, SIZEOF_SHUFFLE(f));
    for (i = 0, pick_count = f->bit_count; pick_count > total_picks; i++, pick_count--) {
        pick = i + (generate_random_number(mutator) % pick_count);
        flip_bit(buffer, SHUFFLE_ABSOLUTE_VALUE(pick));
        f->shuffle[pick] = SHUFFLE_RELATIVE_VALUE(pick, SHUFFLE_ABSOLUTE_VALUE(i));
    }
    ASSERT(i == f->bits_to_flip, "shuffled wrong number of bits");
}

static inline bool
bitflip_has_next_value(bitflip_t *f)
{
    return f->index != NULL;
}

/* Increment the internal combinatoric index of the bit flipper, which is comprised of
 * one bit position per `bits_to_flip`. The index positions represent the set of bits to
 * flip during an ordered traversal of the combinatoric space (the flips are applied by
 * bitflip_distribute_index_and_flip(), which improves early-phase distribution). To
 * increment the flipper means to advance one or more index positions and thereby arrive
 * at a combinatorically unique state; i.e., a set of flips that has not yet been applied
 * to the buffer. For a sparsity greater than 1, each increment will skip over that many
 * states, allowing a greater diversity of states to be reached sooner.
 */
static void
bitflip_increment(mutator_t *mutator)
{
    bitflip_t *f = mutator->bitflip;
    uint skip = (mutator->options.sparsity == 0 ? 1 : mutator->options.sparsity);

    if (f->index[0] == (f->bit_count - f->bits_to_flip)) {
        if (f->bits_to_flip < f->bit_count) {
            bitflip_init_bits_to_flip(f, f->bits_to_flip + 1);
        } else {
            global_free(f->index, sizeof(uint) * f->bits_to_flip, HEAPSTAT_MISC);
            f->index = NULL; /* denotes end of the bitflip range */
        }
        return;
    }

    while (true) { /* repeat this block once per inner loop */
        if ((*f->last_index + skip) < f->bit_count) {
            *f->last_index += skip; /* advance innermost index only, if possible */
            return;
        } else { /* end f's inner loop, start a new inner loop, and repeat this block */
            int i, next_innermost = f->bits_to_flip - 2;

            skip -= (f->bit_count - *f->last_index); /* skip remaining inner loop bits */
            *f->last_index = (f->bit_count - 1);

            for (i = next_innermost; i >= 0; i--) { /* find innermost moveable index */
                uint upper_bound_of_i = (f->bit_count - (f->bits_to_flip - i));
                if (f->index[i] < upper_bound_of_i) {
                    f->index[i]++;
                    bitflip_start_inner_loops(f, i+1);
                    break;
                }
            }
        }
    }
}

/* Distribute the sequential bit flips across the buffer to improve the diversity of the
 * permutations during the early iterations. This function simply maps each sequential
 * bit index onto each subsequent byte. For example, with a target buffer of size 4 bytes:
 *       sequential bit indexes:    [  0,   1,    2,     3,  4,   5,    6,...]
 *       bit flipped in the target: [0x1,0x10,0x100,0x1000,0x2,0x20,0x200,...]
 */
static inline void
distributed_flip_bit(byte *b, uint i, size_t size)
{
    uint byte = i % size;
    uint bit = i / size;
    b[byte] ^= (1 << bit);

    ASSERT(byte >= size, "Error! Byte is out of range\n");
    ASSERT(bit >= 8, "Error! Bit is out of range\n");
}

/* Applies the current value of each bit index in the flipper to the target `buffer`. */
static inline void
bitflip_distribute_index_and_flip(mutator_t *mutator, void *buffer)
{
    uint i;
    bitflip_t *f = mutator->bitflip;

    for (i = 0; i < f->bits_to_flip; i++)
        distributed_flip_bit(buffer, f->index[i], mutator->size);
}
