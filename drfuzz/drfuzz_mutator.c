/* **************************************************************
 * Copyright (c) 2015-2016 Google, Inc.  All rights reserved.
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
#include "drfuzz_internal.h"
#include "drfuzz_mutator.h"
#include "drvector.h"

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

typedef enum _drfuzz_mutator_algorithm_t {
    /* Randomly search the domain of possible permutations. */
    MUTATOR_ALG_RANDOM,
    /* Exhaustively search all possible permutations in an ordered manner. */
    MUTATOR_ALG_ORDERED,
} drfuzz_mutator_algorithm_t;

/* The unit of transformation for applying the mutation algorithm. */
typedef enum _drfuzz_mutator_unit_t {
    MUTATOR_UNIT_BITS, /* Bitwise application of the mutation algorithm. */
    MUTATOR_UNIT_NUM,  /* Numeric application of the mutation algorithm. */
    MUTATOR_UNIT_TOKEN,/* Dictionary token-based mutation. */
} drfuzz_mutator_unit_t;

/* Flags for the mutator. Some flags are specific to a particular algorithm and/or
 * mutation unit. See comments on each flag for details.
 */
typedef enum _drfuzz_mutator_flags_t {
    /* Reset the buffer contents to the input_seed after every bit-flip
     * mutation. Not valid for MUTATOR_UNIT_NUM. On by default.
     */
    MUTATOR_FLAG_SEED_CENTRIC = 0x0001,
    /* Initialize the random seed for MUTATOR_ALG_RANDOM with the current clock time. */
    MUTATOR_FLAG_SEED_WITH_CLOCK      = 0x0002,
} drfuzz_mutator_flags_t;

typedef struct _drfuzz_mutator_options_t {
    drfuzz_mutator_algorithm_t alg;
    drfuzz_mutator_unit_t unit;
    uint flags; /* Flags for the mutator, composed of #drfuzz_mutator_flags_t. */
    /* The degree of sparseness in the random coverage of MUTATOR_ALG_RANDOM with
     * MUTATOR_UNIT_BITS (invalid for other configurations). Sparsity of n will yield on
     * average 1/n total values relative to MUTATOR_ALG_ORDERED in the same configuration.
     * If the sparsity is set to 0, the default value of 1 will be used instead.
     */
    uint sparsity;
    /* For buffers of size 8 bytes or smaller, specifies the maximum mutation value. Use
     * value 0 to disable the maximum value (i.e., limit only by the buffer capacity).
     */
    uint64 max_value;
    /* Set the randomization seed for MUTATOR_ALG_RANDOM. */
    uint64 random_seed;
} drfuzz_mutator_options_t;

/* Default options (ordered, seed-centric bit-flipping).
 * The default random seed is arbitrary, selected to have an equal number of 0 and 1 bits.
 */
static const drfuzz_mutator_options_t default_options = {
    MUTATOR_ALG_ORDERED,               /* alg */
    MUTATOR_UNIT_BITS,                 /* unit */
    MUTATOR_FLAG_SEED_CENTRIC, /* flags */
    1,                                 /* sparsity */
    0,                                 /* max_value */
    0x5a8390e9a31dc65fULL              /* random_seed */
};

typedef struct _bitflip_t bitflip_t; /* bitflip defined under its own banner below */

typedef struct _mutator_t  {
    void *current_value;      /* private copy of the mutation buffer's current value */
    void *input_seed;         /* the input seed for mutation */
    size_t size;              /* number of bytes in the buffer */
    uint64 index;             /* counter for MUTATOR_ALG_ORDERED | MUTATOR_UNIT_NUM */
    drfuzz_mutator_options_t options; /* mutator option values */
    bitflip_t *bitflip;
    /* A vector of token_t* entries used for MUTATOR_UNIT_TOKEN.
     * Access is unsynchronized as this is private to this mutator and it's up to
     * the caller to synchronize access to the mutator.
     */
    drvector_t dictionary;
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

/***************************************************************************
 * Dictionaries
 */

#define DICT_INIT_CAP 256

/* Dictionary-based fuzzing uses tokens that can contain zeroes, so we cannot
 * simply use C strings.  We assume strings are the most common token, however,
 * by allocating for the text-encoded size.
 */
typedef struct _token_t {
    ushort size;
    ushort capacity;
    byte data[0]; /* variable-sized */
} token_t;

static char
token_separator(mutator_t *mutator)
{
    /* XXX: we could parametrize this but we'll wait until we actually see an
     * instance that does not accept a space (perhaps some binary token scheme).
     */
    return ' ';
}

static token_t *
token_alloc(size_t data_alloc_size)
{
    token_t *token = (token_t *)
        global_alloc(offsetof(token_t, data) + data_alloc_size, HEAPSTAT_MISC);
    token->capacity = data_alloc_size;
    token->size = 0;
    return token;
}

static void
token_free(void *entry)
{
    token_t *token = (token_t *) entry;
    global_free(token, offsetof(token_t, data) + token->capacity, HEAPSTAT_MISC);
}

static void
dictionary_init(mutator_t *mutator)
{
    /* To properly free on dictionary parsing errors as well as other option
     * errors, it's simplest to init up front and free at end unconditionally.
     */
    drvector_init(&mutator->dictionary, DICT_INIT_CAP, false/*!sync*/, token_free);
}

static void
dictionary_free(mutator_t *mutator)
{
    drvector_delete(&mutator->dictionary);
}

static bool
drfuzz_parse_dictionary(const char *file, mutator_t *mutator)
{
    const char *line, *next_line, *eof;
    uint64 map_size;
    size_t actual_size;
    bool res = false;
    void *map = NULL;
    file_t f;
    token_t *token = NULL;

    /* We mmap the file for simpler parsing */
    f = dr_open_file(file, DR_FILE_READ);
    if (f != INVALID_FILE) {
        res = dr_file_size(f, &map_size);
        if (res) {
            actual_size = (size_t) map_size;
            ASSERT(actual_size == map_size, "file size too large");
            map = dr_map_file(f, &actual_size, 0, NULL, DR_MEMPROT_READ, 0);
        }
    }
    if (!res || map == NULL || actual_size < map_size) {
        if (map != NULL)
            dr_unmap_file(map, actual_size);
        if (f != INVALID_FILE)
            dr_close_file(f);
        DRFUZZ_ERROR("Error opening dictionary %s"NL, file);
        return false;
    }

    eof = ((char *) map) + map_size;
    res = false;
    for (line = (char *) map; line < eof; line = next_line) {
        const char *c = line, *newline;
        byte *tok;
        next_line = find_next_line(line, eof, &line, &newline, true/*trim ws*/);
        if (line == newline || line[0] == '#')
            continue; /* skip blank or comment */
        DRFUZZ_LOG(4, "dictionary line: \"%.*s\"\n", newline - line, line);
        /* We ignore the names (and AFL levels) */
        while (*c != '"')
            c++;
        c++;
        if (*(newline-1) != '"') {
            DRFUZZ_ERROR("Dictionary entry %.*s is not \"-delimited"NL,
                         newline - line, line);
            goto parse_exit;
        }
        /* We alloc up front with the max size (we expect few escapes) */
        if (!CHECK_TRUNCATE_RANGE_ushort(newline - c)) {
            DRFUZZ_ERROR("Dictionary entry %.*s is too large"NL, newline - line, line);
            goto parse_exit;
        }
        token = token_alloc(newline - c - 1/*"*/);
        /* Parsing the tokens is not a critical path so we go char by char, which
         * we have to do in the presence of escapes in any case.
         */
        for (tok = token->data; c < newline - 1; tok++, c++) {
            if (*c == '\\') {
                if (*(c+1) == 'x') {
                    int val;
                    if (dr_sscanf(c+2, "%2x", &val) != 1) {
                        ASSERT(false, "internal sscanf error?  failed to parse hex");
                        goto parse_exit;
                    }
                    DRFUZZ_LOG(4, "adding hex val 0x%02x\n", val);
                    *tok = (byte) val;
                    c += 3;
                } else if (*(c+1) == '"' || *(c+1) == '\\') {
                    c++;
                    *tok = (byte) *c;
                } else {
                    DRFUZZ_ERROR("Dictionary entry %.*s contains an unsupported escape"NL,
                                 newline - line, line);
                    goto parse_exit;
                }
            } else
                *tok = (byte) *c;
        }
        ASSERT(CHECK_TRUNCATE_RANGE_ushort(tok - token->data), "size < capacity");
        token->size = (ushort) (tok - token->data);
        DRFUZZ_LOG(3, "appending token cap=%d size=%d |%.*s|\n", token->capacity,
                   token->size, token->size,
                   (char *)token->data/*XXX: may be non-ascii!*/);
        drvector_append(&mutator->dictionary, token);
    }
    res = true;
    token = NULL;

 parse_exit:
    dr_unmap_file(map, actual_size);
    dr_close_file(f);
    if (token != NULL)
        token_free(token);
    return res;
}

/***************************************************************************
 * Options
 */

static drmf_status_t
drfuzz_mutator_set_options(drfuzz_mutator_t *mutator_in,
                           int argc, const char *argv[])
{
    mutator_t *mutator = (mutator_t *) mutator_in;
    int i;
    bool user_seed = false, user_sparsity = false, user_units = false, user_dict = false,
        user_alg = false;

    mutator->options = default_options;

    /* XXX: if we get many more options we may want to share the auto-parser
     * and auto-docs generation that DrMem and DR use via optionsx.h files.
     */
    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-alg") == 0) {
            if (i >= argc - 1)
                return DRMF_ERROR_INVALID_PARAMETER;
            ++i;
            if (strcmp(argv[i], "random") == 0)
                mutator->options.alg = MUTATOR_ALG_RANDOM;
            else if (strcmp(argv[i], "ordered") == 0)
                mutator->options.alg = MUTATOR_ALG_ORDERED;
            else
                return DRMF_ERROR_INVALID_PARAMETER;
            user_alg = true;
        } else if (strcmp(argv[i], "-unit") == 0) {
            if (i >= argc - 1)
                return DRMF_ERROR_INVALID_PARAMETER;
            ++i;
            if (strcmp(argv[i], "bits") == 0)
                mutator->options.unit = MUTATOR_UNIT_BITS;
            else if (strcmp(argv[i], "num") == 0)
                mutator->options.unit = MUTATOR_UNIT_NUM;
            else if (strcmp(argv[i], "token") == 0)
                mutator->options.unit = MUTATOR_UNIT_TOKEN;
            else
                return DRMF_ERROR_INVALID_PARAMETER;
            user_units = true;
        } else if (strcmp(argv[i], "-flags") == 0) {
            if (i >= argc - 1)
                return DRMF_ERROR_INVALID_PARAMETER;
            /* we avoid strtoul to avoid needing libc on Linux */
            if (dr_sscanf(argv[++i], "0x%x", &mutator->options.flags) != 1 &&
                dr_sscanf(argv[i], "%d", &mutator->options.flags) != 1)
                return DRMF_ERROR_INVALID_PARAMETER;
        } else if (strcmp(argv[i], "-sparsity") == 0) {
            if (i >= argc - 1)
                return DRMF_ERROR_INVALID_PARAMETER;
            if (dr_sscanf(argv[++i], "%u", &mutator->options.sparsity) != 1)
                return DRMF_ERROR_INVALID_PARAMETER;
            user_sparsity = true;
        } else if (strcmp(argv[i], "-max_value") == 0) {
            if (i >= argc - 1)
                return DRMF_ERROR_INVALID_PARAMETER;
            /* strtoull is not available in ntdll */
            ++i;
            if (dr_sscanf(argv[i], "0x" HEX64_FORMAT_STRING,
                          &mutator->options.max_value) != 1 &&
                dr_sscanf(argv[i], UINT64_FORMAT_STRING,
                          &mutator->options.max_value) != 1)
                return DRMF_ERROR_INVALID_PARAMETER;
        } else if (strcmp(argv[i], "-random_seed") == 0) {
            if (i >= argc - 1)
                return DRMF_ERROR_INVALID_PARAMETER;
            /* strtoull is not available in ntdll */
            ++i;
            if (dr_sscanf(argv[i], "0x" HEX64_FORMAT_STRING,
                          &mutator->options.random_seed) != 1 &&
                dr_sscanf(argv[i], UINT64_FORMAT_STRING,
                          &mutator->options.random_seed) != 1)
                return DRMF_ERROR_INVALID_PARAMETER;
            user_seed = true;
        } else if (strcmp(argv[i], "-dictionary") == 0) {
            if (i >= argc - 1)
                return DRMF_ERROR_INVALID_PARAMETER;
            ++i;
            if (!drfuzz_parse_dictionary(argv[i], mutator))
                return DRMF_ERROR_INVALID_PARAMETER;
            user_dict = true;
        } else
            return DRMF_ERROR_INVALID_PARAMETER;
    }

    if (mutator->options.unit == MUTATOR_UNIT_TOKEN && !user_dict) {
        DRFUZZ_ERROR("-unit token requires -dictionary"NL);
        return DRMF_ERROR_INVALID_PARAMETER;
    }
    if (user_dict) {
        if (user_units && mutator->options.unit != MUTATOR_UNIT_TOKEN)
            return DRMF_ERROR_INVALID_PARAMETER;
        mutator->options.unit = MUTATOR_UNIT_TOKEN;
        if (!user_alg)
            mutator->options.alg = MUTATOR_ALG_RANDOM;
    }

    if (mutator->options.flags != 0 &&
        !TESTANY(MUTATOR_FLAG_SEED_CENTRIC | MUTATOR_FLAG_SEED_WITH_CLOCK,
                 mutator->options.flags))
        return DRMF_ERROR_INVALID_PARAMETER;
    if (TEST(MUTATOR_FLAG_SEED_CENTRIC, mutator->options.flags) &&
        mutator->options.unit == MUTATOR_UNIT_NUM) {
        DRFUZZ_ERROR("Invalid mutator configuration: cannot specify seed-centric"NL);
        DRFUZZ_ERROR("mutation together with the numeric mutation unit."NL);
        return DRMF_ERROR_INVALID_PARAMETER;
    }
    if (TEST(MUTATOR_FLAG_SEED_WITH_CLOCK, mutator->options.flags)) {
        mutator->options.random_seed = dr_get_milliseconds();
        if (user_seed) {
            DRFUZZ_ERROR("Cannot specify both an initial value and a clock seed "
                         "for the same mutator."NL);
            return DRMF_ERROR_INVALID_PARAMETER;
        }
    }

    if (user_sparsity && mutator->options.sparsity > 0 &&
        mutator->options.unit == MUTATOR_UNIT_NUM) {
        DRFUZZ_ERROR("Invalid mutator configuration: cannot specify mutation"NL);
        DRFUZZ_ERROR("sparsity together with the numeric mutation unit."NL);
        return DRMF_ERROR_INVALID_PARAMETER;
    }
    if (mutator->options.max_value > 0 && mutator->size > MAX_NUMERIC_SIZE) {
        DRFUZZ_ERROR("Invalid mutator configuration: cannot specify a max mutator"NL);
        DRFUZZ_ERROR("value together with a mutation buffer size larger than 8 bytes."NL);
        return DRMF_ERROR_INVALID_PARAMETER;
    }

    if (EXCEEDS_CAPACITY(mutator->options.max_value, mutator->size))
        mutator->options.max_value = 0; /* out of range: can allow all values */

    return DRMF_SUCCESS;
}

/***************************************************************************
 * Core operation
 */

LIB_EXPORT drmf_status_t
drfuzz_mutator_start(OUT drfuzz_mutator_t **mutator_out, IN void *input_seed,
                     IN size_t size, IN int argc, IN const char *argv[])
{
    mutator_t *mutator;
    drmf_status_t res;

    if (mutator_out == NULL || input_seed == NULL || size == 0 ||
        (argv == NULL && argc > 0))
        return DRMF_ERROR_INVALID_PARAMETER;

    mutator = global_alloc(sizeof(mutator_t), HEAPSTAT_MISC);
    memset(mutator, 0, sizeof(mutator_t));
    mutator->size = size;
    dictionary_init(mutator);

    res = drfuzz_mutator_set_options((drfuzz_mutator_t *)mutator, argc, argv);
    if (res != DRMF_SUCCESS) {
        dictionary_free(mutator);
        global_free(mutator, sizeof(mutator_t), HEAPSTAT_MISC);
        return res;
    }

    mutator->input_seed = global_alloc(size, HEAPSTAT_MISC);
    memcpy(mutator->input_seed, input_seed, size);
    mutator->current_value = global_alloc(size, HEAPSTAT_MISC);
    memcpy(mutator->current_value, input_seed, size);

    if (mutator->options.unit == MUTATOR_UNIT_BITS)
        mutator->bitflip = bitflip_create(mutator);

    *mutator_out = (drfuzz_mutator_t *) mutator;
    return DRMF_SUCCESS;
}

LIB_EXPORT bool
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
    } else if (mutator->options.unit == MUTATOR_UNIT_BITS) {
        return bitflip_has_next_value(mutator->bitflip);
    } else {
        ASSERT(mutator->options.unit == MUTATOR_UNIT_TOKEN, "unknown mutator unit");
        if (mutator->options.alg == MUTATOR_ALG_RANDOM) {
            return true;
        } else {
            ASSERT(mutator->options.alg == MUTATOR_ALG_ORDERED, "unknown mutator alg");
            return mutator->index < mutator->dictionary.entries;
        }
    }
}

LIB_EXPORT drmf_status_t
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
get_next_ordered_token(mutator_t *mutator, void *buffer)
{
    /* XXX: there are multiple dimensions here: which token to add, where to place
     * it, whether to shift/append or overwrite, and if not overwriting whether to
     * enumerate all orderings of tokens.  For now we only implement the very
     * simplest scheme: we overwrite at position 0, and do an ordered walk through
     * each token.  We could easily randomize the position, try all positions, start
     * laying out tokens side-by-side to try different orderings, etc., but the
     * current focus is on corpus-based fuzzing where we use a random mutation and
     * thus we're not spending much time on this ordered mutator.
     */
    token_t *token = drvector_get_entry(&mutator->dictionary, mutator->index++);
    ASSERT(mutator->index <= mutator->dictionary.entries, "ordered dictionary overflow");
    memcpy(buffer, token->data, MIN(token->size, mutator->size));
    /* We separate this from the existing data with a separator */
    if (mutator->size > token->size)
        *((char *)buffer+token->size) = token_separator(mutator);
    return DRMF_SUCCESS;
}

static drmf_status_t
get_next_ordered_value(mutator_t *mutator, void *buffer)
{
    switch (mutator->options.unit) {
    case MUTATOR_UNIT_BITS:
        return get_next_ordered_bits(mutator, buffer);
    case MUTATOR_UNIT_NUM:
        return get_next_ordered_number(mutator, buffer);
    case MUTATOR_UNIT_TOKEN:
        return get_next_ordered_token(mutator, buffer);
    default:
        return DRMF_ERROR;
    }
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
    uint64 value;

    if (mutator->options.max_value == 0) {
        drmf_status_t res;
        uint i, remainder;
        uint64 mask;

        for (i = 0; (i + 7) < mutator->size; i += 8) { /* step 8 bytes while available */
            value = generate_random_number(mutator);
            res = write_scalar((void *) ((byte *) buffer + i), 8, value);
            if (res != DRMF_SUCCESS)
                return res;
        }
        remainder = mutator->size - i; /* calculate remaining bytes */
        if (remainder > 0) {
            mask = (1ULL << (remainder * 8)) - 1ULL;      /* set up mask */
            value = generate_random_number(mutator) & mask;
            res = write_scalar((void *) ((byte *) buffer + i), remainder, value);
        }
        return res;
    } else {
        if (mutator->size > sizeof(uint64))
            return DRMF_ERROR; /* cannot cap a non-integer value */
        value = generate_random_number(mutator) % mutator->options.max_value;
        return write_scalar(buffer, mutator->size, value);
    }
}

static drmf_status_t
get_next_random_token(mutator_t *mutator, void *buffer)
{
    uint64 rand_which_tok = generate_random_number(mutator);
    uint64 rand_where = generate_random_number(mutator);
    size_t offs;
    token_t *token = drvector_get_entry(&mutator->dictionary,
                                        rand_which_tok % mutator->dictionary.entries);
    /* XXX: there are multiple strategies that could be followed here,
     * such as looking for a separator to avoid splitting an existing token,
     * or shifting existing data to avoid overwriting existing tokens.
     * Shifting is time-consuming and risky for our execution model (we'd
     * have to reallocate the input buffer).
     * We simply insert our own separators around our token.
     */
    offs = token->size >= mutator->size ? 0 :
        (rand_where % (mutator->size - token->size));
    memcpy((byte *)buffer + offs, token->data, MIN(token->size, mutator->size));
    /* We separate this from the existing data with separators */
    if (offs > 0)
        *((char *)buffer + offs - 1) = token_separator(mutator);
    if (offs + token->size < mutator->size)
        *((char *)buffer + offs + token->size) = token_separator(mutator);

    return DRMF_SUCCESS;
}

static drmf_status_t
get_next_random_value(mutator_t *mutator, void *buffer)
{
    switch (mutator->options.unit) {
    case MUTATOR_UNIT_BITS:
        return get_next_random_bits(mutator, buffer);
    case MUTATOR_UNIT_NUM:
        return get_next_random_number(mutator, buffer);
    case MUTATOR_UNIT_TOKEN:
        return get_next_random_token(mutator, buffer);
    default:
        return DRMF_ERROR;
    }
}

LIB_EXPORT drmf_status_t
drfuzz_mutator_get_next_value(drfuzz_mutator_t *mutator_in, IN void *buffer)
{
    mutator_t *mutator = (mutator_t *) mutator_in;
    drmf_status_t res;

    if (TEST(MUTATOR_FLAG_SEED_CENTRIC, mutator->options.flags))
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

LIB_EXPORT drmf_status_t
drfuzz_mutator_stop(drfuzz_mutator_t *mutator_in)
{
    mutator_t *mutator = (mutator_t *) mutator_in;
    if (mutator->bitflip != NULL)
        bitflip_destroy(mutator->bitflip);
    global_free(mutator->input_seed, mutator->size, HEAPSTAT_MISC);
    global_free(mutator->current_value, mutator->size, HEAPSTAT_MISC);
    dictionary_free(mutator);
    global_free(mutator, sizeof(mutator_t), HEAPSTAT_MISC);
    return DRMF_SUCCESS;
}

LIB_EXPORT drmf_status_t
drfuzz_mutator_feedback(drfuzz_mutator_t *mutator_in, int feedback)
{
    mutator_t *mutator = (mutator_t *) mutator_in;
    if (feedback <= 0) {
        /* do nothing for negative or neutral feedback */
        return DRMF_SUCCESS;
    }

    if (mutator->options.unit != MUTATOR_UNIT_BITS) {
        /* do nothing for non-bitflip mutator */
        return DRMF_SUCCESS;
    }

    /* use current input as base for future mutation */
    if (TEST(MUTATOR_FLAG_SEED_CENTRIC, mutator->options.flags))
        memcpy(mutator->input_seed, mutator->current_value, mutator->size);
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

    ASSERT(byte < size, "byte is out of range");
    ASSERT(bit < 8, "bit is out of range");
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
