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

/* Test of the Dr. Fuzz Default Mutator */

#include "dr_api.h"
#include <string.h>
#include "utils.h"
#include "drfuzz_mutator.h"
#include "drfuzz.h"

#undef EXPECT /* we don't want msgbox */
#define EXPECT(cond, msg) \
    ((void)((!(cond)) ? \
     (dr_fprintf(STDERR, "EXPECT FAILURE: %s:%d: %s (%s)", \
                 __FILE__,  __LINE__, #cond, msg), \
      dr_abort(), 0) : 0))

#define MAX_BUFFER_LENGTH 256

/* enabling verbose output of each flipped buffer requires rebuild  (~200k lines) */
#define VERBOSE 0

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
    res = drfuzz_mutator_start(&mutator_rand, &string_buffer, 16, 0, NULL);
    EXPECT(res == DRMF_SUCCESS, "failed to start a mutator with default options");
    res = drfuzz_mutator_stop(mutator_rand);
    EXPECT(res == DRMF_SUCCESS, "failed to cleanup mutator");
}

static void
test_random_scalar(size_t size, uint64 max)
{
    drmf_status_t res;
    uint64 i, step = 1;
    uint64 buffer_rand = 0, buffer_iter = 0;
    char arg_max[16];
    char arg_seed[16];
    const char *argv_ran[] = {
        "-alg", "random", "-unit", "num", "-flags", "0",
        "-max_value", arg_max, "-random_seed", arg_seed
    };
    int argc_ran = sizeof(argv_ran)/sizeof(argv_ran[0]);
    const char *argv_iter[] = {
        "-alg", "ordered", "-unit", "num", "-flags", "0",
        "-max_value", arg_max, "-random_seed", arg_seed
    };
    int argc_iter = sizeof(argv_ran)/sizeof(argv_ran[0]);
    dr_snprintf(arg_max, BUFFER_SIZE_ELEMENTS(arg_max), UINT64_FORMAT_STRING, max);
    NULL_TERMINATE_BUFFER(arg_max);
    dr_snprintf(arg_seed, BUFFER_SIZE_ELEMENTS(arg_seed), UINT64_FORMAT_STRING,
                get_random_value());
    NULL_TERMINATE_BUFFER(arg_seed);

    if (max > 1 && size > 2) /* reduce test time for large spans */
        step = (max >> 9ULL) - (1ULL << (((uint64) size - 1ULL) * 3ULL));

    /* interleave the mutator calls to test independent operation */
    res = drfuzz_mutator_start(&mutator_rand, &buffer_rand, size, argc_ran, argv_ran);
    EXPECT(res == DRMF_SUCCESS, "failed to start the mutator");

    res = drfuzz_mutator_start(&mutator_iter, &buffer_iter, size, argc_iter, argv_iter);
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
test_random_buffer(size_t size)
{
    uint i;
    drmf_status_t res;
    char string_buffer[MAX_BUFFER_LENGTH] = {0};
    char arg_seed[16];
    const char *argv[] = {
        "-alg", "random", "-unit", "num", "-flags", "0",
        "-random_seed", arg_seed
    };
    int argc = sizeof(argv)/sizeof(argv[0]);
    dr_snprintf(arg_seed, BUFFER_SIZE_ELEMENTS(arg_seed), UINT64_FORMAT_STRING,
                get_random_value());
    NULL_TERMINATE_BUFFER(arg_seed);

    res = drfuzz_mutator_start(&mutator_rand, &string_buffer, size, argc, argv);
    EXPECT(res == DRMF_SUCCESS, "failed to start the mutator with custom options");
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

static uint64
compute_permutations(uint bits, uint flips)
{
    uint i, max_multiplier, max_divisor;
    uint64 p;

    if (flips == 0)
        return 0;

    if (flips < (bits / 2)) {
        max_multiplier = (bits - flips);
        max_divisor = flips;
    } else {
        max_multiplier = flips;
        max_divisor = (bits - flips);
    }

    for (i = bits - 1, p = bits; i > max_multiplier; i--)
        p *= i;
    for (i = 2; i <= max_divisor; i++)
        p /= i;
    return p;
}

#if VERBOSE > 0
static void
print_byte_buffer(byte *buffer, size_t size)
{
    uint i, j;
    byte b;
    char c[9] = {0};

    dr_fprintf(STDERR, "   ");
    for (i = 0; i < size; i++) {
        b = buffer[i];
        for (j = 0; j < 8; j++) {
            c[j] = ((b & 1) == 0) ? '0' : '1';
            b >>= 1;
        }
        dr_fprintf(STDERR, " %s", c);
    }
    dr_fprintf(STDERR, "\n");
}
#endif

static uint
count_flips(byte *buffer, size_t size)
{
    uint i, j, flips = 0;
    byte b;

    for (i = 0; i < size; i++) {
        b = buffer[i];
        for (j = 0; j < 8; j++) {
            flips += (b & 1);
            b >>= 1;
        }
    }
    return flips;
}

static void
test_bitflip_buffer(size_t size, const char *arg_sparsity, const char *arg_alg,
                    const char *arg_flags)
{
    uint i = 0, flips, expected_flips = 1, expected_iterations, got;
    drmf_status_t res;
    byte byte_buffer[MAX_BUFFER_LENGTH] = {0}, last_buffer[MAX_BUFFER_LENGTH] = {0};
    bool seed_centric = strcmp(arg_flags, "1") == 0;
    uint sparsity;
    char arg_seed[16];
    const char *argv[] = {
        "-alg", arg_alg, "-sparsity", arg_sparsity,
        "-random_seed", arg_seed, "-flags", arg_flags
    };
    int argc = sizeof(argv)/sizeof(argv[0]);
    dr_snprintf(arg_seed, BUFFER_SIZE_ELEMENTS(arg_seed), UINT64_FORMAT_STRING,
                get_random_value());
    NULL_TERMINATE_BUFFER(arg_seed);
    got = dr_sscanf(arg_sparsity, "%d", &sparsity);
    EXPECT(got == 1, "sscanf failed");

    dr_fprintf(STDERR, "\nFlipping %d bits (sparsity %s, %s, %s)\n\n", (size * 8),
               arg_sparsity, seed_centric ? "seed-centric" : "progressive", arg_alg);

    res = drfuzz_mutator_start(&mutator_iter, &byte_buffer, size, argc, argv);
    EXPECT(res == DRMF_SUCCESS, "failed to start the mutator with default options");
    while (drfuzz_mutator_has_next_value(mutator_iter)) {
        res = drfuzz_mutator_get_next_value(mutator_iter, &byte_buffer);
        EXPECT(res == DRMF_SUCCESS, "failed to get next fuzz value");
        res = drfuzz_mutator_get_current_value(mutator_iter, current_value);
        EXPECT(res == DRMF_SUCCESS, "failed to get current fuzz value");

#if VERBOSE > 0
        print_byte_buffer(byte_buffer, size);
#endif
        if (seed_centric) {
            flips = count_flips(byte_buffer, size);
        } else { /* progressive flip, so check last_buffer to see how many were flipped */
            uint j;

            for (j = 0; j < size; j++)
                last_buffer[j] ^= byte_buffer[j];
            flips = count_flips(last_buffer, size);
            memcpy(last_buffer, byte_buffer, sizeof(*last_buffer));
        }

        if (flips != expected_flips) {
            expected_iterations = compute_permutations(size*8, expected_flips);
            if (sparsity > 1)
                expected_iterations = (expected_iterations/sparsity) + 2/*start and end*/;
            EXPECT(i == expected_iterations, "incorrect iteration count");
            EXPECT(flips == (expected_flips + 1), "flip count advanced by more than one");

            i = 1;
            expected_flips = flips;
        } else {
            i++;
        }
    }
    EXPECT(!drfuzz_mutator_has_next_value(mutator_iter),
           "ordered bitflip mutator should be exhausted now");
    res = drfuzz_mutator_stop(mutator_iter);
    EXPECT(res == DRMF_SUCCESS, "failed to cleanup mutator");
}

static void
test_dictionary(const char * const dict[], size_t entries, const char *arg_alg,
                const char *arg_flags, bool dict_legal)
{
#   define DICT_FNAME "dictionary.txt"
#   define RAND_ITERS 500
    uint i;
    drmf_status_t res;
    file_t f;
    byte byte_buffer[MAX_BUFFER_LENGTH];
    char arg_seed[16];
    const char *argv[] = {
        "-alg", arg_alg, "-dictionary", DICT_FNAME, "-random_seed", arg_seed,
        "-flags", arg_flags
    };
    int argc = sizeof(argv)/sizeof(argv[0]);
    dr_snprintf(arg_seed, BUFFER_SIZE_ELEMENTS(arg_seed), UINT64_FORMAT_STRING,
                get_random_value());
    NULL_TERMINATE_BUFFER(arg_seed);

    dr_fprintf(STDERR, "\nTesting dictionary |%s,...| %s\n\n", dict[0], arg_alg);

    f = dr_open_file(DICT_FNAME, DR_FILE_WRITE_OVERWRITE);
    EXPECT(f != INVALID_FILE, "failed to open dictionary file");
    for (i = 0; i < entries; i++)
        dr_fprintf(f, "\"%s\"\n", dict[i]);
    dr_close_file(f);

    /* Fill with non-zero for easier verbose printing */
    memset(byte_buffer, 'x', BUFFER_SIZE_BYTES(byte_buffer));

    res = drfuzz_mutator_start(&mutator_iter, &byte_buffer, MAX_BUFFER_LENGTH, argc, argv);
    if (dict_legal)
        EXPECT(res == DRMF_SUCCESS, "failed to start the mutator with default options");
    else {
        EXPECT(res != DRMF_SUCCESS, "dictionary should have failed");
        return;
    }
    i = 0;
    while (drfuzz_mutator_has_next_value(mutator_iter)) {
        res = drfuzz_mutator_get_next_value(mutator_iter, &byte_buffer);
        EXPECT(res == DRMF_SUCCESS, "failed to get next fuzz value");
        res = drfuzz_mutator_get_current_value(mutator_iter, current_value);
        EXPECT(res == DRMF_SUCCESS, "failed to get current fuzz value");
#if VERBOSE > 0
        dr_fprintf(STDERR, "iter %d => |%s|\n", i, (char *)byte_buffer);
#endif
        if (strcmp(arg_alg, "ordered") == 0) {
            EXPECT(strncmp((char *)byte_buffer, dict[i], strlen(dict[i])) == 0 ||
                   strstr(dict[i], "\\") != NULL /* can't cmp these */,
                   "failed to match token");
        }
        i++;
        if (strcmp(arg_alg, "random") == 0 && i > RAND_ITERS)
            break;
    }
    if (strcmp(arg_alg, "ordered") == 0) {
        EXPECT(!drfuzz_mutator_has_next_value(mutator_iter),
               "ordered bitflip mutator should be exhausted now");
    }
    res = drfuzz_mutator_stop(mutator_iter);
    EXPECT(res == DRMF_SUCCESS, "failed to cleanup mutator");
}

DR_EXPORT
void dr_client_main(client_id_t id, int argc, const char *argv[])
{
    uint i;

    dr_set_random_seed(dr_get_milliseconds());

    /* test default mutator configuration */
    test_default_mutator();

    /* test ordered, seed-centric flip */
    test_bitflip_buffer(1, "1", "ordered", "1"/*MUTATOR_FLAG_SEED_CENTRIC*/);
    test_bitflip_buffer(2, "1", "ordered", "1"/*MUTATOR_FLAG_SEED_CENTRIC*/);
    test_bitflip_buffer(3, "1000", "ordered", "1"/*MUTATOR_FLAG_SEED_CENTRIC*/);

    /* test random, seed-centric flip */
    test_bitflip_buffer(1, "1", "random", "1"/*MUTATOR_FLAG_SEED_CENTRIC*/);
    test_bitflip_buffer(2, "1", "random", "1"/*MUTATOR_FLAG_SEED_CENTRIC*/);
    test_bitflip_buffer(3, "1000", "random", "1"/*MUTATOR_FLAG_SEED_CENTRIC*/);

    /* test progressive flip */
    test_bitflip_buffer(1, "1", "ordered", "0");
    test_bitflip_buffer(1, "1", "random", "0");

    for (i = 1; i <= 8; i++) {
        test_random_scalar(i, choose_max_value(i)); /* avoids edge cases */
        test_random_scalar(i, 0);                   /* now test edge cases */
        test_random_scalar(i, 1);
    }

    for (i = 0; i < 10; i++)
        test_random_buffer(dr_get_random_value(128) + 16); /* some non-scalar size */

    /* test dictionaries */
    {
        const char * const dict1[] = {"tok1","tok2","1\\xab\\xcd","has\"quote\\slash"};
        const char * const dict2[] = {"tok1","tok2","1\\x66\\x49e","has\"quote\\\\slash"};
        test_dictionary(dict1, sizeof(dict1)/sizeof(dict1[0]), "ordered",
                        "1"/*MUTATOR_FLAG_SEED_CENTRIC*/, false);
        test_dictionary(dict2, sizeof(dict2)/sizeof(dict2[0]), "ordered",
                        "1"/*MUTATOR_FLAG_SEED_CENTRIC*/, true);
        test_dictionary(dict2, sizeof(dict2)/sizeof(dict2[0]), "random",
                        "1"/*MUTATOR_FLAG_SEED_CENTRIC*/, true);
        test_dictionary(dict2, sizeof(dict2)/sizeof(dict2[0]), "random", "0", true);
    }

    dr_fprintf(STDOUT, "TEST PASSED\n"); /* must use STDOUT for correct ouptut sequence */
}
