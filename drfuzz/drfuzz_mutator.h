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

#ifndef _DRFUZZ_MUTATOR_H_
#define _DRFUZZ_MUTATOR_H_ 1

/* Dr. Fuzz Default Mutator: randomly or sequentially mutates a variable-sized buffer. */

/* Framework-shared header */
#include "drmemory_framework.h"
#include "../framework/drmf.h"

/**
 * @file drfuzz_mutator.h
 * @brief Header for Dr. Fuzz Default Mutator: Fuzzy Value Generator for Dr. Fuzz
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup drfuzz Dr. Fuzz Default Mutator: Fuzzy Value Generator for Dr. Fuzz
 */
/*@{*/ /* begin doxygen group */

/**
 * The algorithms for generating a new value.
 */
typedef enum _drfuzz_mutator_algorithm_t {
    /**
     * Randomly search the domain of possible permutations.
     */
    MUTATOR_ALG_RANDOM,
    /**
     * Exhaustively search all possible permutations in an ordered manner.
     */
    MUTATOR_ALG_ORDERED,
} drfuzz_mutator_algorithm_t;

/**
 * The unit of transformation for applying the mutation algorithm.
 */
typedef enum _drfuzz_mutator_unit_t {
    MUTATOR_UNIT_BITS, /**< Bitwise application of the mutation algorithm. */
    MUTATOR_UNIT_NUM,  /**< Numeric application of the mutation algorithm. */
} drfuzz_mutator_unit_t;

/**
 * Flags for the mutator. Some flags are specific to a particular algorithm and/or
 * mutation unit. See comments on each flag for details.
 */
typedef enum _drfuzz_mutator_flags_t {
    /**
     * Reset the buffer contents to the input_seed after every bit-flip
     * mutation. Only valid for MUTATOR_UNIT_BITS. On by default.
     */
    MUTATOR_FLAG_BITFLIP_SEED_CENTRIC = 0x0001,
} drfuzz_mutator_flags_t;

/**
 * Options for the mutator. Most options are specific to a particular algorithm and/or
 * mutation unit. See comments on each option for details.
 */
typedef struct _drfuzz_mutator_options_t {
    /**
     * For compatibility. Set to sizeof(drfuzz_mutator_options_t).
     */
    size_t struct_size;
    /**
     * The algorithm to use for mutating the buffer. Default is MUTATOR_ALG_ORDERED.
     */
    drfuzz_mutator_algorithm_t alg;
    /**
     * The unit of mutation. Default is MUTATOR_UNIT_BITS.
     */
    drfuzz_mutator_unit_t unit;
    /**
     * Flags for the mutator, composed of #drfuzz_mutator_flags_t.
     */
    uint flags;
    /**
     * The degree of sparseness in the random coverage of MUTATOR_ALG_RANDOM with
     * MUTATOR_UNIT_BITS (invalid for other configurations). Sparsity of n will yield on
     * average 1/n total values relative to MUTATOR_ALG_ORDERED in the same configuration.
     * If the sparsity is set to 0, the default value of 1 will be used instead.
     */
    uint sparsity;
    /**
     * For buffers of size 8 bytes or smaller, specifies the maximum mutation value. Use
     * value 0 to disable the maximum value (i.e., limit only by the buffer capacity).
     */
    uint64 max_value;
    /**
     * Set the randomization seed for MUTATOR_ALG_RANDOM.
     */
    uint64 random_seed;
} drfuzz_mutator_options_t;

/**
 * Default options (ordered, seed-centric bit-flipping), provided here for convenience.
 * The default random seed is arbitrary, selected to have an equal number of 0 and 1 bits.
 */
static const drfuzz_mutator_options_t DRFUZZ_MUTATOR_DEFAULT_OPTIONS = {
    sizeof(drfuzz_mutator_options_t),  /* struct_size */
    MUTATOR_ALG_ORDERED,               /* alg */
    MUTATOR_UNIT_BITS,                 /* unit */
    MUTATOR_FLAG_BITFLIP_SEED_CENTRIC, /* flags */
    1,                                 /* sparsity */
    0,                                 /* max_value */
    0x5a8390e9a31dc65fULL              /* random_seed */
};

typedef void * drfuzz_mutator_t;

DR_EXPORT
/**
 * Initiate mutation on a buffer. The default algorithm is MUTATOR_ALG_ORDERED and the
 * default mutation unit is MUTATOR_UNIT_BITS. Returns DRMF_SUCCESS on success.
 *
 * @param[out]  mutator     Return argument for the newly initiated mutator.
 * @param[in]   input_seed  Pointer to the seed instance of the buffer to mutate.
 * @param[in]   size        The number of bytes in the buffer.
 * @param[in]   options     Configuration options for the mutator; to use default
 *                          options, pass &DRFUZZ_MUTATOR_DEFAULT_OPTIONS.
 */
drmf_status_t
drfuzz_mutator_start(OUT drfuzz_mutator_t **mutator, IN void *input_seed, IN size_t size,
                     IN const drfuzz_mutator_options_t *options);

DR_EXPORT
/**
 * Change the mutator options. The algorithm and unit cannot be changed after the first
 * value is generated (start a new mutator instead). Returns DRMF_SUCCESS on success.
 */
drmf_status_t
drfuzz_mutator_set_options(drfuzz_mutator_t *mutator,
                           const drfuzz_mutator_options_t *options);

DR_EXPORT
/**
 * Returns true if the mutator can generate the next value. Only relevant for mutators
 * using MUTATOR_ALG_ORDERED; there is no limit for mutators using MUTATOR_ALG_RANDOM.
 */
bool
drfuzz_mutator_has_next_value(drfuzz_mutator_t *mutator);

DR_EXPORT
/**
 * Provides a copy of the current mutator value. Returns DRMF_SUCCESS on success.
 */
drmf_status_t
drfuzz_mutator_get_current_value(IN drfuzz_mutator_t *mutator, OUT void *buffer);

DR_EXPORT
/**
 * Writes the next fuzz value to the provided buffer. Returns DRMF_SUCCESS on success.
 */
drmf_status_t
drfuzz_mutator_get_next_value(drfuzz_mutator_t *mutator, OUT void *buffer);

DR_EXPORT
/**
 * Clean up resources allocated for the mutator. Returns DRMF_SUCCESS on success.
 */
drmf_status_t
drfuzz_mutator_stop(drfuzz_mutator_t *mutator);

/*@}*/ /* end doxygen group */

#ifdef __cplusplus
}
#endif

#endif /* _DRFUZZ_MUTATOR_H_ */
