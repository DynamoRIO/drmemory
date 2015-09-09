/* **********************************************************
 * Copyright (c) 2015 Google, Inc.  All rights reserved.
 * **********************************************************/

/* Dr. Memory: the memory debugger
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License, and no later version.

 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Library General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _FUZZER_H_
#define _FUZZER_H_ 1

/* Fuzz testing module for Dr. Memory */

#include "drfuzz.h"

/* Used in the descriptor of fuzzer_fuzz_target() to refer to the main module. */
#define FUZZER_MAIN_MODULE_ALIAS "<main>"

/* Initialize the fuzzer. */
void
fuzzer_init(client_id_t client_id, bool shadow_memory_enabled, uint pattern,
            uint redzone_size, bool check_uninitialized
            _IF_WINDOWS(bool fuzz_mangled_names));

/* Exit the fuzzer. */
void
fuzzer_exit();

/* Set up fuzzing as specified by the target_descriptor, which has the form:
 *
 *     <target>|<arg-count>|<buffer-index>|<size-index>|<repeat-count>[|<call-conv>]
 *
 * where <target> is one of
 *
 *     <module>!<symbol>
 *     <module>+<offset>
 *
 * Use <repeat-count> of 0 to repeat the fuzz target until the mutator is exhausted.
 * The optional <call-conv> is the integer value of a DRWRAP_CALLCONV_* constant (see
 * drwrap_callconv_t in the DynamoRIO API documentation). If not specified, the default
 * calling convention for the platform will be used (DRWRAP_CALLCONV_DEFAULT).
 *
 * The fuzzer currently only supports one target at a time. This function may be called
 * multiple times, but on each call the previous target will be removed. Accordingly, this
 * function is not threadsafe and should not be called concurrently. The fuzz target may
 * be explicitly removed by calling fuzzer_unfuzz_target().
 *
 * The fuzzer only supports the first instance of the target module to be loaded. If
 * multiple instances of the module are loaded simultaneously, only the target occurring
 * in the first instance of the module will be fuzzed. It is not necessary for the target
 * module to be loaded at the time this function is called; it will be fuzzed when loaded.
 *
 * Concurrent execution of the target function is supported.
 */
bool
fuzzer_fuzz_target(const char *target_descriptor);

/* Stop fuzzing the current target. Returns false if no target is being fuzzed, or if an
 * error occurred attempting to uninstrument the fuzz target. Application execution may be
 * incorrect if this function is called while any thread is executing the fuzz target.
 */
bool
fuzzer_unfuzz_target();

/* Configure the mutator according to the specified descriptor, which has the form:
 *
 *     <algorithm>|<unit>|<flags>|<sparsity>[|<random_seed>]
 *
 * where <algorithm> is one of the drfuzz_mutator_algorithm_t:
 *     r = MUTATOR_ALG_RANDOM
 *     o = MUTATOR_ALG_ORDERED
 * The <unit> is one of the drfuzz_mutator_unit_t:
 *     b = MUTATOR_UNIT_BITS
 *     n = MUTATOR_UNIT_NUM
 * The <flags> are any combination of:
 *     r = reset the input buffer to the original app value before each mutation
 *         (drfuzz_mutator_flags_t.MUTATOR_FLAG_BITFLIP_SEED_CENTRIC)
 *     t = seed the mutator's random number generator with the current clock time
 *         (drfuzz_mutator_options_t.random_seed)
 * The <sparsity> is an integer specifying the drfuzz_mutator_options_t.sparsity.
 * The optional <random_seed> is an 8-byte hexadecimal integer which assigns the
 * drfuzz_mutator_options_t.random_seed, e.g. "0x123456789abcdef0".
 */
bool
fuzzer_set_mutator_descriptor(const char *mutator_descriptor);

/* Configure the fuzzer to execute only one iteration of the fuzz target using
 * the specified input_value for the fuzz target's input buffer. The input_value
 * should be an ASCII representation of a hexadecimal byte sequence, e.g. "7f392a".
 * This function facilitates confirmation of app errors found during fuzzing.
 */
void
fuzzer_set_singleton_input(const char *input_value);

#endif /* _FUZZER_H_ */
