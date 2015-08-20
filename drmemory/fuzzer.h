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
fuzzer_init(client_id_t client_id _IF_WINDOWS(bool fuzz_mangled_names));

/* Exit the fuzzer. */
void
fuzzer_exit();

/* Set up fuzzing as specified by the target_descriptor, which has the form:
 *
 *     <target>:<arg-count>:<buffer-index>:<size-index>
 *
 * where <target> is one of
 *
 *     <module>!<symbol>
 *     <module>+<offset>
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
 * Assumes the target uses the C calling convention (i.e., "cdecl").
 */
bool
fuzzer_fuzz_target(const char *target_descriptor);

/* Stop fuzzing the current target. Returns false if no target is being fuzzed, or if an
 * error occurred attempting to uninstrument the fuzz target. Application execution may be
 * incorrect if this function is called while any thread is executing the fuzz target.
 */
bool
fuzzer_unfuzz_target();

#endif /* _FUZZER_H_ */
