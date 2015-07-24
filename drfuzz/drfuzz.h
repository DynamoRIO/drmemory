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

#ifndef _DR_FUZZ_H_
#define _DR_FUZZ_H_ 1

/* Dr. Fuzz: DynamoRIO Fuzz Testing Extension */

/* Framework-shared header */
#include "drmemory_framework.h"
#include "../framework/drmf.h"

/**
 * @file drfuzz.h
 * @brief Header for Dr. Fuzz: DynamoRIO Fuzz Testing Extension
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup drfuzz Dr. Fuzz: DynamoRIO Fuzz Testing Extension
 */
/*@{*/ /* begin doxygen group */

/**
 * Values for the flags parameter to drfuzz_fuzz_target(). */
typedef enum _drfuzz_flags_t {
    /** The target function uses the IA-32 cdecl calling convention. */
    DRFUZZ_CALLCONV_CDECL = 0x01,
    /* For the purposes of drfuzz, stdcall is an alias to cdecl, since the only
     * difference is whether the caller or callee cleans up the stack, and drfuzz
     * ignores this detail by simply storing the stack pointer value on target entry.
     */
    /** The target function uses the Microsoft IA-32 stdcall calling convention. */
    DRFUZZ_CALLCONV_STDCALL = DRFUZZ_CALLCONV_CDECL,
    /** The target function uses the IA-32 fastcall calling convention. */
    DRFUZZ_CALLCONV_FASTCALL = 0x02,
    /** The target function uses the Microsoft IA-32 thiscall calling convention. */
    DRFUZZ_CALLCONV_THISCALL = 0x04,
#ifdef X64
    /** The target function is a vararg function. */
    DRFUZZ_CALLCONV_VARARG = DRFUZZ_CALLCONV_FASTCALL,
#else
    /** The target function is a vararg function. */
    DRFUZZ_CALLCONV_VARARG = DRFUZZ_CALLCONV_CDECL,
#endif
    DRFUZZ_CALLCONV_RESERVED_1 = 0x08, /**< Reserved for additional calling conventions */
    DRFUZZ_CALLCONV_RESERVED_2 = 0x10, /**< Reserved for additional calling conventions */
    DRFUZZ_CALLCONV_RESERVED_3 = 0x20, /**< Reserved for additional calling conventions */
    DRFUZZ_CALLCONV_RESERVED_4 = 0x40, /**< Reserved for additional calling conventions */
    DRFUZZ_CALLCONV_RESERVED_5 = 0x80, /**< Reserved for additional calling conventions */
    /** Utility value for masking the set of calling convention flags. */
    DRFUZZ_CALLCONV_MASK = 0xff,
    /* XXX i#1734: calling conventions NYI (assumes cdecl for now) */
} drfuzz_flags_t;

DR_EXPORT
/**
 * Initialize the Dr. Fuzz extension. This function must be called before any other
 * Dr. Fuzz API functions. Can be called any number of times, but each call must be
 * paired with a corresponding call to drfuzz_exit().
 */
drmf_status_t
drfuzz_init(client_id_t client_id);

DR_EXPORT
/**
 * Clean up all resources used by the Dr. Fuzz extension.
 */
drmf_status_t
drfuzz_exit(void);

DR_EXPORT
/**
 * Register the function that starts at address \p func_pc for repeated fuzz testing.
 * The \p pre_func and \p post_func callbacks will control the fuzz testing cycle.
 * The client may arbitrarily change arguments to the target function during the
 * \p pre_func callback, and fuzz testing of the target will continue for as long as
 * the \p post_func callback returns true.
 *
 * Fuzzing requests should normally be made up front during process initialization or
 * module load (see dr_register_module_load_event()). If a fuzzing request is made after
 * the target code may have already been executed by the application, the caller should
 * flush the target code from the cache using the desired flush method after issuing the
 * fuzzing request. Multiple fuzzing requests for the same \p func_pc are not allowed.
 *
 * The \p pre_func will be called at the beginning of the target function on each
 * iteration, before any of its code executes. The \p pre_func may examine the
 * arguments using drfuzz_get_arg() and modify them using drfuzz_set_arg(). Before each
 * invocation of the \p pre_func, drfuzz will reset the arguments to the original values
 * that were passed by the application (by shallow copy). Argument values may only be
 * changed during a \p pre_func callback.
 *
 * The \p post_func will be called after the target function returns on each iteration,
 * but before any subsequent instructions following the call site have been executed.
 * Returning true will cause drfuzz to redirect execution back to the start of the
 * target function, adjusting the call stack and resetting the argument values
 * accordingly (see drwrap_redirect_execution() for details). Argument accessors
 * drfuzz_get_arg() and drfuzz_set_arg() are not available in this phase of the fuzzing
 * cycle, though drfuzz_get_target_arg() can be used at any time during fuzzing.
 *
 * \note Recursive invocation of the fuzz target is currently not supported.
 *
 * @param[in] func_pc             The start pc of the new fuzz target function.
 * @param[in] arg_count           The actual number of arguments passed to the fuzz target
 *                                function during fuzz testing (i.e., for vararg targets,
 *                                the client must know how many args are actually used).
 * @param[in] flags               Flags are optional, except that the calling convention
 *                                must be specified (using one of DRFUZZ_CALLCONV_*).
 * @param[in] pre_fuzz_callback   Called prior to each fuzz iteration of the target
 *                                function (must not be NULL).
 * @param[in] post_fuzz_callback  Called following each fuzz iteration of the target
 *                                function (must not be NULL).
 */
/* XXX i#1734: describe what happens on crash, or when client detects an error (NYI) */
drmf_status_t
drfuzz_fuzz_target(generic_func_t func_pc, uint arg_count, drfuzz_flags_t flags,
                   void (*pre_fuzz_cb)(generic_func_t target_pc, void *fuzzcxt,
                                       INOUT void **user_data),
                   bool (*post_fuzz_cb)(generic_func_t target_pc, void *fuzzcxt,
                                        void *user_data));

DR_EXPORT
/**
 * Get the value of an argument to the fuzz target function at \p target_pc. May only be
 * called while fuzzing of this target is in progress. Will retrieve the arg value for
 * the current fuzz iteration on the current thread. Returns DRMF_SUCCESS on success.
 *
 * @param[in] target      The target function.
 * @param[in] arg         Identifies the argument by its index.
 * @param[in] original    Specifies whether to get the original value of the argument
 *                        passed by the app, or the currently applied fuzz value.
 * @param[out] arg_value  Returns the value of the argument (when successful).
 */
drmf_status_t
drfuzz_get_arg(generic_func_t target_pc, int arg, bool original, OUT void **arg_value);

DR_EXPORT
/**
 * Set the value of an argument to the target function. May only be called from a
 * pre-fuzz callback. Returns DRMF_SUCCESS on success.
 *
 * This routine may de-reference application memory directly, so the
 * caller should wrap it in DR_TRY_EXCEPT if crashes must be avoided.
 */
drmf_status_t
drfuzz_set_arg(void *fuzzcxt, int arg, void *val);

/*@}*/ /* end doxygen group */

#ifdef __cplusplus
}
#endif

#endif /* _DR_FUZZ_H_ */
