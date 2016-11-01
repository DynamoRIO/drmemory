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

/* Framework-shared headers */
#include "drmemory_framework.h"
#include "drwrap.h"
#include "drfuzz_mutator.h" /* for drfuzz_mutator_t */

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
 * Represents the stack frame of a fuzz target during one fuzz iteration, including
 * the argument values from that iteration. To access the target frames for any thread,
 * call drfuzz_target_iterator_start() from that thread. When a crash occurs, the set
 * of target frames that were live at the time of the critical fault are copied into
 * a #drfuzz_fault_thread_state_t, which is provided in the crash events.
 *
 * \note For pointer arguments, the pointed value may change, or may no longer be
 * accessible, after the stack frame returns (or aborts on crash). Clients requiring
 * post-mortem access to such pointed values will need to store them at the beginning
 * of each fuzz iteration.
 */
typedef struct _drfuzz_target_frame_t {
    app_pc func_pc;    /* the target function */
    uint arg_count;    /* the number of arguments for this target */
    reg_t *arg_values; /* the argument values */
} drfuzz_target_frame_t;

/**
 * An opaque iterator of fuzz targets, representing the set of targets that were live on
 * the call stack of one thread at a specific point in time.
 */
typedef void * drfuzz_target_iterator_t;

/**
 * Provides basic information about an occurrence of a "critical fault", which in drfuzz
 * refers to a subset of signals (Unix) or exceptions (Windows) that (a) are likely to be
 * caused by fuzz testing, (b) imply errors and/or vulnerabilities in the code of the
 * target application, and (c) terminate execution if they are not caught and handled.
 * By default, the set of "critical faults" is SIGSEGV and SIGBUS on Unix, and Access
 * Violation on Windows. (In a future release, the "critical faults" will be configurable
 * by the drfuzz client.) Also see comments on drfuzz_register_fault_event().
 *
 * Where provided by callbacks from this API, this struct may be retained indefinitely.
 * Additional information about a critical fault is provided by #drfuzz_fault_ex_t, which
 * duplicates some data from this struct, but may not be retained after a callback.
 */
typedef struct _drfuzz_fault_t {
    /**
     * Signal number (Unix) or exception code (Windows).
     */
    int fault_code;
    /**
     * The address within the target application where the fault occurred.
     */
    app_pc fault_pc;
    /**
     * For memory access faults only, the address of the failed access attempt.
     */
    byte *access_address;
    /**
     * The thread that executed the fault.
     */
    thread_id_t thread_id;
    /**
     * Available for custom user data. To free the custom data when drfuzz deletes an
     * instance of #drfuzz_fault_t, use drfuzz_register_fault_delete_callback().
     */
    void *user_data;
} drfuzz_fault_t;

/**
 * Provides extended information about a critical fault. On Unix cast to dr_siginfo_t,
 * or on Windows cast to dr_exception_t. See documentation on those structs for details.
 *
 * Where provided by callbacks from this API, instances of this struct are temporary and
 * may not be accessed after the callback function returns. Copy the struct as necessary.
 */
#ifdef UNIX
typedef dr_siginfo_t drfuzz_fault_ex_t;
#else
typedef dr_exception_t drfuzz_fault_ex_t;
#endif

/**
 * Records the state of a thread at the time a fault occurred on that thread, or at the
 * time the thread is aborted due to application crash. Faults recorded in the state at
 * the time of a crash are not necessarily responsible for the crash.
 *
 * \note Currently only the first and last faults will be provided in the \p faults array.
 */
typedef struct _drfuzz_fault_thread_state_t {
    /**
     * The thread ID.
     */
    thread_id_t thread_id;
    /**
     * The number of critical faults that occurred in the chain, starting with the
     * first fault that occurred while executing a fuzz target, and including all
     * faults that occurred until the thread exited.
     */
    uint faults_observed;
    /**
     * The number of elements in the faults array.
     */
    uint fault_count;
    /**
     * The array of faults.
     */
    drfuzz_fault_t *faults;
    /**
     * An iterable list of the fuzz targets that were live on the call stack when the
     * first fault in the chain occurred (innermost stack frame first).
     */
    drfuzz_target_iterator_t *targets;
} drfuzz_fault_thread_state_t;

/**
 * Records the state of all application threads at the time of a crash.
 */
typedef struct _drfuzz_crash_state_t {
    uint thread_count; /**< The number of states in the \p thread_states array. */
    drfuzz_fault_thread_state_t **thread_states; /**< An array of thread states. */
} drfuzz_crash_state_t;

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
 * The fuzzer implements repeated execution of the target function using the drwrap
 * extension, which accepts a flags argument for each wrapped target function. Use the
 * \p wrap_flags parameter to pass flags through to the internal drwrap_wrap_ex() call.
 * The calling convention specified in the \p wrap_flags must be correct or the target
 * function will have incorrect arguments and/or a corrupt stack during fuzz testing.
 *
 * \note Recursive invocation of the fuzz target is currently not supported.
 *
 * @param[in] func_pc             The start pc of the new fuzz target function.
 * @param[in] arg_count           The actual number of arguments passed to the fuzz target
 *                                function during fuzz testing (i.e., for vararg targets,
 *                                the client must know how many args are actually used).
 * @param[in] flags               Reserved for future use; must be set to 0.
 * @param[in] wrap_flags          Flags for the delegated call to wrap the fuzz target
 *                                function for repeated execution; see drwrap_wrap_ex().
 * @param[in] pre_fuzz_cb         Called prior to each fuzz iteration of the target
 *                                function (must not be NULL). Any changes made by the
 *                                callee to the application registers must be applied to
 *                                the mcontext provided (or they will not take effect).
 * @param[in] post_fuzz_cb        Called following each fuzz iteration of the target
 *                                function (must not be NULL).
 */
drmf_status_t
drfuzz_fuzz_target(generic_func_t func_pc, uint arg_count, uint flags, uint wrap_flags,
                   void (*pre_fuzz_cb)(void *fuzzcxt, generic_func_t target_pc,
                                       dr_mcontext_t *mc),
                   bool (*post_fuzz_cb)(void *fuzzcxt, generic_func_t target_pc));

DR_EXPORT
/**
 * Unregister the fuzz target at func_pc from drfuzz. Future executions of the target
 * function will not be repeated in the fuzz testing loop. Should not be called while the
 * target function is executing (application may behave incorrectly or crash).
 */
drmf_status_t
drfuzz_unfuzz_target(generic_func_t func_pc);

DR_EXPORT
/**
 * Register for notification of a fault event, which occurs when the execution of any
 * fuzz target encounters a critical fault (as defined at #drfuzz_fault_t). Since the app
 * may handle the fault, drfuzz does not report it to the user at the time this event
 * occurs. Instead, it maintains a chain of faults that occur during a single fuzz
 * iteration, and only reports them if the application crashes before starting the next
 * fuzz iteration. Use drfuzz_register_crash_thread_event() to receive crash notification.
 *
 * <b>Event parameters</b>
 * <table border="0">
 * <tr>
 *   <td valign="top"><code>&nbsp;&nbsp;&nbsp;&nbsp;[in]</code></td>
 *   <td valign="top"><b>fuzzcxt&nbsp;</b></td>
 *   <td valign="top">The drfuzz thread-local context of the fault.</td>
 * </tr>
 * <tr>
 *   <td valign="top"><code>&nbsp;&nbsp;&nbsp;&nbsp;[in]</code></td>
 *   <td valign="top"><b>fault&nbsp;</b></td>
 *   <td valign="top">
 *     Provides basic information about the kind and location of the
 *     fault, and may be retained by the callee until delete (to be
 *     notified, use drfuzz_register_fault_delete_callback()). The
 *     field user_data is available for attaching custom data to the
 *     fault for later use during the crash events (if any) via
 *     #drfuzz_fault_thread_state_t and #drfuzz_crash_state_t.
 *   </td>
 * </tr>
 * <tr>
 *   <td valign="top"><code>&nbsp;&nbsp;&nbsp;&nbsp;[in]</code></td>
 *   <td valign="top"><b>fault_ex&nbsp;</b></td>
 *   <td valign="top">
 *     Provides extended information about the memory state at the
 *     fault. This struct is transitory and must be copied if any of
 *     its data needs to be retained.
 *   </td>
 * </tr>
 * </table>
 *
 * \note Does not allow multiple registration.
 */
drmf_status_t
drfuzz_register_fault_event(void (*event)(void *fuzzcxt,
                                          drfuzz_fault_t *fault,
                                          drfuzz_fault_ex_t *fault_ex));

DR_EXPORT
/**
 * Unregister the fault notification event.
 */
drmf_status_t
drfuzz_unregister_fault_event(void (*event)(void *fuzzcxt,
                                          drfuzz_fault_t *fault,
                                          drfuzz_fault_ex_t *fault_ex));

DR_EXPORT
/**
 * Register to be notified when drfuzz deletes a fault object, indicating it is no longer
 * safe to retain it. If user_data has been attached, it should be disposed at this time.
 *
 * \note Does not allow multiple registration.
 */
drmf_status_t
drfuzz_register_fault_delete_callback(void (*callback)(void *fuzzcxt,
                                                       drfuzz_fault_t *fault));

DR_EXPORT
/**
 * Unregister the fault delete notification callback.
 */
drmf_status_t
drfuzz_unregister_fault_delete_callback(void (*callback)(void *fuzzcxt,
                                                         drfuzz_fault_t *fault));

DR_EXPORT
/**
 * Register to be notified of an application crash on each thread that is running at
 * the time of the crash. The event contains the state of the current thread at the
 * time of the fault. If the crash was not caused by this thread, the state may contain
 * faults that would have been handled by the app (had it continued to run).
 *
 * The state also contains a list of fuzz targets. If the state contains faults, these
 * targets represent the state of fuzzing at the time the first fault occurred. Otherwise
 * these targets were live at the time the thread was aborted by the crash.
 *
 * Access the targets using the provided iterator, but do not stop the iterator
 * (drfuzz_target_iterator_stop() will be called internally).
 *
 * \note Does not allow multiple registration.
 */
drmf_status_t
drfuzz_register_crash_thread_event(void (*event)(void *fuzzcxt,
                                                 drfuzz_fault_thread_state_t *state));

DR_EXPORT
/**
 * Unregister the crash notification callback.
 */
drmf_status_t
drfuzz_unregister_crash_thread_event(void (*event)(void *fuzzcxt,
                                                   drfuzz_fault_thread_state_t *state));

DR_EXPORT
/**
 * Get the drfuzz thread context for the current thread. This function has significant
 * overhead, and should not be used repetitively in performance-sensitive applications.
 */
void *
drfuzz_get_fuzzcxt(void);

DR_EXPORT
/**
 * Get the dcontext associated with this fuzzcxt.
 */
void *
drfuzz_get_drcontext(void *fuzzcxt);

DR_EXPORT
/**
 * Get the total number of basic blocks seen during \p target_pc fuzzing,
 * i.e., from the first execution of the target function at \p target_pc
 * to the last exit from that function.
 *
 * @param[in] target_pc   The target function. If \p target_pc is NULL, the total
 *                        number of basic blocks seen during execution is returned.
 * @param[out] num_bbs    Returns the number of basic blocks.
 *
 * \note: The number of basic blocks returned might not be the precise number
 * of new blocks that are a direct result of the target function's execution.
 * For example, a basic block might be counted multiple times due to code cache
 * management; basic blocks executed by other threads are not be counted; basic
 * blocks executed in the inner fuzzing function are not counted for the outer
 * fuzzing function in the case of nested fuzzing.
 */
drmf_status_t
drfuzz_get_target_num_bbs(IN generic_func_t target_pc, OUT uint64 *num_bbs);

DR_EXPORT
/**
 * Get the value of an argument to the fuzz target function at \p target_pc. May only be
 * called while fuzzing of this target is in progress. Will retrieve the arg value for
 * the current fuzz iteration on the current thread. Returns DRMF_SUCCESS on success.
 *
 * @param[in] fuzzcxt     The drfuzz thread context.
 * @param[in] target_pc   The target function. May be NULL, which implies that the target
 *                        is the most recently called target on the app call stack.
 * @param[in] arg         Identifies the argument by its index.
 * @param[in] original    Specifies whether to get the original value of the argument
 *                        passed by the app, or the currently applied fuzz value.
 * @param[out] arg_value  Returns the value of the argument (when successful).
 */
drmf_status_t
drfuzz_get_arg(void *fuzzcxt, generic_func_t target_pc, int arg, bool original,
               OUT void **arg_value);

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

DR_EXPORT
/**
 * Get the user data associated with the \p target_pc.
 */
drmf_status_t
drfuzz_get_target_user_data(IN generic_func_t target_pc, OUT void **user_data);

DR_EXPORT
/**
 * Set the user data associated with the specified \p target_pc. If the \p delete_callback
 * is not NULL, it will be called when drfuzz deletes the internal target data structure.
 *
 * \note: Only one slot is provided for the data, so multiple writes will overwrite.
 */
drmf_status_t
drfuzz_set_target_user_data(IN generic_func_t target_pc, IN void *user_data,
                            IN void (*delete_callback)(void *user_data));

DR_EXPORT
/**
 * Get the user data associated with the specified \p target_pc and \p fuzzcxt. If the
 * \p fuzzcxt is NULL, the fuzzcxt for the current thread will be used (if any).
 */
drmf_status_t
drfuzz_get_target_per_thread_user_data(IN void *fuzzcxt, IN generic_func_t target_pc,
                                       OUT void **user_data);

DR_EXPORT
/**
 * Set the user data associated with the specified \p target_pc and \p fuzzcxt. If the
 * \p fuzzcxt is NULL, the fuzzcxt for the current thread will be used (if any). If the
 * \p delete_callback is not NULL, it will be called when drfuzz deletes the internal
 * target data structure (after completing a fuzz pass), or when the thread exits.
 *
 * \note: Only one slot is provided for the data, so multiple writes will overwrite.
 */
drmf_status_t
drfuzz_set_target_per_thread_user_data(IN void *fuzzcxt, IN generic_func_t target_pc,
                                       IN void *user_data,
                                       IN void (*delete_callback)(void *fuzzcxt,
                                                                  void *user_data));

DR_EXPORT
/**
 * Initiates an iterator over the set of fuzz targets that are live on the current
 * thread's call stack. Use drfuzz_target_iterator_next() to traverse the fuzz target
 * frames, and use drfuzz_target_iterator_stop() to free the iterator and all frames.
 */
drfuzz_target_iterator_t *
drfuzz_target_iterator_start(void *fuzzcxt);

DR_EXPORT
/**
 * Returns the next fuzz target frame in the iteration set, or NULL after the last frame.
 */
drfuzz_target_frame_t *
drfuzz_target_iterator_next(drfuzz_target_iterator_t *iter);

DR_EXPORT
/**
 * Stop a fuzz target iterator and free its allocated resources (including target frames).
 */
drmf_status_t
drfuzz_target_iterator_stop(drfuzz_target_iterator_t *iter);

/***************************************************************************
 * Mutation
 */

typedef struct _drfuzz_mutator_api_t {
    size_t struct_size;
    dr_auxlib_handle_t handle;

#   define DYNAMIC_INTERFACE 1
#   include "drfuzz_mutator.h"
#   undef DYNAMIC_INTERFACE

} drfuzz_mutator_api_t;

DR_EXPORT
/**
 * Loads a mutator.  If \p lib_path is NULL, the default mutator built
 * in to \p Dr. Fuzz is loaded.  Otherwise, the custom, third-party
 * mutator library located at the file path \p lib_path is loaded.
 * The mutator interface for the loaded mutator is returned in \p api.
 * The caller must set \p api->struct_size before calling.  Returns
 * DRMF_SUCCESS on success.
 */
drmf_status_t
drfuzz_mutator_load(IN const char *lib_path, INOUT drfuzz_mutator_api_t *api);

DR_EXPORT
/**
 * Unloads a custom mutator library.  Returns DRMF_SUCCESS on success.
 */
drmf_status_t
drfuzz_mutator_unload(IN drfuzz_mutator_api_t *lib);


/*@}*/ /* end doxygen group */

#ifdef __cplusplus
}
#endif

#endif /* _DR_FUZZ_H_ */
