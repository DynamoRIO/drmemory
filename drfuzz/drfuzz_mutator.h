/* **********************************************************
 * Copyright (c) 2015 Google, Inc.  All rights reserved.
 * Copyright (c) 2010 VMware, Inc.  All rights reserved.
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

#if defined(DYNAMIC_INTERFACE) || !defined(_DRFUZZ_MUTATOR_H_)
# ifndef DYNAMIC_INTERFACE
#  define _DRFUZZ_MUTATOR_H_ 1
# endif

/* Framework-shared header for drmf_status_t type */
#ifndef DYNAMIC_INTERFACE
# include "drmemory_framework.h"
#endif

/**
 * @file drfuzz_mutator.h
 * @brief Header specifying the Dr. Fuzz mutator library interface.
 *
 * To create a new mutator library, include this header in your
 * library compilation (leaving DYNAMIC_INTERFACE undefined) and
 * implement the interface functions defined below.  You will need
 * to ensure that drmemory_framework.h is on the include path as well
 * for drmf_status_t.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup drfuzz Dr. Fuzz: DynamoRIO Fuzz Testing Extension
 */
/*@{*/ /* begin doxygen group */

/* This header plays double-duty: regular interface declarations for the
 * implementation of the library and also a function pointer invocation
 * interface for users of the library.
 */
#undef LIBFUNC
#undef LIB_EXPORT
#undef LINK_ONCE
#ifdef DYNAMIC_INTERFACE
# define LIBFUNC(name) (*name)
# define LIB_EXPORT /* nothing */
#else
# define LIBFUNC(name) name
# ifdef WINDOWS
#  define LIB_EXPORT __declspec(dllexport)
# else
#  define LIB_EXPORT __attribute__ ((visibility ("default")))
# endif
typedef void * drfuzz_mutator_t;
#endif

#ifdef WINDOWS
# define LINK_ONCE __declspec(selectany)
#else
# define LINK_ONCE __attribute__ ((weak))
#endif

/* Version checking.
 * We provide an oldest-compatible version and a current version.
 * When we make additions to the API, we increment just the current version.
 * When we modify any part of the existing API, we increment the
 * current version, but we also increase the oldest-compatible
 * version to match the (just-incremented) current version.
 */
#define DRFUZZLIB_VERSION_COMPAT_VAR _DRFUZZLIB_VERSION_COMPAT_
#define DRFUZZLIB_VERSION_CUR_VAR    _DRFUZZLIB_VERSION_CUR_
#ifndef DYNAMIC_INTERFACE
LIB_EXPORT LINK_ONCE int DRFUZZLIB_VERSION_COMPAT_VAR = 1;
LIB_EXPORT LINK_ONCE int DRFUZZLIB_VERSION_CUR_VAR    = 1;
#endif
#define DRFUZZLIB_VERSION_COMPAT_NAME STRINGIFY(DRFUZZLIB_VERSION_COMPAT_VAR)
#define DRFUZZLIB_VERSION_CUR_NAME    STRINGIFY(DRFUZZLIB_VERSION_CUR_VAR)

LIB_EXPORT
/**
 * Initiate mutation on a buffer.  Returns DRMF_SUCCESS on success.
 *
 * @param[out]  mutator     Return argument for the newly initiated mutator.
 * @param[in]   input_seed  Pointer to the seed instance of the buffer to mutate.
 * @param[in]   size        The number of bytes in the buffer.
 * @param[in]   argc        The number of arguments to customize the mutator.
 * @param[in]   argv        An array of \p argc arguments to customize the mutator.
 */
drmf_status_t
LIBFUNC(drfuzz_mutator_start)(OUT drfuzz_mutator_t **mutator, IN void *input_seed,
                              IN size_t size, IN int argc, IN const char *argv[]);

LIB_EXPORT
/**
 * Returns true if the mutator can generate the next value.  Generally this is only
 * relevant for mutators using a sequential algorithm.
 */
bool
LIBFUNC(drfuzz_mutator_has_next_value)(drfuzz_mutator_t *mutator);

LIB_EXPORT
/**
 * Provides a copy of the current mutator value. Returns DRMF_SUCCESS on success.
 */
drmf_status_t
LIBFUNC(drfuzz_mutator_get_current_value)(IN drfuzz_mutator_t *mutator, OUT void *buffer);

LIB_EXPORT
/**
 * Writes the next fuzz value to the provided buffer. Returns DRMF_SUCCESS on success.
 */
drmf_status_t
LIBFUNC(drfuzz_mutator_get_next_value)(drfuzz_mutator_t *mutator, OUT void *buffer);

LIB_EXPORT
/**
 * Clean up resources allocated for the mutator. Returns DRMF_SUCCESS on success.
 */
drmf_status_t
LIBFUNC(drfuzz_mutator_stop)(drfuzz_mutator_t *mutator);

LIB_EXPORT
/**
 * Provides feedback to the mutator about the effect of the last mutation.
 * The meaning of \p feedback can be specified by custom mutators.
 * If the meaning of \p feedback is not specified, 0 means neutral,
 * and the greater the value of \p feedback is, the more effective the last
 * mutation is.
 *
 * \note This function must be called to enable feedback guided mutation.
 * For example, in Dr. Memory fuzz testing mode, the option -fuzz_coverage must
 * be specified for any custom mutator that supports feedback guided mutation.
 */
drmf_status_t
LIBFUNC(drfuzz_mutator_feedback)(drfuzz_mutator_t *mutator, int feedback);

/*@}*/ /* end doxygen group */

#ifdef __cplusplus
}
#endif

#endif /* _DRFUZZ_MUTATOR_H_ */
