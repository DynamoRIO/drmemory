/* **********************************************************
 * Copyright (c) 2010-2018 Google, Inc.  All rights reserved.
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

#ifndef _SYSCALL_AUX_H_
#define _SYSCALL_AUX_H_ 1

/* System call auxiliary library interface */

/* Support importing by invoking function pointers */
#ifdef DYNAMIC_INTERFACE
# define DYNFUNC(name) (*name)
# define LIB_EXPORT
#else
# define DYNFUNC(name) name
# ifdef WINDOWS
#  define LIB_EXPORT __declspec(dllexport)
# else
#  define LIB_EXPORT __attribute__ ((visibility ("default")))
# endif
#endif

#define EXPANDSTR(x) #x
#define STRINGIFY(x) EXPANDSTR(x)

#ifndef LINK_ONCE
# ifdef WINDOWS
#  define LINK_ONCE __declspec(selectany)
# else
#  define LINK_ONCE __attribute__ ((weak))
# endif
#endif

/* Version checking.
 * We provide an oldest-compatible version and a current version.
 * When we make additions to the API, we increment just the current version.
 * When we modify any part of the existing API, we increment the
 * current version, but we also increase the oldest-compatible
 * version to match the (just-incremented) current version.
 */
#define SYSAUXLIB_VERSION_COMPAT_VAR _SYSAUXLIB_VERSION_COMPAT_
#define SYSAUXLIB_VERSION_CUR_VAR    _SYSAUXLIB_VERSION_CUR_
#ifndef DYNAMIC_INTERFACE
LIB_EXPORT LINK_ONCE int SYSAUXLIB_VERSION_COMPAT_VAR = 1;
LIB_EXPORT LINK_ONCE int SYSAUXLIB_VERSION_CUR_VAR    = 1;
#endif
#define SYSAUXLIB_VERSION_COMPAT_NAME STRINGIFY(SYSAUXLIB_VERSION_COMPAT_VAR)
#define SYSAUXLIB_VERSION_CUR_NAME    STRINGIFY(SYSAUXLIB_VERSION_CUR_VAR)

/* Type of syscall mem parameter for cases where caller can find actual size */
typedef enum {
    SYSAUXLIB_PARAM_STRUCT,   /* length holds size */
    SYSAUXLIB_PARAM_STRING,   /* C string */
    SYSAUXLIB_PARAM_STRARRAY, /* NULL-terminated array of C strings */
} sysauxlib_param_t;

/* Performs any necessary initialization.  Returns whether this
 * library should continue to be used.
 */
LIB_EXPORT
bool
DYNFUNC(sysauxlib_init)(void);

/* Returns the name of the system call.
 * Returns NULL if sysnum is not a system call handled by
 * this library.
 */
LIB_EXPORT
const char *
DYNFUNC(sysauxlib_syscall_name)(int sysnum);

/* Saves the parameter info at the pre-syscall point.  The returned opaque
 * pointer should be passed to the other API routines.
 */
LIB_EXPORT
void *
DYNFUNC(sysauxlib_save_params)(void *drcontext);

/* Frees the parameter info allocated by sysauxlib_save_params(). */
LIB_EXPORT
void
DYNFUNC(sysauxlib_free_params)(void *drcontext, void *params);

/* Returns whether the given result is successful given the register
 * state passed in (representing the pre-syscall register state)
 * and the current memory state (some system call parameters are
 * optional and depend on other parameters).
 */
LIB_EXPORT
bool
DYNFUNC(sysauxlib_syscall_successful)(void *drcontext, void *params);

/* Returns the number of register parameters that the given
 * system call number takes, given the register
 * state passed in (representing the pre-syscall register state)
 * and the current memory state (some system call parameters are
 * optional and depend on other parameters).
 * Returns -1 if sysnum is not a system call handled by
 * this library.
 */
LIB_EXPORT
int
DYNFUNC(sysauxlib_num_reg_params)(void *drcontext, void *params);

/* Returns the register used for the index-th register parameter given
 * the register state passed in (representing the pre-syscall register
 * state) and the current memory state (some system call parameters
 * are optional and depend on other parameters).  Returns REG_NULL if
 * index is out of bounds.
 */
LIB_EXPORT
reg_id_t
DYNFUNC(sysauxlib_reg_param_info)(void *drcontext, void *params, int index);

/* Returns the number of memory parameters that the given
 * system call number takes, given the register
 * state passed in (representing the pre-syscall register state)
 * and the current memory state (some system call parameters are
 * optional and depend on other parameters).
 * Uses dr_safe_read() to read any memory values.
 * Returns -1 if sysnum is not a system call handled by
 * this library.
 */
LIB_EXPORT
int
DYNFUNC(sysauxlib_num_mem_params)(void *drcontext, void *params);

/* Returns information about the index-th memory parameter that the
 * given system call number takes, given the register state passed in
 * (representing the pre-syscall register state) and the current
 * memory state (some system call parameters are optional and depend
 * on other parameters, and some memory parameter sizes are specified
 * by other parameters).  For length_out, assumes the memory state is
 * the post-syscall state.
 *
 * If a parameter does not have an input component, length_in will be
 * 0; if it does not have an output component, length_out will be 0;
 * if it is NULL-terminated, the corresponding length will be 1
 * (unless it has a maximum size and that full amount should be
 * addressable though not necessarily defined) and the type parameter
 * will indicate how to traverse it.  Uses dr_safe_read() to read any
 * memory values.
 *
 * Returns false if sysnum is not a system call handled by this
 * library or if index is out of bounds; else returns true along with
 * filling in any non-NULL output parameters.
 */
LIB_EXPORT
bool
DYNFUNC(sysauxlib_mem_param_info)(void *drcontext,         /* IN */
                                  void *params,            /* IN */
                                  int index,               /* IN */
                                  const char **name,       /* OUT */
                                  byte **start_addr,       /* OUT */
                                  size_t *length_in,       /* OUT */
                                  size_t *length_out,      /* OUT */
                                  sysauxlib_param_t *type);/* OUT */

/* Returns true if the system call is a fork (or combination fork+exec)
 * and fills in the child process identifier, which should only be
 * asked for (i.e., non-NULL) when called during post-syscall.
 */
LIB_EXPORT
bool
DYNFUNC(sysauxlib_is_fork)(void *drcontext,     /* IN */
                           void *params,        /* IN */
                           process_id_t *child);/* OUT */

/* Returns true if the system call is an exec (or combination fork+exec)
 * and returns the target image path.
 */
LIB_EXPORT
bool
DYNFUNC(sysauxlib_is_exec)(void *drcontext,  /* IN */
                           void *params,     /* IN */
                           char *path,       /* OUT */
                           size_t path_len); /* IN */

#endif /* _SYSCALL_AUX_H_ */
