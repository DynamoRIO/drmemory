/* **********************************************************
 * Copyright (c) 2010-2011 Google, Inc.  All rights reserved.
 * Copyright (c) 2007-2010 VMware, Inc.  All rights reserved.
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

#ifndef _SYSCALL_OS_H_
#define _SYSCALL_OS_H_ 1

enum {
    /* syscall_arg_t.flags */
    SYSARG_WRITE           = 0x00000001,

    /* The following flags are used on Windows. */
    /* BOOLEAN is only 1 byte so ok if only lsb is defined
     * FIXME: are we going to need the sizes of all the params, esp.
     * when we move to 64-bit?
     */
    SYSARG_INLINED_BOOLEAN = 0x00000002,
    SYSARG_PORT_MESSAGE    = 0x00000004,
    /* the size points at the IO_STATUS_BLOCK param */
    SYSARG_POST_SIZE_IO_STATUS = 0x00000008,
    /* the size points at a poiner-to-8-byte value param */
    SYSARG_POST_SIZE_8BYTES = 0x00000010,
    /* the param holding the size is a pointer b/c it's an IN OUT var */
    SYSARG_LENGTH_INOUT     = 0x00000020,
    SYSARG_CONTEXT          = 0x00000040,
    SYSARG_EXCEPTION_RECORD = 0x00000080,
    SYSARG_SECURITY_QOS     = 0x00000100,
    SYSARG_SECURITY_DESCRIPTOR = 0x00000200,
    SYSARG_UNICODE_STRING      = 0x00000400,
    SYSARG_CSTRING_WIDE        = 0x00000800,

    /* The following flags are used on Linux. */
    /* syscall_arg_t.size, using values that cannot be mistaken for
     * a parameter reference
     */
    SYSARG_SIZE_CSTRING       = -100,
    /* used in repeated syscall_arg_t entry for post-syscall size */
    SYSARG_POST_SIZE_RETVAL   = -101,
};

/* We encode the actual size of a write, if it can differ from the
 * requested size, as a subsequent syscall_arg_t entry with the same
 * param#.  A negative size there refers to a parameter that should be
 * de-referenced to obtain the actual write size.  The de-reference size
 * is assumed to be 4 unless SYSARG_POST_SIZE_8BYTES is set.
 */
typedef struct _syscall_arg_t {
    int param; /* ordinal of parameter */
    int size; /* >0 = abs size; <=0 = -param that holds size */
    uint flags; /* SYSARG_ flags */
} syscall_arg_t;

#ifdef WINDOWS
/* unverified but we don't expect pointers beyond 1st 11 args
 * (even w/ dup entries for diff in vs out size to writes)
 */
# define MAX_NONINLINED_ARGS 11
#else
# define MAX_NONINLINED_ARGS 6
#endif

#define SYSCALL_ARG_TRACK_MAX_SZ 2048

typedef struct _syscall_info_t {
    int num; /* system call number: filled in dynamically */
    const char *name;
    int args_size; /* for Windows: total size of args; for Linux: arg count */
    /* list of args that are not inlined */
    syscall_arg_t arg[MAX_NONINLINED_ARGS];
} syscall_info_t;

extern syscall_info_t syscall_info[];

#define SYSARG_CHECK_TYPE(flags, pre) \
    (TEST(SYSARG_WRITE, (flags)) ? \
    ((pre) ? MEMREF_CHECK_ADDRESSABLE : MEMREF_WRITE) : MEMREF_CHECK_DEFINEDNESS)

void
syscall_os_init(void *drcontext _IF_WINDOWS(app_pc ntdll_base));

void
syscall_os_exit(void);

syscall_info_t *
syscall_lookup(int num);

void
syscall_os_module_load(void *drcontext, const module_data_t *info, bool loaded);

uint
get_sysparam_shadow_val(uint sysnum, uint argnum, dr_mcontext_t *mc);

void
check_sysparam_defined(uint sysnum, uint argnum, dr_mcontext_t *mc, size_t argsz);

/* for tasks unrelated to shadowing that are common to all tools */
bool
os_shared_pre_syscall(void *drcontext, int sysnum);

void
os_shared_post_syscall(void *drcontext, int sysnum);

/* for memory shadowing checks */
bool
os_shadow_pre_syscall(void *drcontext, int sysnum);

void
os_shadow_post_syscall(void *drcontext, int sysnum);

/* returns true if the given argument was processed in a non-standard way
 * (e.g. OS-specific structures) and we should skip the standard check
 */
bool
os_handle_pre_syscall_arg_access(int sysnum, dr_mcontext_t *mc, uint arg_num,
                                 const syscall_arg_t *arg_info,
                                 app_pc start, uint size);

/* returns true if the given argument was processed in a non-standard way
 * (e.g. OS-specific structures) and we should skip the standard check
 */
bool
os_handle_post_syscall_arg_access(int sysnum, dr_mcontext_t *mc, uint arg_num,
                                  const syscall_arg_t *arg_info,
                                  app_pc start, uint size);

bool
os_syscall_succeeded(int sysnum, ptr_int_t res);

/* provides name if known when not in syscall_lookup(num) */
const char *
os_syscall_get_name(uint num);

#endif /* _SYSCALL_OS_H_ */
