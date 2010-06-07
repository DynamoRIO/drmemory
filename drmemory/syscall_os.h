/* **********************************************************
 * Copyright (c) 2007-2009 VMware, Inc.  All rights reserved.
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
    SYSARG_PORT_MESSAGE    = 0x00000002,
    /* BOOLEAN is only 1 byte so ok if only lsb is defined
     * FIXME: are we going to need the sizes of all the params, esp.
     * when we move to 64-bit?
     */
    SYSARG_INLINED_BOOLEAN = 0x00000004,
    /* the size points at the IO_STATUS_BLOCK param */
    SYSARG_POST_SIZE_IO_STATUS = 0x00000008,
    /* the size points at a poiner-to-8-byte value param */
    SYSARG_POST_SIZE_8BYTES = 0x00000010,
    /* the param holding the size is a pointer b/c it's an IN OUT var */
    SYSARG_LENGTH_INOUT     = 0x00000020,

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
    uint num; /* system call number: filled in dynamically */
    const char *name;
    int args_size; /* for Windows: total size of args; for Linux: arg count */
    /* list of args that are not inlined */
    syscall_arg_t arg[MAX_NONINLINED_ARGS];
} syscall_info_t;

extern syscall_info_t syscall_info[];

void
syscall_os_init(void *drcontext _IF_WINDOWS(app_pc ntdll_base));

void
syscall_os_exit(void);

syscall_info_t *
syscall_lookup(int num);

uint
get_sysparam_shadow_val(uint argnum, dr_mcontext_t *mc);

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

#ifdef VMX86_SERVER
void
vmkuw_syscall_init(void *drcontext);

bool
vmkuw_shared_pre_syscall(void *drcontext, int sysnum);

void
vmkuw_shared_post_syscall(void *drcontext, int sysnum);

bool
vmkuw_shadow_pre_syscall(void *drcontext, int sysnum);

void
vmkuw_shadow_post_syscall(void *drcontext, int sysnum);
#endif

#endif /* _SYSCALL_OS_H_ */
