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

#ifndef _SYSCALL_H_
#define _SYSCALL_H_ 1

#ifdef WINDOWS
# define KUSER_SHARED_DATA_START 0x7ffe0000
#endif

void
syscall_init(void *drcontext _IF_WINDOWS(app_pc ntdll_base));

void
syscall_exit(void);

void
syscall_thread_init(void *drcontext);

void
syscall_thread_exit(void *drcontext, per_thread_t *pt);

void
syscall_reset_per_thread(void *drcontext, per_thread_t *pt);

bool
is_using_sysenter(void);

bool
is_using_sysint(void);

void
check_syscall_gateway(instr_t *inst);

#ifdef WINDOWS
/* The size, from the vsyscall start, that should be considered
 * "defined".  We size it big enough to cover both stored pc and
 * an actual code sequence.  FIXME: best to size to the actual
 * setup in use.  FIXME: is entire KUSER_SHARED_DATA page defined?
 */
# define VSYSCALL_SIZE 5
#endif

byte *
vsyscall_pc(void *drcontext, byte *entry);

const char *
get_syscall_name(uint num);

#ifdef STATISTICS
# ifdef WINDOWS
/* cover win32k.sys and ntoskrnl calls */
#  define MAX_SYSNUM 5000
# else
/* vmkernel has extra syscalls beyond linux */
#  define MAX_SYSNUM 1400
# endif
extern int syscall_invoked[MAX_SYSNUM];
#endif

void
check_sysmem(uint flags, int sysnum, app_pc ptr, size_t sz, dr_mcontext_t *mc,
             const char *id);

byte *
syscall_auxlib_start(void);

byte *
syscall_auxlib_end(void);

#endif /* _SYSCALL_H_ */
