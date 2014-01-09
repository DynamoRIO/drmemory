/* **********************************************************
 * Copyright (c) 2010-2013 Google, Inc.  All rights reserved.
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

extern int cls_idx_syscall;

typedef struct _cls_syscall_t {
    /* Saves syscall params across syscall */
    void *sysaux_params;

#ifdef WINDOWS
    /* for GDI checks (i#752) */
    HDC paintDC;
    /* for handle leak checks (i#974) */
    void *handle_info;
#endif
} cls_syscall_t;

void
syscall_os_init(void *drcontext _IF_WINDOWS(app_pc ntdll_base));

void
syscall_os_exit(void);

void
syscall_os_thread_init(void *drcontext);

void
syscall_os_thread_exit(void *drcontext);

void
syscall_os_module_load(void *drcontext, const module_data_t *info, bool loaded);

/* for tasks unrelated to shadowing that are common to all tools */
bool
os_shared_pre_syscall(void *drcontext, cls_syscall_t *pt, drsys_sysnum_t sysnum,
                      dr_mcontext_t *mc, drsys_syscall_t *syscall);

void
os_shared_post_syscall(void *drcontext, cls_syscall_t *pt, drsys_sysnum_t sysnum,
                       dr_mcontext_t *mc, drsys_syscall_t *syscall);

bool
os_process_syscall_memarg(drsys_arg_t *arg);

#endif /* _SYSCALL_OS_H_ */
