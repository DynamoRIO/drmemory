/* **********************************************************
 * Copyright (c) 2011-2012 Google, Inc.  All rights reserved.
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

#ifndef _SYSCALL_WINDOWS_H_
#define _SYSCALL_WINDOWS_H_ 1

/* syscall_windows.c exports */

extern hashtable_t systable; /* windows num-to-sysinfo table */


/* syscall_wingdi.c exports */

void
syscall_wingdi_init(void *drcontext, app_pc ntdll_base);

void
syscall_wingdi_exit(void);

bool
wingdi_shared_process_syscall(bool pre, void *drcontext, drsys_sysnum_t sysnum,
                              cls_syscall_t *pt, dr_mcontext_t *mc,
                              drsys_syscall_t *syscall);

bool
wingdi_process_syscall_arg(drsys_arg_t *arg);


#endif /* _SYSCALL_WINDOWS_H_ */
