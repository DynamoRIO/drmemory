/* **********************************************************
 * Copyright (c) 2012-2014 Google, Inc.  All rights reserved.
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

/* Windows Kernel Handle Leak Checks */

#ifndef _HANDLECHECK_H_
#define _HANDLECHECK_H_

#include "dr_api.h"
#include "windefs.h"
#include "drsyscall.h"

enum {
    HANDLE_TYPE_KERNEL,
    HANDLE_TYPE_GDI,
    HANDLE_TYPE_USER,
};

void
handlecheck_init(void);

void
handlecheck_exit(void);

void
handlecheck_create_handle(void *drcontext,
                          HANDLE proc_handle, HANDLE handle, int type,
                          drsys_sysnum_t sysnum, app_pc pc, dr_mcontext_t *mc);

void *
handlecheck_delete_handle(void *drcontext,
                          HANDLE proc_handle, HANDLE handle, int type,
                          drsys_sysnum_t sysnum, app_pc pc, dr_mcontext_t *mc);

void
handlecheck_delete_handle_post_syscall(void *drcontext, HANDLE handle,
				       drsys_sysnum_t sysnum, dr_mcontext_t *mc,
                                       int type, void *handle_info,
                                       bool success);

void
handlecheck_report_leak_on_syscall(dr_mcontext_t *mc, drsys_arg_t *arg,
                                   HANDLE proc_handle);

#ifdef STATISTICS
void
handlecheck_dump_statistics(file_t f);
#endif /* STATISTICS */

void
handlecheck_nudge(void *drcontext);

#endif /* _HANDLECHECK_H_ */
