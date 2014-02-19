/* **********************************************************
 * Copyright (c) 2014 Google, Inc.  All rights reserved.
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

#include "dr_api.h"
#include "drmemory.h"
#include "syscall.h"
#include "syscall_os.h"

#include <sys/syscall.h>

/***************************************************************************
 * SYSTEM CALLS FOR MAC
 */

void
syscall_os_init(void *drcontext)
{
}

void
syscall_os_exit(void)
{
}

void
syscall_os_thread_init(void *drcontext)
{
}

void
syscall_os_thread_exit(void *drcontext)
{
}

void
syscall_os_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
}

/***************************************************************************
 * PER-SYSCALL HANDLING
 */

bool
os_process_syscall_memarg(drsys_arg_t *arg)
{
    return false; /* not handled */
}

/* for tasks unrelated to shadowing that are common to all tools */
bool
os_shared_pre_syscall(void *drcontext, cls_syscall_t *pt, drsys_sysnum_t sysnum,
                      dr_mcontext_t *mc, drsys_syscall_t *syscall)
{
    bool res = true;
    switch (sysnum.number) {
        /* FIXME i#1438: handle thread creation stack, etc. */
    }
    return res;
}

/* for tasks unrelated to shadowing that are common to all tools */
void
os_shared_post_syscall(void *drcontext, cls_syscall_t *pt, drsys_sysnum_t sysnum,
                       dr_mcontext_t *mc, drsys_syscall_t *syscall)
{
    switch (sysnum.number) {
        /* FIXME i#1438: handle thread creation stack, etc. */
    }
}

