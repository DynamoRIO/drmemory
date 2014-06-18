/* **********************************************************
 * Copyright (c) 2012-2014 Google, Inc.  All rights reserved.
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

/***************************************************************************
 * perturb.h: Dr. Memory app timing perturbation
 */

#ifndef _PERTURB_H_
#define _PERTURB_H_ 1

#include "drmgr.h"
#include "utils.h"

void
perturb_init(void);

void
perturb_exit(void);

#ifdef STATISTICS
void
perturb_dump_statistics(file_t f);
#endif

void
perturb_fork_init(void);

void
perturb_thread_init(void);

void
perturb_thread_exit(void);

void
perturb_module_load(void *drcontext, const module_data_t *info, bool loaded);

void
perturb_pre_fork(void);

bool
perturb_pre_syscall(void *drcontext, int sysnum);

void
perturb_instrument(void *drcontext, instrlist_t *bb, instr_t *inst);

#endif /* _PERTURB_H_ */
