/* **********************************************************
 * Copyright (c) 2011-2015 Google, Inc.  All rights reserved.
 * Copyright (c) 2008-2010 VMware, Inc.  All rights reserved.
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
 * fastpath_arch.h: declarations shared between neutral and arch-specific code
 */

#ifndef _FASTPATH_ARCH_H_
#define _FASTPATH_ARCH_H_ 1

#include "dr_api.h"
#include "fastpath.h"

instr_t *
restore_mcontext_on_shadow_fault(void *drcontext,
                                 dr_mcontext_t *raw_mc, dr_mcontext_t *mc,
                                 byte *pc_post_fault, bb_saved_info_t *save);

bool
handle_slowpath_fault(void *drcontext, dr_mcontext_t *raw_mc, dr_mcontext_t *mc,
                      void *tag);

#endif /* _FASTPATH_ARCH_H_ */
