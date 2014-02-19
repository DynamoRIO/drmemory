/* **********************************************************
 * Copyright (c) 2011-2012 Google, Inc.  All rights reserved.
 * Copyright (c) 2009-2010 VMware, Inc.  All rights reserved.
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

#ifndef _DRHEAPSTAT_H_
#define _DRHEAPSTAT_H_ 1

#include "drmgr.h"
#include "utils.h"
#include "../drmemory/options.h"

/***************************************************************************
 * DATA SHARED ACROSS MODULES
 */

extern file_t f_callstack;
extern file_t f_snapshot;
extern file_t f_staleness;

#ifdef STATISTICS
extern uint num_mallocs;
extern uint num_frees;
extern uint alloc_stack_count;
extern uint heap_regions;
#endif /* STATISTICS */

#ifdef UNIX
/* for strchr in linux, which will bring in libc: FIXME */
# include <string.h>
#endif /* UNIX */

struct _per_callstack_t;
typedef struct _per_callstack_t per_callstack_t;

uint
get_cstack_id(per_callstack_t *per);

#endif /* _DRHEAPSTAT_H_ */
