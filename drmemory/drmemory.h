/* **********************************************************
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

#ifndef _DRMEMORY_H_
#define _DRMEMORY_H_ 1

#include "per_thread.h"
#include "client_per_thread.h"
#include "options.h"
#include "utils.h"

/***************************************************************************
 * PARAMETERS
 */

extern client_id_t client_id;

/***************************************************************************
 * DATA SHARED ACROSS MODULES
 */

extern char logsubdir[MAXIMUM_PATH];

extern file_t f_fork;

#ifdef LINUX
/* PR 424847: prevent app from closing our logfiles */
extern hashtable_t logfile_table;
#endif

#ifdef USE_DRSYMS
extern file_t f_results;
extern file_t f_suppress;
#endif

#ifdef WINDOWS
extern app_pc ntdll_base;
extern app_pc ntdll_end;
#else
extern app_pc libc_base;
extern app_pc libc_end;
#endif
extern app_pc app_base;
extern app_pc app_end;

#ifdef STATISTICS
void 
dump_statistics(void);

extern uint num_nudges;
#endif /* STATISTICS */

#ifdef LINUX

/* for strchr in linux, which will bring in libc: FIXME */
# include <string.h>

bool
is_in_client_or_DR_lib(app_pc pc);

#endif /* LINUX */

/* We can't get app xsp at init time so we call this on 1st bb */
void
set_initial_layout(void);

byte *
mmap_walk(app_pc start, size_t size,
          IF_WINDOWS_(MEMORY_BASIC_INFORMATION *mbi_start) bool add);

#ifdef WINDOWS
void
set_teb_initial_shadow(TEB *teb);
#endif

#endif /* _DRMEMORY_H_ */
