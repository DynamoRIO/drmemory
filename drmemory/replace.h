/* **********************************************************
 * Copyright (c) 2010-2012 Google, Inc.  All rights reserved.
 * Copyright (c) 2008-2009 VMware, Inc.  All rights reserved.
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
 * replace.h: Dr. Memory str* and mem* replacement
 */

#ifndef _REPLACE_H_
#define _REPLACE_H_ 1

void
replace_init(void);

void
replace_exit(void);

void
replace_module_load(void *drcontext, const module_data_t *info, bool loaded);

void
replace_module_unload(void *drcontext, const module_data_t *info);

bool
in_replace_routine(app_pc pc);

bool
in_replace_memset(app_pc pc);

#endif /* _REPLACE_H_ */
