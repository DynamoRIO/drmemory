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

void
syscall_wingdi_init(void *drcontext, app_pc ntdll_base, dr_os_version_info_t *ver);

void
syscall_wingdi_exit(void);

void
syscall_wingdi_user32_load(void *drcontext, const module_data_t *info);


extern hashtable_t systable; /* windows num-to-sysinfo table */

#endif /* _SYSCALL_WINDOWS_H_ */
