/* **********************************************************
 * Copyright (c) 2012-2014 Google, Inc.  All rights reserved.
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
 * leak.h: leak scanning
 */

#ifndef _LEAK_H_
#define _LEAK_H_ 1

#include "drmgr.h"

#ifdef STATISTICS
extern uint midchunk_postsize_ptrs;
extern uint midchunk_postnew_ptrs;
extern uint midchunk_postinheritance_ptrs;
extern uint midchunk_string_ptrs;
extern uint strings_not_pointers;
# ifdef WINDOWS
extern uint pointers_encoded;
extern uint encoded_pointers_scanned;
# endif
#endif

/**************************/
/* Must be provided by client */

void
client_found_leak(app_pc start, app_pc end, size_t indirect_bytes,
                  bool pre_us, bool reachable,
                  bool maybe_reachable, void *client_data,
                  bool count_reachable, bool show_reachable);

/**************************/
/* Must be called by client */

void
leak_init(bool have_defined_info,
          bool check_leaks_on_destroy,
          bool midchunk_new_ok,
          bool midchunk_inheritance_ok,
          bool midchunk_string_ok,
          bool midchunk_size_ok,
          bool show_reachable,
          IF_WINDOWS_(bool check_encoded_pointers)
          byte *(*next_defined_ptrsz)(byte *, byte *),
          byte *(*end_of_defined_region)(byte *, byte *),
          bool (*is_register_defined)(void *, reg_id_t));
void
leak_exit();

void
leak_module_load(void *drcontext, const module_data_t *info, bool loaded);

void
leak_module_unload(void *drcontext, const module_data_t *info);

void
leak_scan_for_leaks(bool at_exit);

/* User must call from client_handle_malloc() and client_handle_realloc() */
void
leak_handle_alloc(void *drcontext, app_pc base, size_t size);

#ifdef WINDOWS
/* User must call from client_remove_malloc_on_destroy() */
void
leak_remove_malloc_on_destroy(HANDLE heap, byte *start, byte *end);
#endif

#endif /* _LEAK_H_ */
