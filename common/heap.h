/* **********************************************************
 * Copyright (c) 2011-2013 Google, Inc.  All rights reserved.
 * Copyright (c) 2007-2009 VMware, Inc.  All rights reserved.
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

#ifndef _HEAP_H_
#define _HEAP_H_ 1

/***************************************************************************
 * UTILS
 */

size_t
allocation_size(app_pc start, app_pc *base);

#ifdef LINUX
app_pc
get_heap_start(void);
#endif

#ifdef WINDOWS
app_pc
get_ntdll_base(void);
#endif

app_pc
get_libc_base(app_pc *libc_end OUT);

bool
pc_is_in_libc(app_pc pc);

app_pc
get_libcpp_base(void);

/***************************************************************************
 * HEAP WALK
 */

/* Walks the heap and calls the "cb_region" callback for each heap region or arena
 * and the "cb_chunk" callback for each malloc block.
 */
void
heap_iterator(void (*cb_region)(app_pc start, app_pc end _IF_WINDOWS(HANDLE handle)),
              void (*cb_chunk)(app_pc start, app_pc end)
              _IF_WINDOWS(void (*cb_heap)(HANDLE)));

#ifdef WINDOWS
/* Returns the end of the last valid chunk seen.
 * If there are sub-regions, this will be in the final sub-region seen.
 */
byte *
heap_allocated_end(HANDLE heap);
#endif

/***************************************************************************
 * HEAP REGION LIST
 */

#ifdef STATISTICS
extern uint heap_regions;
#endif

enum {
    HEAP_PRE_US   = 0x01,
    HEAP_ARENA    = 0x02,
    HEAP_MMAP     = 0x04,
};

void
heap_region_init(void (*region_add_cb)(app_pc, app_pc, dr_mcontext_t *mc),
                 void (*region_remove_cb)(app_pc, app_pc, dr_mcontext_t *mc));

void
heap_region_exit(void);

void
heap_region_add(app_pc start, app_pc end, uint flags, dr_mcontext_t *mc);

bool
heap_region_remove(app_pc start, app_pc end, dr_mcontext_t *mc);

bool
heap_region_adjust(app_pc base, app_pc new_end);

bool
heap_region_bounds(app_pc pc, app_pc *start_out/*OPTIONAL*/,
                   app_pc *end_out/*OPTIONAL*/, uint *flags_out/*OPTIONAL*/);

bool
is_in_heap_region(app_pc pc);

bool
is_entirely_in_heap_region(app_pc start, app_pc end);

uint
get_heap_region_flags(app_pc pc);

#ifdef WINDOWS
bool
heap_region_set_heap(app_pc pc, HANDLE heap);

HANDLE
heap_region_get_heap(app_pc pc);

#endif /* WINDOWS */

void
heap_region_iterate(bool (*iter_cb)(byte *start, byte *end, uint flags
                                    _IF_WINDOWS(HANDLE heap), void *data),
                    void *data);

#endif /* _HEAP_H_ */
