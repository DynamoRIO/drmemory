/* **********************************************************
 * Copyright (c) 2012 Google, Inc.  All rights reserved.
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
 * alloc_private.h: Dr. Memory heap tracking internal header
 */

#ifndef _ALLOC_PRIVATE_H_
#define _ALLOC_PRIVATE_H_ 1

extern alloc_options_t alloc_ops;

/***************************************************************************
 * Large malloc tree
 */

/* PR 525807: to handle malloc-based stacks we need an interval tree
 * for large mallocs.  Putting all mallocs in a tree instead of a table
 * is too expensive (PR 535568).
 */
#define LARGE_MALLOC_MIN_SIZE 12*1024

void
malloc_large_add(byte *start, size_t size);

void
malloc_large_remove(byte *start);

void
malloc_large_iterate(bool (*iter_cb)(byte *start, size_t size, void *data),
                     void *iter_data);

#endif /* _ALLOC_PRIVATE_H_ */
