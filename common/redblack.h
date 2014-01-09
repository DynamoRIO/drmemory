/* **********************************************************
 * Copyright (c) 2012 Google, Inc.  All rights reserved.
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

#ifndef _REDBLACK_H_
#define _REDBLACK_H_

/* Interval tree for address ranges implemented as a red-black binary tree.
 * Assumes that no intervals in the tree overlap and they are all
 * open at the upper end.
 */

#include "dr_api.h"

/* opaque structs */
struct _rb_node_t;
typedef struct _rb_node_t rb_node_t;

struct _rb_tree_t;
typedef struct _rb_tree_t rb_tree_t;

/* Synchronization is up to the caller.  A lock should be held from
 * the point of a call to any routine here to the last use of any
 * returned rb_node_t*.
 */

/* Allocate a new, empy tree.  free_payload_func, if non-null, will be called
 * to free the client field whenever a node is freed.
 */
rb_tree_t *
rb_tree_create(void (*free_payload_func)(void*));

/* Remove and free all nodes in the tree and free the tree itself */
void
rb_tree_destroy(rb_tree_t *tree);

/* Retrieve copies of fields.  The node pointer is then no longer needed. */
void
rb_node_fields(rb_node_t *node, byte **base OUT, size_t *size OUT, void **client OUT);

/* Modify the client field of a node. */
void
rb_node_set_client(rb_node_t *node, void *client);

/* Insert a node into the tree.  If an existing node overlaps with [base,base+size),
 * returns that node; else, adds a new node and returns NULL.
 */
rb_node_t *
rb_insert(rb_tree_t *tree, byte *base, size_t size, void *client);

/* Find the node with base 'base' */
rb_node_t *
rb_find(rb_tree_t *tree, byte *base);

/* Find the first node with client field == 'client' */
rb_node_t *
rb_find_client_node(rb_tree_t *tree, void *client);

/* Check if 'addr' is in the [base,base+size) of any node */
rb_node_t *
rb_in_node(rb_tree_t *tree, byte *addr);

/* Check if the range [start, end] overlaps with [base,base+size) of any node */
rb_node_t *
rb_overlaps_node(rb_tree_t *tree, byte *start, byte *end);

/* Finds the node [base,base+size) with smallest base such that base+size >= addr */
rb_node_t *
rb_next_higher_node(rb_tree_t *tree, byte *addr);

/* Finds the node [base,base+size) with largest base such that base <= addr */
rb_node_t *
rb_next_lower_node(rb_tree_t *tree, byte *addr);

/* Remove a node from the RB tree */
void
rb_delete(rb_tree_t *tree, rb_node_t *node);

/* Remove and free all nodes in the tree */
void
rb_clear(rb_tree_t *tree);

/* Returns node with highest base+size */
rb_node_t *
rb_max_node(rb_tree_t *tree);

/* Returns node with lowest base */
rb_node_t *
rb_min_node(rb_tree_t *tree);

/* Performs an in-order traversal, calling iter_cb on each node. */
void
rb_iterate(rb_tree_t *tree, bool (*iter_cb)(rb_node_t *, void *), void *iter_data);

#ifdef DEBUG_UNIT_TEST
void
rb_print(rb_tree_t *tree, char *filename);

bool
rb_check_tree(rb_tree_t *tree);
#endif

#endif /* _REDBLACK_H_ */
