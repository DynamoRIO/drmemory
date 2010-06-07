/* **********************************************************
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

/* Red-black tree implementation to store allocated regions and their
 * size.  Algorithm taken from the description in "Intro to
 * Algorithms" by CLR.
 */

#include "redblack.h"
#include "utils.h"
#include "per_thread.h"

typedef enum { RED, BLACK } rb_color;

struct _rb_node_t {
    rb_node_t *parent;
    rb_node_t *right;
    rb_node_t *left;
    rb_color color;
    /* the node key is the base */
    byte *base;
    size_t size;
    /* for efficiently finding nearest neighbors: max base+size of childen.
     * if our data sets weren't disjoint we would also need this for normal
     * lookups.
     */
    byte *max;
    /* custom data field */
    void *client;
};

/* Sentinel NIL node to mark leaves rather than NULL.  Simplifies
 * node deletion; see CLR.
 * Exported for users to use as static root node initial value.
 */
static rb_node_t NIL_node = {
    &NIL_node, /* parent */
    &NIL_node, /* right */
    &NIL_node, /* left */
    BLACK,     /* color */
    NULL,      /* base */
    0,         /* size */
    NULL,      /* max */
    NULL       /* client */
};

static rb_node_t *NIL = &NIL_node;

/* Data structure to wrap around the root node, to store global info
 * such as callback routines.
 */
struct _rb_tree_t {
    rb_node_t *root;
    void (*free_payload_func)(void*);
};

static inline byte *
ptrmax(byte *val1, byte *val2)
{
    return (val1 >= val2) ? val1 : val2;
}


/* Retrieve copies of fields.  The node pointer is then no longer needed. */
void
rb_node_fields(rb_node_t *node, byte **base OUT, size_t *size OUT, void **client OUT)
{
    ASSERT(node != NULL, "invalid param");
    ASSERT(node != NIL, "should not ask for fields of NIL!");
    if (base != NULL)
        *base = node->base;
    if (size != NULL)
        *size = node->size;
    if (client != NULL)
        *client = node->client;
}


/* Allocate a new node */
static rb_node_t *
rb_new_node(byte *base, size_t size, void *client)
{
    rb_node_t *node = (rb_node_t *) global_alloc(sizeof(rb_node_t), HEAPSTAT_RBTREE);
    ASSERT(node != NULL, "alloc failed");

    if (node != NULL) {
        node->parent = NIL;
        node->right = NIL;
        node->left = NIL;
        node->color = RED;
        node->base = base;
        node->size = size;
        node->max = NULL; /* filled in later */
        node->client = client;
    }

    return node;
}


/* Free a node */
static inline void
rb_free_node(rb_tree_t *tree, rb_node_t *node, bool free_payload)
{
    if (tree != NULL && free_payload && tree->free_payload_func != NULL)
        (tree->free_payload_func)(node->client);
    global_free(node, sizeof(rb_node_t), HEAPSTAT_RBTREE);
}


static void
rb_clear_helper(rb_tree_t *tree, rb_node_t *node)
{
    if (node != NIL) {
        rb_clear_helper(tree, node->left);
        rb_clear_helper(tree, node->right);
        rb_free_node(tree, node, true/*free payload*/);
    }
}

/* Free all nodes in the tree */
void
rb_clear(rb_tree_t *tree)
{
    rb_clear_helper(tree, tree->root);
    tree->root = NIL;
}


/* Find region with base 'base'.  Returns NULL if the region is not in
 * the tree.
 */
rb_node_t *
rb_find(rb_tree_t *tree, byte *base)
{
    rb_node_t *iter = tree->root;

    while (iter != NIL) {
        if (base == iter->base) {
            return iter;
        }
        else if (base < iter->base) {
            iter = iter->left;
        }
        else {
            iter = iter->right;
        }
    }

    return NULL;
}


static inline rb_node_t *
get_next_helper(void *client, rb_node_t *curr)
{
    rb_node_t *node;
    if (curr == NIL) {
        return NIL;
    }

    if (curr->client == client) {
        return curr;
    }
    
    node = get_next_helper(client, curr->left);
    if (node != NIL) {
        return node;
    }

    node = get_next_helper(client, curr->right);
    if (node != NIL) {
        return node;
    }

    return NIL;
}

/* Find the first node with client field == 'client' */
rb_node_t *
rb_find_client_node(rb_tree_t *tree, void *client)
{
    rb_node_t *node = get_next_helper(client, tree->root);
    if (node == NIL) {
        return NULL;
    }

    return node;
}


static void
rb_right_rotate(rb_node_t **root, rb_node_t *y)
{
    rb_node_t *x = y->left;

    y->left = x->right;
    if (x->right != NIL) {
        x->right->parent = y;
    }

    x->parent = y->parent;
    if (y->parent == NIL) {
        *root = x;
    }
    else if (y == y->parent->left) {
        y->parent->left = x;
    }
    else {
        y->parent->right = x;
    }

    x->right = y;
    y->parent = x;

    /* parent max did not change */
    y->max = ptrmax(y->left->max, y->right->max);
    x->max = ptrmax(x->left->max, y->max);
}


static void
rb_left_rotate(rb_node_t **root, rb_node_t *x)
{
    rb_node_t *y = x->right;

    x->right = y->left;
    if (y->left != NIL) {
        y->left->parent = x;
    }

    y->parent = x->parent;
    if (x->parent == NIL) {
        *root = y;
    }
    else if (x == x->parent->left) {
        x->parent->left = y;
    }
    else {
        x->parent->right = y;
    }

    y->left = x;
    x->parent = y;

    /* parent max did not change */
    x->max = ptrmax(x->left->max, x->right->max);
    y->max = ptrmax(x->max, y->right->max);
}


static inline void
rb_delete_fixup(rb_node_t **root, rb_node_t *x)
{
    while (x != *root && x->color == BLACK) {
        if (x == x->parent->left) {
            rb_node_t *w = x->parent->right;
            if (w->color == RED) {
                w->color = BLACK;
                x->parent->color = RED;
                rb_left_rotate(root, x->parent);
                w = x->parent->right;
            }
            if (w->left->color == BLACK && w->right->color == BLACK) {
                w->color = RED;
                x = x->parent;
            }
            else {
                if (w->right->color == BLACK) {
                    w->left->color = BLACK;
                    w->color = RED;
                    rb_right_rotate(root, w);
                    w = x->parent->right;
                }
                w->color = x->parent->color;
                x->parent->color = BLACK;
                w->right->color = BLACK;
                rb_left_rotate(root, x->parent);
                x = *root;
            }
        }
        else {
            rb_node_t *w = x->parent->left;
            if (w->color == RED) {
                w->color = BLACK;
                x->parent->color = RED;
                rb_right_rotate(root, x->parent);
                w = x->parent->left;
            }
            if (w->right->color == BLACK && w->left->color == BLACK) {
                w->color = RED;
                x = x->parent;
            }
            else {
                if (w->left->color == BLACK) {
                    w->right->color = BLACK;
                    w->color = RED;
                    rb_left_rotate(root, w);
                    w = x->parent->left;
                }
                w->color = x->parent->color;
                x->parent->color = BLACK;
                w->left->color = BLACK;
                rb_right_rotate(root, x->parent);
                x = *root;
            }
        }
    }

    x->color = BLACK;
}


/* Find immediate successor of node 'x' */
static inline rb_node_t *
rb_successor(rb_node_t *x)
{
    if (x->right != NIL) {
        x = x->right;
        while (x->left != NIL) {
            x = x->left;
        }
        return x;
    }
    else {
        rb_node_t *y = x->parent;
        while (y != NIL && x == y->right) {
            x = y;
            y = y->parent;
        }
        return y;
    }
}
    

/* Remove a node from the RB tree */
void
rb_delete(rb_tree_t *tree, rb_node_t *z)
{
    rb_node_t *y, *x;
    void *client_tmp;

    if (z->left == NIL || z->right == NIL) {
        y = z;
    }
    else {
        y = rb_successor(z);
    }

    x = (y->left != NIL) ? y->left : y->right;
    x->parent = y->parent;

    if (y->parent == NIL) {
        tree->root = x;
    }
    else if (y == y->parent->left) {
        y->parent->left = x;
    }
    else {
        y->parent->right = x;
    }

    if (y != z) {
        /* y's contents are being moved into z's node */
        client_tmp = z->client;
        z->base = y->base;
        z->size = y->size;
        z->client = y->client;
        z->max = y->max;
        y->client = client_tmp;
    }

    if (y->color == BLACK) {
        rb_delete_fixup(&tree->root, x);
    }

    rb_free_node(tree, y, true/*free payload*/);
}


/* Binary tree insertion.  First step when inserting a node into 
 * an RB tree.
 */
static rb_node_t *
bt_insert(rb_node_t **root, rb_node_t *node)
{
    rb_node_t *iter = NIL;
    rb_node_t **p_iter = root;

    byte *nbase = node->base;
#ifdef DEBUG
    byte *nlast = nbase + node->size;
#endif

    while (*p_iter != NIL) {
        byte *ibase;
#ifdef DEBUG
        byte *ilast;
#endif
        iter = *p_iter;
        ibase = iter->base;
#ifdef DEBUG        
        ilast = ibase + iter->size;
        if ((ibase >= nbase && ibase < nlast) ||
            (nbase >= ibase && nbase < ilast)) {
            return iter;
        }
#else
        if (nbase == ibase) {
            return iter;
        }
#endif
        else if (nbase < ibase) {
            p_iter = &(iter->left);
        }
        else {
            p_iter = &(iter->right);
        }
    }

    *p_iter = node;
    node->parent = iter;

    /* successful insertion */
    return NULL;
}


/* Insert node 'x' into the RB tree. */
static rb_node_t *
rb_insert_helper(rb_node_t **root, rb_node_t *x)
{
    rb_node_t *node = bt_insert(root, x);
    if (node != NULL) {
        /* the new node overlaps with an existing node */
        return node;
    }

    while (x != *root && x->parent->color == RED) {
        if (x->parent == x->parent->parent->left) {
            rb_node_t *y = x->parent->parent->right;
            if (y != NIL && y->color == RED) {
                x->parent->color = BLACK;
                y->color = BLACK;
                x->parent->parent->color = RED;
                x = x->parent->parent;
            }
            else {
                if (x == x->parent->right) {
                    x = x->parent;
                    rb_left_rotate(root, x);
                }
                x->parent->color = BLACK;
                x->parent->parent->color = RED;
                rb_right_rotate(root, x->parent->parent);
            }
        }
        else {
            rb_node_t *y = x->parent->parent->left;
            if (y != NIL && y->color == RED) {
                x->parent->color = BLACK;
                y->color = BLACK;
                x->parent->parent->color = RED;
                x = x->parent->parent;
            }
            else {
                if (x == x->parent->left) {
                    x = x->parent;
                    rb_right_rotate(root, x);
                }
                x->parent->color = BLACK;
                x->parent->parent->color = RED;
                rb_left_rotate(root, x->parent->parent);
            }
        }
    }

    (*root)->color = BLACK;
    return NULL;
}

/* Insert a node into the tree.  If an existing node overlaps with [base,base+size),
 * returns that node; else, adds a new node and returns NULL.
 */
rb_node_t *
rb_insert(rb_tree_t *tree, byte *base, size_t size, void *client)
{
    rb_node_t *node = rb_new_node(base, size, client);
    rb_node_t *existing = rb_insert_helper(&tree->root, node);
    if (existing != NULL)
        rb_free_node(tree, node, false/*do not free payload*/);
    return existing;
}

/* Check if 'addr' is in the [base,base+size) of any node */
rb_node_t *
rb_in_node(rb_tree_t *tree, byte *addr)
{
    rb_node_t *iter = tree->root;

    while (iter != NIL) {
        byte *base = iter->base;
        byte *last = base + iter->size;

        if (addr >= base && addr < last) {
            return iter;
        }
        else if (addr < base) {
            iter = iter->left;
        }
        else {
            ASSERT(addr >= last, "rbtree inconsistent");
            iter = iter->right;
        }
    }

    return NULL;
}


/* Check if the range [start, end) overlaps with [base,base+size) of any node */
rb_node_t *
rb_overlaps_node(rb_tree_t *tree, byte *start, byte *end)
{
    rb_node_t *iter = tree->root;

    while (iter != NIL) {
        byte *base = iter->base;
        byte *last = base + iter->size;

        if (start < last && end > base) {
            return iter;
        }
        else if (end <= base) {
            iter = iter->left;
        }
        else {
            ASSERT(start >= last, "rbtree inconsistent");
            iter = iter->right;
        }
    }

    return NULL;
}

/* Finds the node [base,base+size) with smallest base such that base+size >= addr */
rb_node_t *
rb_next_higher_node(rb_tree_t *tree, byte *addr)
{
    rb_node_t *iter = tree->root;
    while (iter != NIL) {
        if (addr >= iter->left->max && addr < iter->base + iter->size) {
            return iter;
        } 
        else if (addr >= iter->right->max) {
            return NULL;
        } 
        else if (addr < iter->base) {
            iter = iter->left;
        }
        else {
            ASSERT(addr >= iter->base + iter->size, "rbtree inconsistent");
            iter = iter->right;
        }
    }
    return NULL;
}

/* Finds the node [base,base+size) with largest base such that base <= addr */
rb_node_t *
rb_next_lower_node(rb_tree_t *tree, byte *addr)
{
    rb_node_t *iter = tree->root;
    while (iter != NIL) {
        if (addr >= iter->base && (iter->right == NIL || addr < iter->right->base)) {
            return iter;
        } 
        else if (addr < iter->base) {
            iter = iter->left;
        }
        else {
            ASSERT(addr >= iter->base + iter->size, "rbtree inconsistent");
            iter = iter->right;
        }
    }
    return NULL;
}

/* Returns node with highest base+size */
rb_node_t *
rb_max_node(rb_tree_t *tree)
{
    rb_node_t *iter = tree->root;
    if (iter != NIL) {
        while (iter->right != NIL)
            iter = iter->right;
    }
    return iter;
}

/* Returns node with lowest base */
rb_node_t *
rb_min_node(rb_tree_t *tree)
{
    rb_node_t *iter = tree->root;
    if (iter != NIL) {
        while (iter->left != NIL)
            iter = iter->left;
    }
    return iter;
}


rb_tree_t *
rb_tree_create(void (*free_payload_func)(void*))
{
    rb_tree_t *tree = global_alloc(sizeof(*tree), HEAPSTAT_RBTREE);
    tree->root = &NIL_node;
    tree->free_payload_func = free_payload_func;
    return tree;
}

void
rb_tree_destroy(rb_tree_t *tree)
{
    ASSERT(tree != NULL, "invalid params");
    rb_clear(tree);
    global_free(tree, sizeof(*tree), HEAPSTAT_RBTREE);
}

static void
iterate_helper(rb_node_t *node, void (*iter_cb)(rb_node_t *, void *), void *iter_data)
{
    ASSERT(node != NULL && node != NIL && iter_cb != NULL, "invalid params");
    if (node->left != NIL)
        iterate_helper(node->left, iter_cb, iter_data);
    iter_cb(node, iter_data);
    if (node->right != NIL)
        iterate_helper(node->right, iter_cb, iter_data);
}

/* Performs an in-order traversal, calling iter_cb on each node. */
void
rb_iterate(rb_tree_t *tree, void (*iter_cb)(rb_node_t *, void *), void *iter_data)
{
    ASSERT(tree != NULL && iter_cb != NULL, "invalid params");
    iterate_helper(tree->root, iter_cb, iter_data);
}

/***************************************************************************/
#ifdef DEBUG_UNIT_TEST

static void
print_helper(rb_node_t *node, FILE *fp)
{
    fprintf(fp, "n%d [label = \"%s %d\"]\n", 
            node->base,
            node->color == RED ? "R" : "B",
            node->base);

    if (node->left != NIL) {
        fprintf(fp, "  n%d -> n%d\n", node->base, node->left->base);
        print_helper(node->left, fp);
    }

    if (node->right != NIL) {
        fprintf(fp, "  n%d -> n%d\n", node->base, node->right->base);        
        print_helper(node->right, fp);
    }
}


void
rb_print(rb_tree_t *tree, char *filename)
{
    FILE *fp = fopen(filename, "w");
    if (fp == NULL) {
        fprintf(stderr, "ERROR: can't open %s\n", filename);
    }

    fprintf(fp, "digraph g {\n");
    if (root != NIL) {
        print_helper(tree->root, fp);
    }
    fprintf(fp, "}\n");

    fclose(fp);
}


static void
rb_check_node(rb_node_t *node, int *black, byte **max, byte **min, bool *ret)
{
    byte *left_max, *left_min, *right_max, *right_min;
    int left_black, right_black;

    if (node == NIL) {
        *black = 1;
        return;
    }

    /* check the red-black invariant */
    if (node->color == RED) {
        if ((node->left != NIL && node->left->color != BLACK) ||
            (node->right != NIL && node->right->color != BLACK)) {
            *ret = false;
        }
    }

    /* gather info for left and right subtrees */
    rb_check_node(node->left, &left_black, &left_max, &left_min, ret);
    rb_check_node(node->right, &right_black, &right_max, &right_min, ret);

    /* check binary-tree integrity */
    if (node->right == NIL) {
        *max = node->base;
    }
    else {
        *max = right_max;
        if (right_min <= node->base) {
            *ret = false;
        }
    }

    if (node->left == NIL) {
        *min = node->base;
    }
    else {
        *min = left_min;
        if (left_max >= node->base) {
            *ret = false;
        }
    }

    /* 'black' should be the same on both subtrees */
    if (left_black != right_black) {
        *ret = false;
    }

    *black = left_black + (node->color == BLACK) ? 1 : 0;
}


bool
rb_check_tree(rb_tree_t *tree)
{
    bool ret = true;
    int black;
    byte *max, *min;
    rb_check_node(tree->root, &black, &max, &min, &ret);
    return ret;
}

#endif /* DEBUG_UNIT_TEST */
/***************************************************************************/
