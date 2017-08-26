/* **********************************************************
 * Copyright (c) 2011-2017 Google, Inc.  All rights reserved.
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

#include "dr_api.h"
#include "drwrap.h"
#include "drmemory.h"
#include "utils.h"
#include "leak.h"
#include "alloc.h"
#include "heap.h"
#include "redblack.h"
#ifdef TOOL_DR_MEMORY
# include "shadow.h"
#endif

/***************************************************************************
 * REACHABILITY-BASED LEAK DETECTION
 */

/* We claim 4 of the malloc table's client flags */
enum {
    MALLOC_IGNORE_LEAK  = MALLOC_CLIENT_1,
    MALLOC_REACHABLE    = MALLOC_CLIENT_2,
    /* Reachable via a mid-chunk pointer (PR 476482) */
    MALLOC_MAYBE_REACHABLE = MALLOC_CLIENT_3,
    /* Indirect leak (PR 576032) */
    MALLOC_INDIRECTLY_REACHABLE = MALLOC_CLIENT_4,
};

/* the lowest possbile pointer value */
#ifdef WINDOWS
# define LOWEST_POINTER ((byte *)(16*PAGE_SIZE))
#else
# define LOWEST_POINTER ((byte *)(PAGE_SIZE))
#endif

/* For queueing up regions to scan */
typedef struct _pc_entry_t {
    app_pc start;
    app_pc end;
    struct _pc_entry_t *next;
} pc_entry_t;

static void
queue_add(pc_entry_t **head, pc_entry_t **tail, pc_entry_t *add)
{
    ASSERT(head != NULL && tail != NULL && add != NULL, "invalid args");
    if (*tail == NULL) {
        ASSERT(*head == NULL, "inconsistent list");
        *head = add;
        *tail = add;
    } else {
        ASSERT((*tail)->next == NULL, "inconsistent list tail");
        (*tail)->next = add;
        *tail = add;
    }
}

/* For passing shared data to helper routines */
typedef struct _reachability_data_t {
    /* The primary scans find chunks whose head is reachable.
     * Secondary scans find chunks reachable via mid-chunk pointers.
     */
    bool primary_scan;
    bool first_of_2_iters;
    bool last_of_2_iters;
    /* Queue of reachable malloc chunks */
    pc_entry_t *reachq_head;
    pc_entry_t *reachq_tail;
    /* Queue of reachable-through-mid-chunk-pointer malloc chunks.
     * Anything whose first reach is through a mid-chunk pointer
     * from the root, regardless of whether later points are to heads,
     * falls into this queue (PR 476482).
     */
    pc_entry_t *midreachq_head;
    pc_entry_t *midreachq_tail;
    /* Tree for interval lookup to find head given mid-chunk pointer */
    rb_tree_t *alloc_tree;
    /* Tree for storing beyond-TOS ranges for -leaks_only */
    rb_tree_t *stack_tree;
    /* Lowest possible pointer value */
    byte *low_ptr;
} reachability_data_t;

#ifdef STATISTICS
uint midchunk_postsize_ptrs;
uint midchunk_postnew_ptrs;
uint midchunk_postinheritance_ptrs;
uint midchunk_string_ptrs;
uint strings_not_pointers;
# ifdef WINDOWS
uint pointers_encoded;
uint encoded_pointers_scanned;
# endif
#endif

/* FIXME PR 487993: switch to file-private sets of options and option parsing */
static bool op_have_defined_info;
static bool op_check_leaks_on_destroy;
static bool op_midchunk_new_ok;
static bool op_midchunk_inheritance_ok;
static bool op_midchunk_string_ok;
static bool op_midchunk_size_ok;
static bool op_show_reachable;
#ifdef WINDOWS
static bool op_check_encoded_pointers;
#endif
static byte *(*cb_next_defined_ptrsz)(byte *, byte *);
static byte *(*cb_end_of_defined_region)(byte *, byte *);
static bool (*cb_is_register_defined)(void *, reg_id_t);

#ifdef WINDOWS
/* RtlHeap stores failed alloc info which can hide leaks (i#292) */
static app_pc rtl_fail_info;
/* heap chunk pointer stored at offset 0x10, data struct is 0x20 */
#define RTL_FAIL_INFO_SIZE 0x20

/* We track encoded pointers to avoid false positive leaks (i#153) */
# define ENCODED_PTR_TABLE_HASH_BITS 6
/* Key is encoded address.  Value is decoded address plus
 * ENCODED_PTR_SHIFT, which is required because NULL, -1, and 1 (== SIG_IGN:
 * i#1065) are all deliberately encoded.
 */
#define ENCODED_PTR_SHIFT 42
static hashtable_t encoded_ptr_table;
/* Rtl routines we intercept */
static app_pc rtl_encode_ptr;
static app_pc rtl_encode_sysptr;
static void leak_wrap_pre_encode_ptr(void *wrapcxt, void OUT **user_data);
static void leak_wrap_post_encode_ptr(void *wrapcxt, void *user_data);
/* i#1276: handle VS2012 Concurrency::details::Security::EncodePointer */
static app_pc crt_encode_ptr;
#endif

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
          bool (*is_register_defined)(void *, reg_id_t))
{
#ifdef WINDOWS
    module_data_t *mod;
#endif

    op_have_defined_info = have_defined_info;
    op_check_leaks_on_destroy = check_leaks_on_destroy;
    op_midchunk_new_ok = midchunk_new_ok;
    op_midchunk_inheritance_ok = midchunk_inheritance_ok;
    op_midchunk_string_ok = midchunk_string_ok;
    op_midchunk_size_ok = midchunk_size_ok;
    op_show_reachable = show_reachable;
#ifdef WINDOWS
    op_check_encoded_pointers = check_encoded_pointers;
#endif
    if (op_have_defined_info) {
        ASSERT(next_defined_ptrsz != NULL, "defined info needs cbs");
        ASSERT(end_of_defined_region != NULL, "defined info needs cbs");
        ASSERT(is_register_defined != NULL, "defined info needs cbs");
        cb_next_defined_ptrsz = next_defined_ptrsz;
        cb_end_of_defined_region = end_of_defined_region;
        cb_is_register_defined = is_register_defined;
    }

#ifdef WINDOWS
    if (op_check_encoded_pointers) {
        hashtable_init(&encoded_ptr_table, ENCODED_PTR_TABLE_HASH_BITS,
                       HASH_INTPTR, false/*!strdup*/);
    }
    mod = dr_lookup_module_by_name("ntdll.dll");
    if (mod != NULL) {
# ifdef USE_DRSYMS
        rtl_fail_info = lookup_internal_symbol(mod, "RtlpHeapFailureInfo");
        LOG(1, "RtlpHeapFailureInfo is "PFX"\n", rtl_fail_info);
# endif
        if (op_check_encoded_pointers) {
            rtl_encode_ptr = (app_pc)
                dr_get_proc_address(mod->handle, "RtlEncodePointer");
            rtl_encode_sysptr = (app_pc)
                dr_get_proc_address(mod->handle, "RtlEncodeSystemPointer");
            if ((rtl_encode_ptr != NULL &&
                 !drwrap_wrap(rtl_encode_ptr, leak_wrap_pre_encode_ptr,
                              leak_wrap_post_encode_ptr)) ||
                (rtl_encode_sysptr != NULL &&
                 !drwrap_wrap(rtl_encode_sysptr, leak_wrap_pre_encode_ptr,
                              leak_wrap_post_encode_ptr)))
                ASSERT(false, "failed to wrap encoded ptr routines");
        }

        dr_free_module_data(mod);
    } else
        ASSERT(false, "can't find ntdll");
#endif
}

void
leak_exit(void)
{
#ifdef WINDOWS
    if (op_check_encoded_pointers) {
        hashtable_delete_with_stats(&encoded_ptr_table, "encoded_ptr");
        if (rtl_encode_ptr != NULL) {
            drwrap_unwrap(rtl_encode_ptr, leak_wrap_pre_encode_ptr,
                          leak_wrap_post_encode_ptr);
        }
        if (rtl_encode_sysptr != NULL) {
            drwrap_unwrap(rtl_encode_sysptr, leak_wrap_pre_encode_ptr,
                          leak_wrap_post_encode_ptr);
        }
    }
#endif
}

void
leak_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
#if defined(WINDOWS) && defined(USE_DRSYMS)
    if (op_check_encoded_pointers) {
        /* i#1276: VS2012 Concurrency::details::Security::EncodePointer does
         * its own xor, but it has the same signature so we use the same
         * drwrap handlers.
         */
        crt_encode_ptr = lookup_symbol(info,
                                       "Concurrency::details::Security::EncodePointer");
        if (crt_encode_ptr != NULL &&
            !drwrap_wrap(crt_encode_ptr, leak_wrap_pre_encode_ptr,
                         leak_wrap_post_encode_ptr))
            ASSERT(false, "failed to wrap encoded CRT ptr routine");
    }
#endif
}

void
leak_module_unload(void *drcontext, const module_data_t *info)
{
#if defined(WINDOWS) && defined(USE_DRSYMS)
    if (crt_encode_ptr != NULL) {
        drwrap_unwrap(crt_encode_ptr, leak_wrap_pre_encode_ptr,
                      leak_wrap_post_encode_ptr);
    }
#endif
}

/* User must call from client_handle_malloc() and client_handle_realloc() */
void
leak_handle_alloc(void *drcontext, app_pc base, size_t size)
{
#ifdef WINDOWS
    /* Suppress the per-Heap leak of an RtlCreateHeap-allocated big chunk
     * (used for heap lookaside lists) on Windows.
     * Note that alloc.c now tries to ignore these allocs up front b/c
     * some are allocated after Heap creation, so we probably won't
     * come in here
     */
    if (alloc_in_create(drcontext)) {
        LOG(3, "since in_create, ignoring whether "PFX"-"PFX" is ever leaked\n",
            base, base+size);
        malloc_set_client_flag(base, MALLOC_IGNORE_LEAK);
    }
#endif
}

#ifdef WINDOWS
/* User must call from client_remove_malloc_on_destroy() */
void
leak_remove_malloc_on_destroy(HANDLE heap, byte *start, byte *end)
{
    uint client_flags;
    /* Our normal leak detection is through reachability analysis at
     * exit time.  If a heap arena is removed, though, some apps want
     * to know whether they freed all the mallocs inside, since their
     * code should usually be general and work with other Heaps.
     * Other apps, though, use HeapDestroy as a quick-free heap and
     * don't consider not freeing individually to be an error.  So,
     * under an option -check_leaks_on_destroy we only report as a
     * possible leak.
     */
    /* Before I implemented reachability-based leak detection, I would
     * walk each heap when removed and report any regions not
     * marked SHADOW_UNADDRESSABLE: there's no reason to do that
     * anymore.  Xref PR 484550.
     */
    if (!op_check_leaks_on_destroy)
        return;
    client_flags = malloc_get_client_flags(start);
    if (!TEST(MALLOC_IGNORE_LEAK, client_flags)) {
        client_found_leak(start, end, 0, malloc_is_pre_us(start), false,
                          /* Report as a possible leak since technically not
                           * incorrect to free heap w/ live mallocs inside
                           */
                          true, malloc_get_client_data(start), true, false);
    }
}
#endif

/***************************************************************************
 * Handling encoded pointers (i#153)
 *
 * XXX: We never delete from our table.  We assume there aren't very
 * many and that most if not all of them have a lifetime equal to the
 * process lifetime, since we don't have a good point to delete (we
 * can't assume a call to RtlDecodePointer means there will be no
 * further uses, right?).
 *
 * Note that there are other cases of pointers being xor-ed with magic
 * values that do not go through RtlEncodePointer, but our table here
 * does catch enough to be worthwhile.
 */

#ifdef WINDOWS
static void
leak_wrap_pre_encode_ptr(void *wrapcxt, void OUT **user_data)
{
    *user_data = drwrap_get_arg(wrapcxt, 0);
    ASSERT(op_check_encoded_pointers, "should not be called");
}

static void
leak_wrap_post_encode_ptr(void *wrapcxt, void *user_data)
{
    byte *encoded = (byte *) drwrap_get_retval(wrapcxt);
    byte *to_be_encoded = (byte *) user_data;
    ASSERT(op_check_encoded_pointers, "should not be called");
    LOG(2, "Encode*Pointer "PFX" => "PFX"\n", to_be_encoded, encoded);
    STATS_INC(pointers_encoded);
    /* Shift since NULL must be supported */
    ASSERT(to_be_encoded - ENCODED_PTR_SHIFT != NULL, "invalid ptr to encode");
    if (to_be_encoded != NULL &&
        hashtable_lookup(&encoded_ptr_table, (void *)to_be_encoded) != NULL) {
        /* We see encoded ptrs being passed to RtlEncodePointer which
         * ends up decoding (so an xor or other reversible operation).
         * We don't want the reverse in there: in fact we guarantee
         * not to have it.
         */
        LOG(2, "not adding to table since reverse encoding already present\n");
    }
    /* If we do hit ptr==ENCODED_PTR_SHIFT, just skip in release build */
    else if (to_be_encoded - ENCODED_PTR_SHIFT != NULL) {
        hashtable_add(&encoded_ptr_table, (void *)encoded,
                      (void *)(to_be_encoded - ENCODED_PTR_SHIFT));
    }
}

/* Encoded pointer tracking (i#153).  Guarantees that a non-NULL value
 * returned will always return NULL if passed back through.
 */
static byte *
get_decoded_ptr(byte *encoded)
{
    byte *res = hashtable_lookup(&encoded_ptr_table, (void *)encoded);
    if (res != NULL)
        return (res + ENCODED_PTR_SHIFT);
    else
        return NULL;
}
#endif /* WINDOWS */

/***************************************************************************
 * Splitting indirectly leaked bytes from direct (PR 576032)
 */

typedef struct _unreach_entry_t {
    /* If this is an unreachable or maybe-reachable entry, the sum of
     * directly-reachable child leaks and a pointer to the parent for
     * updating when the children are themselves scanned.
     */
    size_t indirect_bytes;
    struct _unreach_entry_t *parent;
} unreach_entry_t;

static unreach_entry_t *
unreach_entry_alloc(void)
{
    unreach_entry_t *e = global_alloc(sizeof(*e), HEAPSTAT_MISC);
    memset(e, 0, sizeof(*e));
    return e;
}

static bool
rb_cleanup_entries(rb_node_t *node, void *iter_data)
{
    unreach_entry_t *e;
    ASSERT(node != NULL, "invalid param");
    rb_node_fields(node, NULL, NULL, (void*)&e);
    if (e != NULL)
        global_free(e, sizeof(*e), HEAPSTAT_MISC);
    return true;
}

/*
 * Design:
 * * in top-level summary, just list total bytes (direct+indirect):
 *   do not split, for simplicity
 * * indirect leaks are only top-chunk-pointer reachable: any mid-chunk
 *   becomes its own possible leak, since if fixed top level the indirect
 *   would still be listed as a possible leak
 * * top-level (both normal and possible) leaks have their byte amounts
 *   split into direct and indirect
 * * off-by-default option could also list callstacks of indirect leaks
 *   but not worth effort to label w/ which is top-level for each:
 *   just label "INDIRECT LEAK" or "DEPENDENT LEAK".
 *   I punted on this: only if someone requests it is it worth the effort to
 *   add it, since IMHO it's not likely to be all that useful.
 *
 * Algorithm:
 * 1) scan unreach A:
 *    A is indirect: leave alone
 *    A points to B:
 *      if B reachable: leave alone.
 *      if B indirect: leave alone: someone else claimed
 *      if B maybe-reachable: change from maybe to indirect and follow else below
 *        => maybe-queue walk should check indirect flag
 *      else mark B indirect and add B's bytes + B's indirect bytes to top
 *        parent's indirect bytes.
 *        point B's parent pointer to top parent.
 *        use rbtree to hold these values.
 *    A maybe-points to B:
 *      if B reachable: leave alone.
 *      if B indirect: leave alone: someone else claimed
 *      if B maybe-reachable: nothing to do
 *      else mark B maybe-reachable: add to maybe-queue
 * 2) then walk maybe-queue: indirect trumps maybe, so only claim unclaimed
 *    directs as maybe-indirect
 */
static void
mark_indirect(reachability_data_t *data, byte *ptr_parent, byte *ptr_child,
              byte *child_start, byte *child_end, uint flags,
              rb_node_t *node_child/*OPTIONAL*/)
{
    if (TEST(MALLOC_REACHABLE, flags)) {
        /* if reachable through some other parent: leave alone */
    } else {
        /* if maybe-reachable: change to indirect by marking,
         *    and the maybe-reachable queue walk will ignore.
         * if already indirect: if someone else claimed, leave alone;
         *    else update parent size
         * if nothing yet: mark as indirect
         */
        /* We need the sum of the sizes of all indirect children of
         * every top-level direct leak, but we're not doing a
         * depth-first walk, so we must later update parents when we
         * process their children.  We also don't have any other good
         * place to store the size so we use the rbtree.
         */
        unreach_entry_t *unreach_child, *unreach_parent;
        rb_node_t *node_parent = rb_in_node(data->alloc_tree, ptr_parent);
        ASSERT(node_parent != NULL, "unreachable must be in heap");
        if (node_child == NULL) /* optional */
            node_child = rb_find(data->alloc_tree, ptr_child);
        ASSERT(node_child != NULL, "reachable object must be in rbtree");
        rb_node_fields(node_child, NULL, NULL, (void*)&unreach_child);
        /* rb client fields allocated lazily */
        if (unreach_child == NULL) {
            unreach_child = unreach_entry_alloc();
            rb_node_set_client(node_child, (void *)unreach_child);
        }
        /* acquire after in case child==parent */
        rb_node_fields(node_parent, NULL, NULL, (void *)&unreach_parent);
        if (unreach_parent == NULL) {
            unreach_parent = unreach_entry_alloc();
            rb_node_set_client(node_parent, (void *)unreach_parent);
        }

        if (TEST(MALLOC_INDIRECTLY_REACHABLE, flags)) {
            /* node is already claimed: either by another parent,
             * or by this parent if this chunk has two pointers
             * to the same child
             */
            ASSERT(unreach_child->parent != NULL, "node should be already claimed");
        } else {
            unreach_entry_t *top = unreach_parent;
            /* be sure to check for circular reference */
            while (top->parent != NULL && top->parent != top)
                top = top->parent;
            /* claim the child */
            LOG(4, "indirect bytes: top "PFX" %d + child "PFX" %d + "PFX"-"PFX"\n",
                top, top->indirect_bytes, unreach_child, unreach_child->indirect_bytes,
                child_end, child_start);
            if (top != unreach_child) {
                top->indirect_bytes +=
                    unreach_child->indirect_bytes + (child_end - child_start);
            }
            /* any future additions to the child (from scanning its children)
             * should go to top-level (i.e., direct leak) parent
             */
            unreach_child->parent = top;
            LOG(4, "mark_indirect: top "PFX" claiming child "PFX","PFX
                " through parent "PFX","PFX"\n",
                top, unreach_child, ptr_child, unreach_parent, ptr_parent);

            /* do not mark indirect if top of group (i#564) */
            if (top != unreach_child) {
                IF_DEBUG(bool found =)
                    malloc_set_client_flag(child_start, MALLOC_INDIRECTLY_REACHABLE);
                ASSERT(found, "malloc chunk must be in hashtable");
            }
        }
    }
}

/***************************************************************************/

/* PR 570839: this is a perf hit so we need to avoid a syscall
 * or ideally any setjmp overhead, which we can now do w/ DR's
 * fast dr_safe_read().  I measured and DR's safe_read_asm()
 * does seem to outperform try/except even for a single 4-byte
 * read.
 */
static inline bool
leak_safe_read_heap(void *base, void **var)
{
    return safe_read(base, sizeof(void*), var);
}

/* Helper for PR 484544.  Do not export: assumes world is suspended! */
static bool
is_text(byte *ptr)
{
    dr_mem_info_t info;
    /* PR 570839: avoid perf hit by caching.  World is suspended so no locks needed
     * and no races, so the page protections remain constant throughout the scan.
     */
    static byte *last_start = NULL;
    static byte *last_end = NULL;
    static bool last_ans = false;
    if (ptr < LOWEST_POINTER)
        return false;
    if (ptr >= last_start && ptr < last_end)
        return last_ans;
    /* FIXME i#270: DR should provide a section iterator! */
    last_ans = (dr_query_memory_ex(ptr, &info) &&
                info.type == DR_MEMTYPE_IMAGE &&
                TESTALL(DR_MEMPROT_READ | DR_MEMPROT_EXEC, info.prot) &&
                (!TEST(DR_MEMPROT_WRITE, info.prot) ||
                 /* i#: allow pretend-writable from hooking, etc. */
                 TEST(DR_MEMPROT_PRETEND_WRITE, info.prot)));
    last_start = info.base_pc;
    last_end = info.base_pc + info.size;
    return last_ans;
}

/* Helper for PR 484544.  Do not export: assumes world is suspended! */
static bool
is_image(byte *ptr)
{
    dr_mem_info_t info;
    /* PR 570839: avoid perf hit by caching.  World is suspended so no locks needed
     * and no races, so the page protections remain constant throughout the scan.
     */
    static byte *last_start = NULL;
    static byte *last_end = NULL;
    static bool last_ans = false;
    if (ptr < LOWEST_POINTER)
        return false;
    if (ptr >= last_start && ptr < last_end) {
        LOG(4, "is_image match "PFX": cached in "PFX"-"PFX" => %d\n",
            ptr, last_start, last_end, last_ans);
        return last_ans;
    }
    /* Even w/ the caching this is too slow on spec2k gap so we use the
     * fast module check from callstack.c
     */
    if (!is_in_module(ptr))
        return false;
    /* FIXME i#270: DR should provide a section iterator! */
    last_ans = (dr_query_memory_ex(ptr, &info) &&
                info.type == DR_MEMTYPE_IMAGE &&
                /* Turns out many libraries are loaded w/ the read-only data
                 * sections in a writable segment!  They have an rx segment and
                 * an rw segment and no read-only segment.  So we do not check
                 * for lack of DR_MEMPROT_WRITE.  Is it worth going to disk
                 * for each module at load time and constructing a section map?
                 * Xref i#270: DR-provided section iterator.
                 */
                TEST(DR_MEMPROT_READ, info.prot));
    last_start = info.base_pc;
    last_end = info.base_pc + info.size;
    LOG(4, "is_image no match "PFX", now cached "PFX"-"PFX" => %d\n",
        ptr, last_start, last_end, last_ans);
    return last_ans;
}

/* Heuristic for PR 484544 */
static bool
is_vtable(byte *ptr)
{
    if (ptr < LOWEST_POINTER)
        return false;
    if (ALIGNED(ptr, sizeof(void*)) && is_image(ptr)) {
        /* We have no symbols so we use heuristics: see if looks like
         * a table of ptrs to funcs.
         * We assume has at least 2 non-NULL entries (is that always true?).
         *
         * We do not check whether these are aligned: on Windows they often point
         * into the ILT and are not aligned.  Checking for is_text is our
         * most important check here: it's not unlikely to have various pointers
         * into data sections, but pointers into text are much rarer.
         *
         * Note that we do not also check for these func ptrs being in the same
         * library as the vtable itself or for the 2 func ptrs being in the same
         * library as each other as both are too restrictive (both are violated
         * on hostd).
         *
         * I added the checks for NULL b/c hostd has thousands of objects with
         * 93 different vtables that have NULL entries at the top and are definitely
         * vtables.  I'm not sure if NULL is a func ptr that is not initialized
         * or available, or what.  Hopefully we won't have false positives where
         * the vtable has nothing but NULL fields and we read other fields beyond it,
         * or the vtable has just 1 field and we read beyond (ignoring NULLs there):
         * do all vtables have at least contructor + destructor?  Based on hostd
         * I'm not too worried and as a heuristic I'm going to tune based
         * on what I see.
         */
        uint num_found = 0;
        byte *p, *val;
#       define VTABLE_MAX_CHECK 20 /* I've seen 13 on hostd */
        LOG(3, "\tis_vtable @"PFX"\n", ptr);
        for (p = ptr; p < (ptr + VTABLE_MAX_CHECK*sizeof(ptr)); p += sizeof(ptr)) {
            if (safe_read(p, sizeof(val), &val)) {
                LOG(4, "\t  vtable entry @"PFX": "PFX"\n", p, val);
                if (val == NULL)
                    continue; /* keep looking */
                else if (is_text(val)) {
                    num_found++;
                    if (num_found >= 2)
                        break;
                } else /* if hit a non-NULL, non-text entry, fail the check */
                    break;
            } else
                break;
        }
        return (num_found >= 2);
    } else {
        DOLOG(3, {
            dr_mem_info_t info;
            if (dr_query_memory_ex(ptr, &info))
                LOG(3, "\tis_vtable "PFX": %d, %d\n", ptr, info.type, info.prot);
        });
    }
    return false;
}

/* chunk_end is the asked-for end: does not include padding from malloc,
 * or any redzone from Dr. Memory
 */
static bool
is_midchunk_pointer_legitimate(byte *pointer, byte *chunk_start, byte *chunk_end)
{
    /* PR 484544: remove new[] from possible-leak category.  Mid-chunk
     * pointers happen legitimately for C++ arrays, since if have
     * destructor then new[] adds a header and so the app's pointer isn't
     * to the chunk head.
     */
    if (op_midchunk_new_ok) {
        /* FIXME: if we had symbols we could watch for calls to new[], which
         * we want to do for PR 408581 anyway: but for now we just look for
         * an appropriate # of array entries value and hope to not hit false
         * negatives (only removing from possible category so not that bad).
         */
        if (pointer == chunk_start + sizeof(size_t)) {
            size_t count;
            if (leak_safe_read_heap(chunk_start, (void **) &count) &&
                count > 0 && count < (chunk_end - chunk_start - sizeof(size_t)) &&
                (chunk_end - chunk_start - sizeof(size_t)) % count == 0) {
                LOG(3, "\tmid-chunk "PFX" is post-new[]-header => ok\n", pointer);
                STATS_INC(midchunk_postnew_ptrs);
                return true;
            }
        }
    }
    /* PR 484544: remove multi-inheritance from possible-leak category.
     * Mid-chunk pointers happen with multiple inheritance where a pointer
     * is cast to a base class and so points to the subobject for that
     * class, when the subobject is not the first in the class object
     * layout.
     */
    if (op_midchunk_inheritance_ok) {
        /* Our heuristic is to look for a vtable at the mid-chunk point and at
         * the start of the chunk.  Our heuristic thus assumes that the vtable
         * pointer is the (hidden) first field, not the last field.
         */
        byte *val1, *val2;
        if (ALIGNED(pointer, sizeof(void*))) {
            LOG(4, "\tmid="PFX", top="PFX"\n",
                /* risky perhaps but v4: */ *(byte **)pointer, *(byte **)chunk_start);
            if (leak_safe_read_heap(pointer, (void **) &val1) &&
                /* PR 570839: check for non-addresses to avoid call cost */
                val1 > LOWEST_POINTER && is_vtable(val1)) {
                if (leak_safe_read_heap(chunk_start, (void **) &val2) &&
                    val2 > LOWEST_POINTER && is_vtable(val2)) {
                    LOG(3, "\tmid-chunk "PFX" is multi-inheritance parent ptr => ok\n",
                        pointer);
                    STATS_INC(midchunk_postinheritance_ptrs);
                    return true;
                }
            }
        }
    }
    /* PR 535344: remove std::string instances from possible leak category */
    if (op_midchunk_string_ok) {
        /* A std::string object points at a heap-allocated instance of its internal
         * representation where the stored pointer is to the char array after 3
         * header fields (length, capacity, refcount).
         */
        size_t length, capacity;
        if (pointer == chunk_start + 3*sizeof(size_t) &&
            leak_safe_read_heap(chunk_start, (void **) &length) &&
            leak_safe_read_heap(chunk_start + sizeof(size_t), (void **) &capacity)) {
            LOG(4, "\tstring length="PIFX", capacity="PIFX", alloc="PIFX"\n",
                length, capacity, chunk_end - chunk_start);
            if (length <= capacity &&
                ((capacity + 1/*null-terminated*/ + 3*sizeof(size_t)/*3 header fields*/
                  == (chunk_end - chunk_start)) ||
                 /* Wide 2-byte characters (i#1814) */
                 ((capacity + 1/*null*/)*2 + 3*sizeof(size_t)/*3 header fields*/
                  == (chunk_end - chunk_start)))) {
                /* could also check for no nulls in char[] until length */
                LOG(3, "\tmid-chunk "PFX" is std::string => ok\n", pointer);
                STATS_INC(midchunk_string_ptrs);
                return true;
            }
        }
    }
    /* PR 513954: remove app-added malloc header from possible-leak category */
    if (op_midchunk_size_ok) {
        /* If the app has added a header with a size field, consider it
         * a legitimate pointer to after the size field (malloc-aligned).
         * This heuristic could have false positives but pretty unlikely
         * and already just a possible leak: though see below about
         * moving to "probably reachable" status.
         *
         * Currently this option looks for a very specific pattern seen in one
         * app.  To avoid false positives I'm not going to generalize it until I
         * see another example: so we'll leave the general option name and
         * generalize the pattern match as we accumulate more examples.
         */
        if (pointer == chunk_start + MALLOC_CHUNK_ALIGNMENT) {
            /* i#754: Try first two size_t slots in chunk.  We've seen the size
             * at offset 4 in an 8 byte header in the ldapMalloc layer in
             * WLDAP32.dll.
             */
            uint i;
            for (i = 0; i < 2; i++) {
                size_t val;
                size_t offset = i * sizeof(size_t);
                if (leak_safe_read_heap(chunk_start + offset, (void **) &val) &&
                    /* I've seen the total size as well as the size minus
                     * the extra header stored (the latter in sqlite)
                     */
                    (val == (chunk_end - chunk_start) ||
                     val == (chunk_end - chunk_start - MALLOC_CHUNK_ALIGNMENT))) {
                    LOG(3, "\tmid-chunk "PFX" is post-size => ok\n", pointer);
                    STATS_INC(midchunk_postsize_ptrs);
                    return true;
                }
            }
        }
    }

    return false;
}

/***************************************************************************
 * STRINGS VS POINTERS
 */

/* i#625: rule out parts of a string that look like heap pointers.  We use
 * heuristics geared toward ASCII characters in ASCII string or wide-char
 * string sequences.  It seems too fragile to just look for one string, and
 * most cases of false anchors are copies of the environment and other sequences
 * of many strings.  So we loook for at least 3 min-10-char strings, separated
 * by at least one null char, starting at the given address.  We need to take in
 * max_scan so we know what's guaranteed to be readable (all the threads are
 * suspended so there are no races).
 */

#define STRING_MIN_LEN   10
#define STRING_MIN_COUNT  3
/* i#1183: perlbench has many 7-million-char strings.  An alternative
 * to 3+ min-10-char strings is a single long string.  It seems
 * unlikely that a series of pointers this long would have no byte
 * with either the top bit set or equal to zero.
 */
#define STRING_SINGLE_MAX_LEN   128

#ifdef WINDOWS
static bool
is_part_of_string_wide(wchar_t *s, wchar_t *max_scan)
{
    uint count = 0;
    wchar_t *stop = (max_scan != NULL) ? max_scan :
        (wchar_t *) ALIGN_FORWARD(s, PAGE_SIZE);
    wchar_t *start;
    for (start = s; s < stop; s++) {
        if (*s == 0) {
            if (start < s) {
                count++;
                if (s - start < STRING_MIN_LEN)
                    return false;
                if (count >= STRING_MIN_COUNT)
                    break;
            } /* else, several nulls in a row */
            start = s + 1;
        } else if (!IS_ASCII(*s)) {
            return false;
        } else if (s - start >= STRING_SINGLE_MAX_LEN)
            return true;
    }
    return (count >= STRING_MIN_COUNT);
}
#endif

static bool
is_part_of_string_ascii(byte *s, byte *max_scan)
{
    uint count = 0;
    byte *stop = (max_scan != NULL) ? max_scan : (byte *) ALIGN_FORWARD(s, PAGE_SIZE);
    byte *start;
    for (start = s; s < stop; s++) {
        if (*s == 0) {
            if (start < s) {
                count++;
                if (s - start < STRING_MIN_LEN)
                    return false;
                if (count >= STRING_MIN_COUNT)
                    break;
            } /* else, several nulls in a row */
            start = s + 1;
        } else if (!IS_ASCII(*s)) {
            return false;
        } else if (s - start >= STRING_SINGLE_MAX_LEN)
            return true;
    }
    return (count >= STRING_MIN_COUNT);
}

static bool
is_part_of_string(byte *s, byte *max_scan)
{
#ifdef WINDOWS
    if (*(s+1) == 0 && *(s+3) == 0)
        return is_part_of_string_wide((wchar_t *)s, (wchar_t *)max_scan);
#endif
    return is_part_of_string_ascii(s, max_scan);
}

/***************************************************************************/

static void
check_reachability_pointer(byte *pointer, byte *ptr_addr, byte *defined_end,
                           reachability_data_t *data)
{
    byte *chunk_start = NULL;
    byte *chunk_end;
    bool add_reachable = false, add_maybe_reachable = false;
    uint flags = 0;
    bool reachable = false;
    rb_node_t *node = NULL;

    if (pointer == NULL)
        return;

#ifdef WINDOWS
    if (op_check_encoded_pointers) {
        /* XXX: measure perf hit of yet another hashtable lookup on every single ptr.
         * Could store in malloc table since already looking there, and assuming
         * disjoint though could imagine an xor happening to collide.
         */
        byte *decoded = get_decoded_ptr(pointer);
        if (decoded != NULL) {
            LOG(3, "\t("PFX" when decoded is "PFX" so checking both)\n",
                pointer, decoded);
            STATS_INC(encoded_pointers_scanned);
            /* We check both encoded and decoded b/c xor could collide w/ heap addr.
             * No reverse in table so we won't recurse forever.
             */
            ASSERT(get_decoded_ptr(decoded) == NULL, "encoded table can't have reverse");
            check_reachability_pointer(decoded, ptr_addr, defined_end, data);
            pointer = decoded;
        }
    }
#endif

    /* skip any small value that cannot be a pointer
     * Note: there are several places (e.g., is_text, is_vtable, and is_image)
     * doing the similar checks against LOWEST_POINTER, which might benefit from
     * using data->low_ptr. However, it might not worth the effort passing extra
     * param around.
     */
    if (pointer < data->low_ptr)
        return;
    /* We look in rbtree first since likely to miss both so why do hash lookup */
    node = rb_in_node(data->alloc_tree, pointer);
    if (node != NULL) {
#ifndef VMX86_SERVER /* unsafe to read */
        /* We check for strings after the rbtree lookup to avoid extra work
         * on every pointer.
         */
        if (options.strings_vs_pointers &&
            ptr_addr > (byte *) PAGE_SIZE && /* rule out register */
            is_part_of_string(ptr_addr, defined_end)) {
            LOG(3, "\t("PFX" is part of a string table so not considering a pointer)\n",
                ptr_addr);
            STATS_INC(strings_not_pointers);
            node = NULL;
        }
#endif
    }
    if (node != NULL) {
        chunk_end = malloc_end(pointer);
        if (chunk_end != NULL) {
            if (ptr_addr >= pointer && ptr_addr < chunk_end) {
                LOG(3, "\t("PFX" points to start of its own chunk "PFX"-"PFX")\n",
                    ptr_addr, pointer, chunk_end);
            } else {
                flags = malloc_get_client_flags(pointer);
                LOG(3, "\t"PFX" points to chunk "PFX"-"PFX"\n",
                    ptr_addr, pointer, chunk_end);
                chunk_start = pointer;
                reachable = true;
            }
        } else {
            size_t chunk_size;
            rb_node_fields(node, &chunk_start, &chunk_size, NULL);
            chunk_end = chunk_start + chunk_size;
            ASSERT(is_in_heap_region(pointer), "heap data struct inconsistency");
            if (ptr_addr >= chunk_start && ptr_addr < chunk_end) {
                LOG(3, "\t("PFX" points to middle "PFX" of its own chunk "PFX"-"PFX")\n",
                    ptr_addr, pointer, chunk_start, chunk_end);
            } else {
                /* PR 476482: we have a separate category of "possible leaks" that
                 * are not reached by chunk-head pointers but are reached by
                 * mid-chunk pointers.
                 */
                LOG(3, "\t("PFX" points to mid-chunk "PFX" in "PFX"-"PFX")\n",
                    ptr_addr, pointer, chunk_start, chunk_end);
                flags = malloc_get_client_flags(chunk_start);
                if (is_midchunk_pointer_legitimate(pointer, chunk_start, chunk_end)) {
                    /* We could split these out as "probably reachable" but that would
                     * require a new chunk queue and flags and extra logic for
                     * whether reached initially by which: not worth it since the
                     * heuristics are unlikely to mask real leaks.
                     */
                    reachable = true;
                    LOG(3, "\t  mid-chunk "PFX" in "PFX"-"PFX" is reachable\n",
                        pointer, chunk_start, chunk_end);
                } else if (!TESTANY(MALLOC_MAYBE_REACHABLE | MALLOC_REACHABLE |
                                    /* indirect trumps maybe */
                                    MALLOC_INDIRECTLY_REACHABLE, flags)) {
                    add_maybe_reachable = true;
                }
            }
        }
    } else {
#if 0
        /* FIXME PR 484550: investigate addressable bytes in heap but not in
         * chunk.  I'm seeing defined bytes in heap regions that aren't in
         * allocated chunk.  My old leak checking also found bytes inside
         * heap regions that were not UNADDR but I don't know how often
         * those were not in chunks, and most of those were from UNADDR
         * errors that we then marked as defined.  This may well be some
         * inconsistency that should be fixed so we should investigate.
         * For now, relaxing the assert.
         */
        ASSERT(!is_in_heap_region(pointer) ||
               shadow_get_byte(pointer) == SHADOW_UNADDRESSABLE,
               "heap data struct inconsistency");
#endif
    }
#ifdef WINDOWS
    if (reachable && rtl_fail_info != NULL &&
        ptr_addr >= rtl_fail_info && ptr_addr < rtl_fail_info + RTL_FAIL_INFO_SIZE) {
        /* RtlHeap stores failed alloc info which can hide leaks (i#292) */
        LOG(1, "WARNING: "PFX" is inside RtlpHeapFailureInfo data struct: ignoring!\n",
            ptr_addr);
        reachable = false;
    }
#endif

    if (reachable) {
        if (data->primary_scan) {
            if (!TEST(MALLOC_REACHABLE, flags))
                add_reachable = true;
            /* if already on the maybe-reachable queue we'll just ignore in
             * the secondary scan
             */
        } else {
            mark_indirect(data, ptr_addr, pointer, chunk_start, chunk_end, flags, node);
        }
    }
    if (add_reachable || add_maybe_reachable) {
        /* Mark chunk as reachable using the client flag and add to
         * the queue of chunks to scan for further pointers.
         */
        pc_entry_t *add;
        IF_DEBUG(bool found =)
            malloc_set_client_flag(chunk_start,
                                   add_reachable ? MALLOC_REACHABLE :
                                   MALLOC_MAYBE_REACHABLE);
        ASSERT(found, "malloc chunk must be in hashtable");
        ASSERT(!add_reachable || data->primary_scan, "only add reachable in primary");
        /* Add to queue of chunks to scan */
        add = (pc_entry_t *) global_alloc(sizeof(*add), HEAPSTAT_MISC);
        add->start = chunk_start;
        add->end = chunk_end;
        add->next = NULL;
        queue_add(add_reachable ? &data->reachq_head : &data->midreachq_head,
                  add_reachable ? &data->reachq_tail : &data->midreachq_tail,
                  add);
    }
}

static void
check_reachability_helper(byte *start, byte *end, bool skip_heap,
                          reachability_data_t *data)
{
    byte *pc, *defined_end, *chunk_end, *pointer, *iter_end, *query_end = NULL;
    dr_mem_info_t info;
#ifdef WINDOWS
    MEMORY_BASIC_INFORMATION mbi = {0};
#endif
    ASSERT(data != NULL, "invalid args");
    LOG(4, "\nchecking reachability of "PFX"-"PFX"\n", start, end);
    pc = start;
    while (pc < end) {
        /* Skip free and unreadable regions (once we have PR 406328 unreadable
         * regions won't show up in the defined range below but may as well skip
         * here: examples of defined but unreadable today include stack guard
         * pages on Linux or .stab section in a cygwin .exe).
         */
        if (pc >= query_end) {
            if (!dr_query_memory_ex(pc, &info)) {
                /* query on Windows expected to fail on kernel memory */
                ASSERT(IF_WINDOWS_ELSE(info.type == DR_MEMTYPE_ERROR_WINKERNEL, false),
                       "dr_query_memory_ex failed");
                return;
            }
#ifdef WINDOWS
            /* We need to avoid touching guard pages on Windows
             * We could not call dr_query_memory_ex() and convert the mbi fields,
             * but simpler this way even if takes extra syscall.
             */
            if (dr_virtual_query(pc, &mbi, sizeof(mbi)) == sizeof(mbi) &&
                TEST(PAGE_GUARD, mbi.Protect))
                info.prot = DR_MEMPROT_NONE;
#endif
            /* PR 483063: bounds should be page-aligned, but be paranoid */
            query_end = (byte *) ALIGN_FORWARD(info.base_pc + info.size, PAGE_SIZE);
            LOG(4, "query "PFX"-"PFX" prot=%x\n", info.base_pc, query_end, info.prot);
            if (!TEST(DR_MEMPROT_READ, info.prot) ||
                /* we skip r-x regions.  FIXME PR 475518: if we have info on
                 * what's been modified since it was loaded we can avoid
                 * potential false negatives here if the r-x was restored.
                 */
                (TESTALL(DR_MEMPROT_READ|DR_MEMPROT_EXEC, info.prot) &&
                 !TEST(DR_MEMPROT_WRITE, info.prot)) ||
                (!options.scan_read_only_files &&
                /* This could result in false negatives, which is why this is
                 * under an option.  It's not worth tracking whether these pages
                 * have been unmodified since loaded since mapped (how often is
                 * someone going to store a heap pointer in a file-mapped page
                 * and then mark the page read-only?).
                 * We want to skip these not only for a significant performance
                 * gain but also to avoid false anchors in .pdata sections (PR 485354)
                 * and locale.nls (i#1096) that make our test suite non-deterministic.
                 */
                 TEST(DR_MEMPROT_READ, info.prot) &&
                 !TEST(DR_MEMPROT_WRITE, info.prot) &&
                 (info.type == DR_MEMTYPE_IMAGE
                  /* Windows-only b/c it's a pain to identify non-image maps on Linux */
                  IF_WINDOWS(|| mbi.Type == MEM_MAPPED))) ||
#if defined(WINDOWS) && defined(USE_DRSYMS)
                /* skip private heap: here we assume it's a single segment */
                (pc == (byte *) get_private_heap_handle()) ||
#endif
#ifdef LINUX
                /* i#1778: skip vvar page to avoid kernel soft lockups.
                 * This skips vdso as well but we're already doing that b/c it's +rx.
                 */
                TEST(DR_MEMPROT_VDSO, info.prot) ||
#endif
                /* don't count references in DR data */
                dr_memory_is_dr_internal(pc) ||
#ifdef TOOL_DR_MEMORY
                /* skip over shadow memory */
                shadow_memory_is_shadow(pc) ||
#endif
                /* don't count references in DrMem data (e.g., report.c's
                 * page_buf holds a page's worth of old stack data)
                 */
                dr_memory_is_in_client(pc)) {
                if (query_end < pc) /* overflow */
                    break;
                pc = query_end;
                continue;
            }
        }
        iter_end = (query_end < end) ? query_end : end;
        if (!op_have_defined_info) {
            /* scan everything except beyond TOS which we assume a query
             * boundary will intersect
             */
            rb_node_t *node = rb_in_node(data->stack_tree, pc);
            if (node != NULL) {
                byte *stack_base;
                size_t TOS_size;
                rb_node_fields(node, &stack_base, &TOS_size, NULL);
                pc = stack_base + TOS_size;
                LOG(3, "skipping TOS "PFX"-"PFX"\n", stack_base, pc);
                if (pc >= iter_end)
                    continue;
            }
            defined_end = iter_end;
        } else {
            pc = cb_next_defined_ptrsz(pc, iter_end);
            if (pc == NULL) {
                pc = iter_end;
                continue;
            }
            defined_end = cb_end_of_defined_region(pc, iter_end);
        }
        LOG(3, "defined range "PFX"-"PFX"\n", pc, defined_end);

        for (pc = (byte *)ALIGN_FORWARD(pc, sizeof(void*));
             pc < defined_end && pc + sizeof(void*) <= defined_end; pc += sizeof(void*)) {
            if (skip_heap) {
                /* Skip heap regions */
                if (heap_region_bounds(pc, NULL, &chunk_end, NULL) &&
                    chunk_end != NULL) {
                    pc = chunk_end - sizeof(void*); /* let loop inc bump pc */
                    ASSERT(ALIGNED(pc, sizeof(void*)), "heap region end not aligned!");
                    continue;
                }
            }
            /* Now pc points to an aligned and defined (non-heap) ptrsz bytes */
            /* XXX PR 475518: improve performance of all these reads and table
             * lookups: this scan is where the noticeable pause at exit comes
             * from, not the identification of defined regions.
             */
#ifdef UNIX
            /* i#1773: we could hit a bus error even on a readable page.  Also
             * on some UNIX platforms like VMX86_SERVER we do not have a
             * reliable memory query.
             */
            if (leak_safe_read_heap(pc, (void **)&pointer))
                check_reachability_pointer(pointer, pc, defined_end, data);
#else
            /* Threads are suspended and we checked readability so safe to deref */
            pointer = *((app_pc*)pc);
            check_reachability_pointer(pointer, pc, defined_end, data);
#endif
        }
        pc = (byte *) ALIGN_FORWARD(defined_end, sizeof(void*));
    }
}

static void
check_reachability_regs(void *drcontext, dr_mcontext_t *mc, reachability_data_t *data)
{
    reg_id_t reg;
    if (!op_have_defined_info) {
        /* with no shadow info we have to rule out stale stack data by
         * recording the current stacks and hoping any old stacks were
         * munmapped.  FIXME: altsigstack
         */
        app_pc stack_base;
        size_t stack_size;
        if (dr_query_memory((app_pc)mc->xsp, &stack_base, &stack_size, NULL)) {
            LOG(2, "thread "TIDFMT" stack is "PFX"-"PFX", sp="PFX"\n",
                dr_get_thread_id(drcontext), stack_base,
                stack_base + stack_size, mc->xsp);
            /* store the region beyond TOS */
            rb_insert(data->stack_tree, stack_base,
                      ((app_pc)mc->xsp) - stack_base, NULL);
        }
    }
    /* we ignore fp/mmx and xmm regs */
    for (reg = REG_START_32; reg <= IF_X86_ELSE(REG_EDI/*STOP_32 is R15D!*/, REG_STOP_32);
         reg++) {
        if (!op_have_defined_info || cb_is_register_defined(drcontext, reg)) {
            reg_t val = reg_get_value(reg, mc);
            LOG(4, "thread "TIDFMT" reg %d: "PFX"\n", dr_get_thread_id(drcontext),
                reg, val);
            check_reachability_pointer((byte *)val, (byte *)(ptr_uint_t)reg/*diagnostic*/,
                                       NULL, data);
        }
    }
}

static bool
malloc_iterate_identify_indirect_cb(malloc_info_t *info, void *iter_data)
{
    reachability_data_t *data = (reachability_data_t *) iter_data;
    ASSERT(data != NULL, "invalid iteration data");
    ASSERT(info->base != NULL, "invalid params");
    if (!TESTANY(MALLOC_IGNORE_LEAK | MALLOC_REACHABLE | MALLOC_MAYBE_REACHABLE,
                 info->client_flags)) {
        check_reachability_helper(info->base, info->base + info->request_size,
                                  false, (void *)data);
    }
    return true;
}

static bool
malloc_iterate_cb(malloc_info_t *info, void *iter_data)
{
    reachability_data_t *data = (reachability_data_t *) iter_data;
    ASSERT(data != NULL, "invalid iteration data");
    ASSERT(info->base != NULL, "invalid params");
    LOG(4, "malloc iter: "PFX"-"PFX"%s%s%s%s%s\n", info->base,
        info->base + info->request_size,  info->pre_us ? ", pre-us" : "",
        TEST(MALLOC_IGNORE_LEAK, info->client_flags) ? ", ignore leak" : "",
        TEST(MALLOC_REACHABLE, info->client_flags) ? ", reachable" : "",
        TEST(MALLOC_MAYBE_REACHABLE, info->client_flags) ? ", maybe reachable" : "",
        TEST(MALLOC_INDIRECTLY_REACHABLE, info->client_flags) ?
        ", indirectly reachable" : "");
    /* If requested in future we can add a -show_indirectly_reachable: for now
     * we never print detailed info for them, just add their sizes to
     * their parent direct leaks
     */
    if (!TESTANY(MALLOC_IGNORE_LEAK | MALLOC_INDIRECTLY_REACHABLE, info->client_flags) &&
        /* for 2nd pass only report reachable */
        (!data->last_of_2_iters || TEST(MALLOC_REACHABLE, info->client_flags))) {
        rb_node_t *node = rb_find(data->alloc_tree, info->base);
        unreach_entry_t *unreach;
        ASSERT(node != NULL, "must be in rbtree");
        rb_node_fields(node, NULL, NULL, (void *)&unreach);
        client_found_leak(info->base, info->base + info->request_size,
                          (unreach == NULL) ? 0 : unreach->indirect_bytes,
                          info->pre_us,
                          TEST(MALLOC_REACHABLE, info->client_flags),
                          TEST(MALLOC_MAYBE_REACHABLE, info->client_flags),
                          info->client_data,
                          !data->last_of_2_iters, /* count on 1st iter */
                          data->last_of_2_iters); /* show, but no double-count, on 2nd */
    }
    /* clear for any subsequent reachability walks */
    if (!data->first_of_2_iters) {
        malloc_clear_client_flag(info->base, MALLOC_REACHABLE | MALLOC_MAYBE_REACHABLE |
                                 MALLOC_INDIRECTLY_REACHABLE);
    }
    return true;
}

static bool
malloc_iterate_build_tree_cb(malloc_info_t *info, void *iter_data)
{
    rb_tree_t *alloc_tree = (rb_tree_t *) iter_data;
    IF_DEBUG(rb_node_t *node;)
    ASSERT(alloc_tree != NULL, "invalid iteration data");
    /* We use NULL for client b/c we only need unreach_entry_t for the
     * leaks, a small fraction (for most apps!) of the total and thus
     * best allocated lazily
     */
    IF_DEBUG(node = )
        rb_insert(alloc_tree, info->base, info->request_size, NULL);
    ASSERT(node == NULL, "mallocs should not overlap");
    return true;
}

static void
prepare_thread_for_scan(void *drcontext, bool *was_app_state OUT)
{
    ASSERT(was_app_state != NULL, "invalid param");
    *was_app_state = dr_using_app_state(drcontext);
    LOG(2, "%s: thread "TIDFMT" was %s state\n", __FUNCTION__,
        dr_get_thread_id(drcontext), *was_app_state ? "app" : "priv");
    /* Restore app's PEB and TEB fields (i#248) */
    if (!*was_app_state)
        dr_switch_to_app_state(drcontext);

#if defined(TOOL_DR_MEMORY) && defined(WINDOWS)
    LOG(3, "prepare_thread_for_scan: thread "TIDFMT" has TLS "PFX"\n",
        dr_get_thread_id(drcontext), drmgr_get_tls_field(drcontext, tls_idx_drmem));
    if (drmgr_get_tls_field(drcontext, tls_idx_drmem) == NULL && op_have_defined_info) {
        /* We received the exit event for this thread and marked its
         * TEB as unaddr -- but we want to scan that memory.
         * We treat it all as defined (instead of calling set_teb_initial_shadow())
         * b/c it is all initialized and we can be more liberal wrt leaks.
         */
        TEB *teb = get_TEB_from_handle(dr_get_dr_thread_handle(drcontext));
        if (teb == NULL) {
            /* can happen due to permissions problems (i#442).
             * we use a cached teb value placed at thread exit (i#547).
             */
            teb = (TEB *) get_thread_tls_value(drcontext, SPILL_SLOT_1);
        }
        ASSERT(teb != NULL, "invalid param");
        shadow_set_range((app_pc)teb, (app_pc)teb + sizeof(*teb), SHADOW_DEFINED);
    }
#endif
}

static void
restore_thread_after_scan(void *drcontext, bool was_app_state)
{
    /* Restore private PEB and TEB fields (i#248) */
    if (!was_app_state)
        dr_switch_to_dr_state(drcontext);

#if defined(TOOL_DR_MEMORY) && defined(WINDOWS)
    if (drmgr_get_tls_field(drcontext, tls_idx_drmem) == NULL && op_have_defined_info) {
        /* Re-mark as unaddr */
        TEB *teb = get_TEB_from_handle(dr_get_dr_thread_handle(drcontext));
        if (teb == NULL) /* see above */
            teb = (TEB *) get_thread_tls_value(drcontext, SPILL_SLOT_1);
        ASSERT(teb != NULL, "invalid param");
        shadow_set_range((app_pc)teb, (app_pc)teb + sizeof(*teb), SHADOW_UNADDRESSABLE);
    }
#endif
}

void
leak_scan_for_leaks(bool at_exit)
{
    pc_entry_t *e, *next_e;
    void **drcontexts = NULL;
    bool *was_app_state = NULL;
    uint num_threads = 0, i;
    dr_mcontext_t mc; /* do not init whole thing: memset is expensive */
    reachability_data_t data;
    void *my_drcontext = dr_get_current_drcontext();
    dr_mem_info_t mem_info;
#ifdef DEBUG
    static bool called_at_exit;
    if (at_exit) {
        /* we only clear the flags on nudges, so only 1 at_exit supported */
        ASSERT(!called_at_exit, "check_reachability only supports 1 call at_exit");
        called_at_exit = true;
    }
#endif
    LOG(1, "checking leaks via reachability analysis\n");
    mc.size = sizeof(mc);
    mc.flags = DR_MC_CONTROL|DR_MC_INTEGER; /* don't need xmm */

    /* XXX: no MacOS private loader yet */
    /* ARM is always in app state */
#if !defined(MACOS) && !defined(ARM)
    /* i#1016: ensure the thread performing the leak scan is in DR state,
     * which should be the case regardless of whether at exit or a nudge.
     */
    ASSERT(!dr_using_app_state(my_drcontext), "state error");
#endif

    /* Strategy: First walk non-heap memory that is defined to find reachable
     * heap blocks.  (Ideally we would skip memory that has not been modified
     * since startup -- .rodata cannot point into heap of course -- but we don't
     * know that even w/ the special shadow blocks.  PR 475518 covers adding
     * that info.)  Then walk those heap blocks to find what they reach.  Assume
     * pointers are aligned.  For now only considering pointers to the start of
     * a heap block: we'll see how many false positives we hit with that.
     */
    if (IF_WINDOWS_ELSE(false, true) && at_exit && op_have_defined_info) {
        /* We assume no synch is needed at exit time, and that we
         * can ignore thread registers as roots of the search.
         * if no defined info we need to walk the thread stacks.
         * On Windows we need to restore the PEB/TEB fields so we
         * need to get the thread list to iterate over: safest
         * and simplest to suspend-all.
         */
    } else {
        /* PR 428709: reachability mid-run */
        if (!dr_suspend_all_other_threads(&drcontexts, &num_threads, NULL)) {
            LOG(0, "WARNING: not all threads suspended for reachability analysis\n");
            /* We carry on and live w/ the raciness.  We still allocate was_app_state
             * to store cur thread info.
             */
            ASSERT(num_threads == 0, "param clobbered on failure");
        }
        /* Restore app's PEB and TEB fields (i#248) */
        /* Store prior state (+1 for cur thread) (i#5) */
        was_app_state = (bool *) global_alloc((num_threads+1)*sizeof(bool), HEAPSTAT_MISC);
        for (i = 0; i < num_threads; i++)
            prepare_thread_for_scan(drcontexts[i], &was_app_state[i]);
        prepare_thread_for_scan(my_drcontext, &was_app_state[num_threads]);
    }

    memset(&data, 0, sizeof(data));
    data.primary_scan = true;
    data.alloc_tree = rb_tree_create(NULL);
    data.stack_tree = rb_tree_create(NULL);
    /* get the lowest allocated memory */
    dr_query_memory_ex(NULL, &mem_info);
    if (mem_info.prot == DR_MEMPROT_NONE)
        data.low_ptr = mem_info.base_pc + mem_info.size;
    else
        data.low_ptr = NULL;

    /* Build tree for interval lookup for mid-chunk pointers (PR 476482).
     * Since doing this just once, we could use an array, but tree may be
     * useful later on.  I have measured the cost of having the malloc
     * hashtable be an rbtree instead, avoiding this creation, but the extra
     * overhead shows up on heap-intensive bmarks (PR 535568).
     */
    malloc_iterate(malloc_iterate_build_tree_cb, (void *) data.alloc_tree);

    if (!at_exit || !op_have_defined_info) {
        /* Walk the thread's registers.  We rely on mcontext field ordering here. */
        for (i = 0; i < num_threads; i++) {
            LOG(3, "\nwalking registers of thread "TIDFMT"\n",
                dr_get_thread_id(drcontexts[i]));
            dr_get_mcontext(drcontexts[i], &mc);
            check_reachability_regs(drcontexts[i], &mc, &data);
        }
        LOG(3, "\nwalking registers of thread "TIDFMT"\n",
            dr_get_thread_id(my_drcontext));
        dr_get_mcontext(my_drcontext, &mc);
        check_reachability_regs(my_drcontext, &mc, &data);
    }

    check_reachability_helper(NULL, (app_pc)POINTER_MAX, true/*skip heap*/, &data);
    LOG(3, "\nwalking reachable-chunk queue\n");
    for (e = data.reachq_head; e != NULL; e = next_e) {
        check_reachability_helper(e->start, e->end, false, &data);
        next_e = e->next;
        global_free(e, sizeof(*e), HEAPSTAT_MISC);
    }
    data.primary_scan = false;

    /* now split direct from indirect leaks, and perhaps find new maybe-reachable.
     * indirect trumps maybe-reachable, so do this walk first.
     */
    LOG(3, "\nwalking unreachable chunks\n");
    malloc_iterate(malloc_iterate_identify_indirect_cb, &data);

    /* split direct from indirect among maybe-reachable */
    LOG(3, "\nwalking maybe-reachable-chunk queue\n");
    for (e = data.midreachq_head; e != NULL; e = next_e) {
        uint flags = malloc_get_client_flags(e->start);
        if (TEST(MALLOC_REACHABLE, flags)) {
            /* This was later marked as fully-reachable and added to reachq,
             * so ignore it here
             */
        } else if (TEST(MALLOC_INDIRECTLY_REACHABLE, flags)) {
            /* This was later marked as indirectly-reachable and accounted for
             * in its parent size, so ignore it here
             */
        } else {
            check_reachability_helper(e->start, e->end, false, &data);
        }
        next_e = e->next;
        global_free(e, sizeof(*e), HEAPSTAT_MISC);
    }

    /* we must restore prior to any symbol lookup (i#324) */
    if (drcontexts != NULL) {
        /* Back to private PEB and TEB fields (i#248) */
        for (i = 0; i < num_threads; i++)
            restore_thread_after_scan(drcontexts[i], was_app_state[i]);
    }
    if (was_app_state != NULL) {
        restore_thread_after_scan(my_drcontext, was_app_state[num_threads]);
        global_free(was_app_state, (num_threads+1)*sizeof(bool), HEAPSTAT_MISC);
    }

    /* up to caller to call report_leak_stats_{checkpoint,revert} if desired */

    /* in order to separate reachable from real leaks we do two passes */
    if (op_show_reachable)
        data.first_of_2_iters = true;
    malloc_iterate(malloc_iterate_cb, &data);
    if (op_show_reachable) {
        data.first_of_2_iters = false;
        data.last_of_2_iters = true;
        malloc_iterate(malloc_iterate_cb, &data);
    }

    if (drcontexts != NULL) {
        IF_DEBUG(bool ok =)
            dr_resume_all_other_threads(drcontexts, num_threads);
        ASSERT(ok, "failed to resume after leak scan");
    }

    /* We do not maintain the tree throughout execution: we make a new one for
     * each reachability scan.
     */
    rb_iterate(data.alloc_tree, rb_cleanup_entries, NULL);
    rb_tree_destroy(data.alloc_tree);
    rb_tree_destroy(data.stack_tree);
}
