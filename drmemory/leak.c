/* **********************************************************
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

#include "dr_api.h"
#include "leak.h"
#include "alloc.h"
#include "heap.h"
#include "redblack.h"

/***************************************************************************
 * REACHABILITY-BASED LEAK DETECTION
 */

/* We claim 3 of the malloc table's client flags */
enum {
    MALLOC_IGNORE_LEAK  = MALLOC_CLIENT_1,
    MALLOC_REACHABLE    = MALLOC_CLIENT_2,
    /* Reachable via a mid-chunk pointer (PR 476482) */
    MALLOC_MAYBE_REACHABLE = MALLOC_CLIENT_3,
};

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
} reachability_data_t;

#ifdef STATISTICS
uint midchunk_postsize_ptrs;
uint midchunk_postnew_ptrs;
uint midchunk_postinheritance_ptrs;
uint midchunk_string_ptrs;
#endif

/* FIXME PR 487993: switch to file-private sets of options and option parsing */ 
static bool op_have_defined_info; 
static bool op_check_leaks_on_destroy;
static bool op_midchunk_new_ok;
static bool op_midchunk_inheritance_ok;
static bool op_midchunk_string_ok;
static bool op_midchunk_size_ok;
static byte *(*cb_next_defined_dword)(byte *, byte *);
static byte *(*cb_end_of_defined_region)(byte *, byte *);
static bool (*cb_is_register_defined)(void *, reg_id_t);


void
leak_init(bool have_defined_info, 
          bool check_leaks_on_destroy,
          bool midchunk_new_ok,
          bool midchunk_inheritance_ok,
          bool midchunk_string_ok,
          bool midchunk_size_ok,
          byte *(*next_defined_dword)(byte *, byte *),
          byte *(*end_of_defined_region)(byte *, byte *),
          bool (*is_register_defined)(void *, reg_id_t))
{
    op_have_defined_info = have_defined_info; 
    op_check_leaks_on_destroy = check_leaks_on_destroy;
    op_midchunk_new_ok = midchunk_new_ok;
    op_midchunk_inheritance_ok = midchunk_inheritance_ok;
    op_midchunk_string_ok = midchunk_string_ok;
    op_midchunk_size_ok = midchunk_size_ok;
    if (op_have_defined_info) {
        ASSERT(next_defined_dword != NULL, "defined info needs cbs");
        ASSERT(end_of_defined_region != NULL, "defined info needs cbs");
        ASSERT(is_register_defined != NULL, "defined info needs cbs");
        cb_next_defined_dword = next_defined_dword;
        cb_end_of_defined_region = end_of_defined_region;
        cb_is_register_defined = is_register_defined;
    }
}

/* User must call from client_handle_malloc() and client_handle_realloc() */
void
leak_handle_alloc(per_thread_t *pt, app_pc base, size_t size)
{
#ifdef WINDOWS
    /* Suppress the per-Heap leak of an RtlCreateHeap-allocated big chunk
     * (used for heap lookaside lists) on Windows
     */
    if (pt->in_create)
        malloc_set_client_flag(base, MALLOC_IGNORE_LEAK);
#endif
}

/* User must call from client_exit_iter_chunk() */
void
leak_exit_iter_chunk(app_pc start, app_pc end, bool pre_us, uint client_flags,
                     void *client_data)
{
    if (!TEST(MALLOC_IGNORE_LEAK, client_flags)) {
        client_found_leak(start, end, pre_us,
                          TEST(MALLOC_REACHABLE, client_flags), 
                          TEST(MALLOC_MAYBE_REACHABLE, client_flags),
                          client_data);
    }
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
        client_found_leak(start, end, malloc_is_pre_us(start), false,
                          /* Report as a possible leak since technically not
                           * incorrect to free heap w/ live mallocs inside
                           */
                          true, malloc_get_client_data(start));
    }
}
#endif

/* PR 570839: this is a perf hit so we avoid dr_safe_read(), on
 * Windows at least.  No races since world is suspended, but we
 * should do a cached query in case app made part of heap
 * unreadable: or better use try/except for windows and linux.
 */
static inline bool
leak_safe_read_heap(void *base, void **var)
{
    /* FIXME: use try/except: for now blindly reading and always returning true */
    *var = *((void **)base);
    return true;
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
    if (ptr < (byte *)PAGE_SIZE)
        return false;
    if (ptr >= last_start && ptr < last_end)
        return last_ans;
    /* FIXME i#270: DR should provide a section iterator! */
    last_ans = (dr_query_memory_ex(ptr, &info) &&
                info.type == DR_MEMTYPE_IMAGE &&
                TESTALL(DR_MEMPROT_READ | DR_MEMPROT_EXEC, info.prot) &&
                !TEST(DR_MEMPROT_WRITE, info.prot));
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
    if (ptr < (byte *)PAGE_SIZE)
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
    if (ptr < (byte *)PAGE_SIZE)
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
                val1 > (byte *)PAGE_SIZE && is_vtable(val1)) {
                if (leak_safe_read_heap(chunk_start, (void **) &val2) &&
                    val2 > (byte *)PAGE_SIZE && is_vtable(val2)) {
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
        /* A std::string object points at a heap-allocate instance of its internal
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
                (capacity + 1/*null-terminated*/ + 3*sizeof(size_t)/*3 header fields*/
                 == (chunk_end - chunk_start))) {
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
            size_t val;
            if (leak_safe_read_heap(chunk_start, (void **) &val) &&
                val == (chunk_end - chunk_start)) {
                LOG(3, "\tmid-chunk "PFX" is post-size => ok\n", pointer);
                STATS_INC(midchunk_postsize_ptrs);
                return true;
            }
        }
    }

    return false;
}

static void
check_reachability_pointer(byte *pointer, byte *ptr_addr, reachability_data_t *data)
{
    byte *chunk_start = NULL;
    byte *chunk_end = malloc_end(pointer);
    bool add_reachable = false, add_maybe_reachable = false;
    uint flags = 0;
    bool reachable = false;
    if (chunk_end != NULL) {
        flags = malloc_get_client_flags(pointer);
        LOG(3, "\t"PFX" points to chunk "PFX"-"PFX"\n", ptr_addr, pointer, chunk_end);
        chunk_start = pointer;
        reachable = true;
    } else {
        rb_node_t *node = rb_in_node(data->alloc_tree, pointer);
        size_t chunk_size;
        if (node != NULL) {
            rb_node_fields(node, &chunk_start, &chunk_size, NULL);
            chunk_end = chunk_start + chunk_size;
            ASSERT(is_in_heap_region(pointer), "heap data struct inconsistency");
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
            } else if (!TESTANY(MALLOC_MAYBE_REACHABLE | MALLOC_REACHABLE, flags)) {
                add_maybe_reachable = true;
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
    }
    if (reachable) {
        if (data->primary_scan && !TEST(MALLOC_REACHABLE, flags)) {
            add_reachable = true;
            /* if already on the maybe-reachable queue we'll just ignore in
             * the secondary scan
             */
        }
        /* Even if the head is pointed at, if that pointer was reached
         * by a mid-chunk pointer, the target is maybe-reachable
         */
        if (!data->primary_scan && !TEST(MALLOC_MAYBE_REACHABLE, flags))
            add_maybe_reachable = true;
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
    LOG(2, "\nchecking reachability of "PFX"-"PFX"\n", start, end);
    pc = start;
    while (pc < end) {
        /* Skip free and unreadable regions (once we have PR 406328 unreadable
         * regions won't show up in the defined range below but may as well skip
         * here: examples of defined but unreadable today include stack guard
         * pages on Linux or .stab section in a cygwin .exe).
         */
        if (pc >= query_end) {
            if (!dr_query_memory_ex(pc, &info)) {
                /* query on Windows expected to fail at 0x7fff000 */
                ASSERT(IF_WINDOWS_ELSE(pc >= (app_pc)0x7fff0000, false),
                       "dr_query_memory_ex failed");
                IF_X64(ASSERT(false, "update windows max query"));
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
            LOG(4, "query "PFX"-"PFX" prot=%x\n",
                info.base_pc, query_end, info.prot);
            if (!TEST(DR_MEMPROT_READ, info.prot) ||
                /* we skip r-x regions.  FIXME PR 475518: if we have info on
                 * what's been modified since it was loaded we can avoid
                 * potential false negatives here if the r-x was restored.
                 */
                (TESTALL(DR_MEMPROT_READ|DR_MEMPROT_EXEC, info.prot) &&
                 !TEST(DR_MEMPROT_WRITE, info.prot)) ||
#ifdef WINDOWS
                /* FIXME PR 475518: this could result in false negatives: should
                 * track whether unmodified since load.  I'm only doing this
                 * by default w/o PR 475518 impl to avoid .pdata sections so our
                 * unit tests will pass deterministically (PR 485354).
                 */
                (TEST(DR_MEMPROT_READ, info.prot) &&
                 !TEST(DR_MEMPROT_WRITE, info.prot) &&
                 info.type == DR_MEMTYPE_IMAGE) ||
#endif
                /* don't count references in DR data */
                dr_memory_is_dr_internal(pc) ||
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
            pc = cb_next_defined_dword(pc, iter_end);
            if (pc == NULL) {
                pc = iter_end;
                continue;
            }
            defined_end = cb_end_of_defined_region(pc, iter_end);
        }
        LOG(3, "defined range "PFX"-"PFX"\n", pc, defined_end);

        /* For 64-bit we'll need to change _dword and this 4 */
        for (pc = (byte *)ALIGN_FORWARD(pc, 4);
             pc < defined_end && pc + 4 <= defined_end; pc += 4) {
            if (skip_heap) {
                /* Skip heap regions */
                chunk_end = heap_region_end(pc);
                if (chunk_end != NULL) {
                    pc = chunk_end - 4; /* let loop inc bump by 4 */
                    ASSERT(ALIGNED(pc, 4), "heap region end not aligned to 4!");
                    continue;
                }
            }
            /* Now pc points to an aligned and defined (non-heap) 4 bytes */
            /* FIXME: to handle races should we do a safe_read?  but
             * don't want to pay cost on Windows: really want try/except.
             */
            /* FIXME PR 475518: improve performance of all these reads and table
             * lookups: this scan is where the noticeable pause at exit comes
             * from, not the identification of defined regions.
             */
            if (!op_have_defined_info) {
                /* we don't have lists of defined regions so we can easily crash */
                if (safe_read(pc, sizeof(pointer), &pointer))
                    check_reachability_pointer(pointer, pc, data);
            } else  {
                pointer = *((app_pc*)pc);
                check_reachability_pointer(pointer, pc, data);
            }
        }
        pc = (byte *) ALIGN_FORWARD(defined_end, 4);
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
            LOG(2, "thread %d stack is "PFX"-"PFX", sp="PFX"\n",
                dr_get_thread_id(drcontext), stack_base,
                stack_base + stack_size, mc->xsp);
            /* store the region beyond TOS */
            rb_insert(data->stack_tree, stack_base,
                      ((app_pc)mc->xsp) - stack_base, NULL);
        }
    }
    /* we ignore fp/mmx and xmm regs */
    for (reg = REG_START_32; reg <= REG_EDI/*STOP_32 is R15D!*/; reg++) {
        if (!op_have_defined_info || cb_is_register_defined(drcontext, reg)) {
            reg_t val = reg_get_value(reg, mc);
            LOG(4, "thread %d reg %d: "PFX"\n", dr_get_thread_id(drcontext), reg, val);
            check_reachability_pointer((byte *)val, (byte *)(ptr_uint_t)reg/*diagnostic*/,
                                       data);
        }
    }
}

static void
malloc_iterate_cb(app_pc start, app_pc end, app_pc real_end,
                  bool pre_us, uint client_flags,
                  void *client_data, void *iter_data)
{
    ASSERT(start != NULL && start <= end, "invalid params");
    LOG(4, "malloc iter: "PFX"-"PFX"%s%s%s%s\n", start, end,
        pre_us ? ", pre-us" : "",
        TEST(MALLOC_IGNORE_LEAK, client_flags) ? ", ignore leak" : "",
        TEST(MALLOC_REACHABLE, client_flags) ? ", reachable" : "", 
        TEST(MALLOC_MAYBE_REACHABLE, client_flags) ? ", maybe reachable" : "");
    if (!TEST(MALLOC_IGNORE_LEAK, client_flags)) {
        client_found_leak(start, end, pre_us,
                          TEST(MALLOC_REACHABLE, client_flags), 
                          TEST(MALLOC_MAYBE_REACHABLE, client_flags),
                          client_data);
    }
    /* clear for any subsequent reachability walks */
    malloc_clear_client_flag(start, MALLOC_REACHABLE | MALLOC_MAYBE_REACHABLE);
}

static void
malloc_iterate_build_tree_cb(app_pc start, app_pc end, app_pc real_end,
                             bool pre_us, uint client_flags,
                             void *client_data, void *iter_data)
{
    rb_tree_t *alloc_tree = (rb_tree_t *) iter_data;
    ASSERT(alloc_tree != NULL, "invalid iteration data");
    rb_insert(alloc_tree, start, (end - start), NULL);
}

void
leak_scan_for_leaks(bool at_exit)
{
    pc_entry_t *e, *next_e;
    void **drcontexts = NULL;
    uint num_threads, i;
    dr_mcontext_t mc;
    reachability_data_t data;
#ifdef DEBUG
    static bool called_at_exit;
    if (at_exit) {
        /* we only clear the flags on nudges, so only 1 at_exit supported */
        ASSERT(!called_at_exit, "check_reachability only supports 1 call at_exit");
        called_at_exit = true;
    }
#endif
    LOG(1, "checking leaks via reachability analysis\n");

    /* Strategy: First walk non-heap memory that is defined to find reachable
     * heap blocks.  (Ideally we would skip memory that has not been modified
     * since startup -- .rodata cannot point into heap of course -- but we don't
     * know that even w/ the special shadow blocks.  PR 475518 covers adding
     * that info.)  Then walk those heap blocks to find what they reach.  Assume
     * pointers are aligned.  For now only considering pointers to the start of
     * a heap block: we'll see how many false positives we hit with that.
     */
    if (at_exit && op_have_defined_info) {
        /* We assume no synch is needed at exit time, and that we
         * can ignore thread registers as roots of the search.
         * if no defined info we need to walk the thread stacks.
         */
    } else {
        /* PR 428709: reachability mid-run */
        if (!dr_suspend_all_other_threads(&drcontexts, &num_threads, NULL)) {
            LOG(0, "WARNING: not all threads suspended for reachability analysis\n");
            /* We carry on and live w/ the raciness */
        }
    }

    memset(&data, 0, sizeof(data));
    data.primary_scan = true;
    data.alloc_tree = rb_tree_create(NULL);
    data.stack_tree = rb_tree_create(NULL);

    /* Build tree for interval lookup for mid-chunk pointers (PR 476482).
     * Since doing this just once, we could use an array, but tree may be
     * useful later on.  I have measured the cost of having the malloc
     * hashtable be an rbtree instead, avoiding this creation, but the extra
     * overhead shows up on heap-intensive bmarks (PR 535568).
     */
    malloc_iterate(malloc_iterate_build_tree_cb, (void *) data.alloc_tree);

    if (!at_exit || !op_have_defined_info) {
        /* Walk the thread's registers.  We rely on mcontext field ordering here. */
        void *my_drcontext = dr_get_current_drcontext();
        for (i = 0; i < num_threads; i++) {
            LOG(3, "\nwalking registers of thread %d\n", dr_get_thread_id(drcontexts[i]));
            dr_get_mcontext(drcontexts[i], &mc, NULL);
            check_reachability_regs(drcontexts[i], &mc, &data);
        }
        LOG(3, "\nwalking registers of thread %d\n", dr_get_thread_id(my_drcontext));
        dr_get_mcontext(my_drcontext, &mc, NULL);
        check_reachability_regs(my_drcontext, &mc, &data);
    } else
        ASSERT(drcontexts == NULL, "inconsistency in thread suspension");

    check_reachability_helper(NULL, (app_pc)POINTER_MAX, true/*skip heap*/, &data);
    LOG(3, "\nwalking reachable-chunk queue\n");
    for (e = data.reachq_head; e != NULL; e = next_e) {
        check_reachability_helper(e->start, e->end, false, &data);
        next_e = e->next;
        global_free(e, sizeof(*e), HEAPSTAT_MISC);
    }

    LOG(3, "\nwalking maybe-reachable-chunk queue\n");
    data.primary_scan = false;
    for (e = data.midreachq_head; e != NULL; e = next_e) {
        if (TEST(MALLOC_REACHABLE, malloc_get_client_flags(e->start))) {
            /* This was later marked as fully-reachable and added to reachq,
             * so ignore it here
             */
        } else {
            check_reachability_helper(e->start, e->end, false, &data);
        }
        next_e = e->next;
        global_free(e, sizeof(*e), HEAPSTAT_MISC);
    }

    if (!at_exit || !op_have_defined_info) {
        IF_DEBUG(bool ok;)
        if (!at_exit) {
            /* up to caller to call report_leak_stats_{checkpoint,revert} if desired */
            malloc_iterate(malloc_iterate_cb, NULL);
        }
        ASSERT(drcontexts != NULL, "dr_suspend_all_other_threads never fails");
        if (drcontexts != NULL) {
            IF_DEBUG(ok =)
                dr_resume_all_other_threads(drcontexts, num_threads);
            ASSERT(ok, "failed to resume after leak scan");
        }
    }

    /* We do not maintain the tree throughout execution: we make a new one for
     * each reachability scan.
     */
    rb_tree_destroy(data.alloc_tree);
    rb_tree_destroy(data.stack_tree);
}
