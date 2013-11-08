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

/* windows kernel handle leak checks */

#include "handlecheck.h"
#include "drmemory.h"
#include "callstack.h"
#include "syscall.h"
#include "drsyscall.h"

#ifndef WINDOWS
# error WINDOWS-only
#endif

#ifdef STATISTICS
static uint num_handle_add;
static uint num_handle_remove;
#endif /* STATISTICS */

/* handle table payload */
typedef struct _handle_callstack_info_t {
    app_loc_t loc;
    packed_callstack_t *pcs;
} handle_callstack_info_t;

typedef struct _open_close_pair_t {
    handle_callstack_info_t open;  /* handle open info */
    handle_callstack_info_t close; /* handle close info */
} open_close_pair_t;

#define HANDLE_VERBOSE_1 1
#define HANDLE_VERBOSE_2 2
#define HANDLE_VERBOSE_3 3

/* Hashtable for handle open/close callstack */
#define HSTACK_TABLE_HASH_BITS 8
static hashtable_t handle_stack_table;
#ifdef STATISTICS
uint handle_stack_count;
#endif

/* Hashtable for handle open/close pair, synchronized by
 * explicit hashtable lock.
 */
#define OPEN_CLOSE_TABLE_BITS 8
static hashtable_t open_close_table;
#ifdef STATISTICS
uint open_close_count;
#endif

/* Table of handle entries: [handle, hci]
 * there are multiple handle namespaces: kernel object, gdi object, user object,
 * and they are disjoint, so we have different hashtables for each type.
 */
/* we use handle_stack_table lock for synchronizing all table operations */
#define HANDLE_TABLE_HASH_BITS 6
static hashtable_t kernel_handle_table;
static hashtable_t gdi_handle_table;
static hashtable_t user_handle_table;

#ifdef DEBUG
static void
open_close_pair_print(open_close_pair_t *pair)
{
    LOG(HANDLE_VERBOSE_2, "Handle open/close pair:\n");
    LOG(HANDLE_VERBOSE_2, "Handle open stack:\n");
    DOLOG(HANDLE_VERBOSE_2, {
        packed_callstack_log(pair->open.pcs, INVALID_FILE);
    });
    LOG(HANDLE_VERBOSE_2, "Handle close stack:\n");
    DOLOG(HANDLE_VERBOSE_2, {
        packed_callstack_log(pair->close.pcs, INVALID_FILE);
    });
}
#endif

static void
open_close_pair_free(void *p)
{
    open_close_pair_t *pair = (open_close_pair_t *)p;

    DODEBUG({ open_close_pair_print(pair); });
    packed_callstack_free(pair->open.pcs);
    packed_callstack_free(pair->close.pcs);
    global_free(pair, sizeof(*pair), HEAPSTAT_CALLSTACK);
}

/* Add open/close pair into table, assuming lock is held.
 * Called from handlecheck_delete_handle_post_syscall if the handle
 * is closed successfully.
 */
static void
open_close_pair_add(handle_callstack_info_t *hci/* callstack of creation */,
                    drsys_sysnum_t sysnum,
                    dr_mcontext_t *mc/* context of close */)
{
    open_close_pair_t *pair;
    IF_DEBUG(bool res;)

    if (!options.filter_handle_leaks)
        return;
    pair = (open_close_pair_t *)hashtable_lookup(&open_close_table, hci->pcs);
    /* we only store one close pcs if there are multiple */
    if (pair != NULL)
        return;

    pair = global_alloc(sizeof(*pair), HEAPSTAT_CALLSTACK);
    /* not clone but point to the same pcs */
    pair->open = *hci;
    packed_callstack_add_ref(hci->pcs);
    IF_DEBUG(res =)
        hashtable_add(&open_close_table, (void *)hci->pcs, (void *)pair);
    ASSERT(res, "failed to add to open_close_table");
    ASSERT(packed_callstack_cmp(pair->open.pcs, hci->pcs), "pcs should be the same");
    syscall_to_loc(&pair->close.loc, sysnum, NULL);
    packed_callstack_record(&pair->close.pcs, mc, &pair->close.loc);
    pair->close.pcs = packed_callstack_add_to_table(&handle_stack_table,
                                                    pair->close.pcs
                                                    _IF_STATS(&handle_stack_count));
}

static void
handle_table_lock(void)
{
    /* we use handle_stack_table lock for synchronizing all table operations */
    hashtable_lock(&handle_stack_table);
}

static void
handle_table_unlock(void)
{
    /* we use handle_stack_table lock for synchronizing all table operations */
    hashtable_unlock(&handle_stack_table);
}

void
handle_callstack_free(void *p)
{
    packed_callstack_destroy((packed_callstack_t *)p);
}

static handle_callstack_info_t *
handle_callstack_info_clone(handle_callstack_info_t *src)
{
    handle_callstack_info_t *dst;
    dst = global_alloc(sizeof(*src), HEAPSTAT_CALLSTACK);
    *dst = *src;
    packed_callstack_add_ref(dst->pcs);
    return dst;
}

/* the caller must hold the lock */
static handle_callstack_info_t *
handle_callstack_info_alloc(drsys_sysnum_t sysnum, app_pc pc, dr_mcontext_t *mc)
{
    handle_callstack_info_t *hci;
    hci = global_alloc(sizeof(*hci), HEAPSTAT_CALLSTACK);
    /* assuming pc will never be NULL */
    if (pc == NULL)
        syscall_to_loc(&hci->loc, sysnum, NULL);
    else
        pc_to_loc(&hci->loc, pc);
    packed_callstack_record(&hci->pcs, mc, &hci->loc);
    hci->pcs = packed_callstack_add_to_table(&handle_stack_table, hci->pcs
                                             _IF_STATS(&handle_stack_count));
    return hci;
}

static void
handle_callstack_info_free(handle_callstack_info_t *hci)
{
    uint count;
    count = packed_callstack_free(hci->pcs);
    LOG(4, "%s: freed pcs "PFX" => refcount %d\n", __FUNCTION__, hci->pcs, count);
    global_free(hci, sizeof(*hci), HEAPSTAT_CALLSTACK);
}

/* the caller must hold hashtable lock */
static bool
handlecheck_handle_add(hashtable_t *table, HANDLE handle,
                       handle_callstack_info_t *hci)
{
    void *res;

    STATS_INC(num_handle_add);
    res = hashtable_add_replace(table, (void *)handle, (void *)hci);
    if (res != NULL) {
        handle_callstack_info_free(res);
        LOG(HANDLE_VERBOSE_1, "Error: duplicated handle in handle table\n");
        return false;
    }
    return true;
}

/* the caller must hold hashtable lock */
static bool
handlecheck_handle_remove(hashtable_t *table, HANDLE handle,
                          handle_callstack_info_t **hci OUT)
{
    bool res;

    STATS_INC(num_handle_remove);
    if (hci != NULL) {
        handle_callstack_info_t *info;
        info = hashtable_lookup(table, (void *)handle);
        if (info != NULL)
            *hci = handle_callstack_info_clone(info);
        else 
            *hci = NULL;
    }
    res = hashtable_remove(table, (void *)handle);
    return res;
}

#define HANDLECHECK_PRE_MSG_SIZE 0x100

void
handlecheck_report_leak_on_syscall(dr_mcontext_t *mc, drsys_arg_t *arg)
{
    handle_callstack_info_t *hci;
    char msg[HANDLECHECK_PRE_MSG_SIZE];
    const char *name;
    /* Some system call like NtDuplicateObject may leak the handle by passing
     * NULL to the out handle argument, so we assume that the leak on syscall
     * is only caused by the arg PHANDLE being NULL.
     */
    ASSERT(arg->value == (ptr_uint_t)NULL, "syscall arg value is not NULL");
    hci = handle_callstack_info_alloc(arg->sysnum, NULL, mc);
    if (drsys_syscall_name(arg->syscall, &name) != DRMF_SUCCESS)
        name = "<unknown>";
    /* We do not have the leaked handle value, so we report leak without
     * value. We could passing our own ptr to get the value, which may have
     * transparency problems.
     */
    dr_snprintf(msg, BUFFER_SIZE_ELEMENTS(msg),
                "Syscall %s leaks handle with NULL handle pointer.",
                name);
    report_handle_leak(dr_get_current_drcontext(), msg, &hci->loc, hci->pcs,
                       NULL /* aux_pcs */, false /* potential */);
    /* add the pair info */
    handle_callstack_info_free(hci);
}

static void
handlecheck_iterate_handle_table(void *drcontext, hashtable_t *table, char *name)
{
    uint i;
    char msg[HANDLECHECK_PRE_MSG_SIZE];
    handle_table_lock();
    hashtable_lock(&open_close_table);
    for (i = 0; i < HASHTABLE_SIZE(table->table_bits); i++) {
        hash_entry_t *entry, *next;
        for (entry = table->table[i]; entry != NULL; entry = next) {
            HANDLE handle = (HANDLE)entry->key;
            handle_callstack_info_t *hci = (handle_callstack_info_t *) entry->payload;
            open_close_pair_t *pair;
            bool potential = false;
            uint count;
            next  = entry->next;
            pair  = hashtable_lookup(&open_close_table, (void *)hci->pcs);
            count = packed_callstack_refcount(hci->pcs) - 1/* hashtable refcount */;
            /* i#1373: use heuristics for better handle leak reports */
            if (options.filter_handle_leaks) {
                if (pair != NULL) {
                    /* Heuristic 1: for each left-open-handle, we check if there is
                     * any handle being opened with the same callstack and being closed
                     * somewhere. If we see such cases, it means that all handles opened
                     * at that site should probably be closed.
                     */
                    count--; /* pair table refcount */
                } else if (count >= options.handle_leak_threshold) {
                    /* Heuristic 2: if too many handles opened from the same callstack
                     * left open, it should be paid attention to, so report it.
                     */
                } else {
                    /* no heuristic is applied, report it as potential error */
                    potential = true;
                }
            }
            dr_snprintf(msg, BUFFER_SIZE_ELEMENTS(msg),
                        "%s Handle "PFX" and %d similar handles were opened"
                        " but not closed:", name, handle, count);
            report_handle_leak(drcontext, msg, &hci->loc, hci->pcs,
                               (pair == NULL) ? NULL : pair->close.pcs,
                               potential);
        }
    }
    hashtable_unlock(&open_close_table);
    handle_table_unlock();
}

static void
handlecheck_iterate_handles(void)
{
    void *drcontext = dr_get_current_drcontext();
    LOG(HANDLE_VERBOSE_3, "iterating kernel handle table");
    handlecheck_iterate_handle_table(drcontext, &kernel_handle_table, "Kernel");
    LOG(HANDLE_VERBOSE_3, "iterating gdi handle table");
    handlecheck_iterate_handle_table(drcontext, &gdi_handle_table, "GDI");
    LOG(HANDLE_VERBOSE_3, "iterating user handle table");
    handlecheck_iterate_handle_table(drcontext, &user_handle_table, "USER");
}

static inline hashtable_t *
handlecheck_get_handle_table(int type
                             _IF_DEBUG(void *handle)
                             _IF_DEBUG(const char *msg))
{
    hashtable_t *table;
    switch (type) {
    case HANDLE_TYPE_KERNEL:
        LOG(HANDLE_VERBOSE_2, "kernel handle "PFX" is %s\n", handle, msg);
        table = &kernel_handle_table;
        break;
    case HANDLE_TYPE_GDI:
        LOG(HANDLE_VERBOSE_2, "gdi handle "PFX" is %s\n", handle, msg);
        table = &gdi_handle_table;
        break;
    case HANDLE_TYPE_USER:
        LOG(HANDLE_VERBOSE_2, "user handle "PFX" is %s\n", handle, msg);
        table = &user_handle_table;
        break;
    default:
        table = &kernel_handle_table; /* for release build */
        ASSERT(false, "wrong handle type for creation");
    }
    return table;
}

void
handlecheck_init(void)
{
    ASSERT(options.check_handle_leaks, "incorrectly called");
    hashtable_init_ex(&kernel_handle_table, HANDLE_TABLE_HASH_BITS, HASH_INTPTR,
                      false/*!str_dup*/, false/*!synch*/,
                      handle_callstack_info_free, NULL, NULL);
    hashtable_init_ex(&gdi_handle_table, HANDLE_TABLE_HASH_BITS, HASH_INTPTR,
                      false/*!str_dup*/, false/*!synch*/,
                      handle_callstack_info_free, NULL, NULL);
    hashtable_init_ex(&user_handle_table, HANDLE_TABLE_HASH_BITS, HASH_INTPTR,
                      false/*!str_dup*/, false/*!synch*/,
                      handle_callstack_info_free, NULL, NULL);
    hashtable_init_ex(&handle_stack_table, HSTACK_TABLE_HASH_BITS, HASH_CUSTOM,
                      false /*!str_dup*/, false /*!synch*/,
                      handle_callstack_free,
                      (uint (*)(void*)) packed_callstack_hash,
                      (bool (*)(void*, void *)) packed_callstack_cmp);
    hashtable_init_ex(&open_close_table, OPEN_CLOSE_TABLE_BITS, HASH_CUSTOM,
                      false /*!str_dup*/, false /*!synch*/,
                      open_close_pair_free,
                      (uint (*)(void*)) packed_callstack_hash,
                      (bool (*)(void*, void *)) packed_callstack_cmp);
}

void
handlecheck_exit(void)
{
    ASSERT(options.check_handle_leaks, "incorrectly called");
    handlecheck_iterate_handles();
    hashtable_delete_with_stats(&kernel_handle_table,  "Kernel handle table");
    hashtable_delete_with_stats(&gdi_handle_table,     "GDI handle table");
    hashtable_delete_with_stats(&user_handle_table,    "USER handle table");
    hashtable_delete_with_stats(&open_close_table, "Alloc/free pair table");
    hashtable_delete_with_stats(&handle_stack_table,   "Handle stack table");
}

void
handlecheck_create_handle(void *drcontext, HANDLE handle, int type,
                          drsys_sysnum_t sysnum, app_pc pc, dr_mcontext_t *mc)
{
    handle_callstack_info_t *hci;
    hashtable_t *table;

    if (handle == INVALID_HANDLE_VALUE) {
        LOG(HANDLE_VERBOSE_1, "WARNING: application opened an invalid handle\n");
        return;
    }
    if (handle == (HANDLE)0) {
        LOG(HANDLE_VERBOSE_1, "WARNING: handle value is 0\n");
    }
    table = handlecheck_get_handle_table(type
                                         _IF_DEBUG((void *)handle)
                                         _IF_DEBUG("opened"));
    ASSERT(table != NULL, "fail to get handle table");
    handle_table_lock();
    hci = handle_callstack_info_alloc(sysnum, pc, mc);
    DOLOG(HANDLE_VERBOSE_3, { packed_callstack_log(hci->pcs, INVALID_FILE); });
    if (!handlecheck_handle_add(table, handle, hci)) {
        LOG(HANDLE_VERBOSE_1, "WARNING: fail to add handle "PFX"\n", handle);
    }
    handle_table_unlock();
}

void *
handlecheck_delete_handle(void *drcontext, HANDLE handle, int type,
                          drsys_sysnum_t sysnum, app_pc pc, dr_mcontext_t *mc)
{
    hashtable_t *table;
    handle_callstack_info_t *hci;

    if (handle == INVALID_HANDLE_VALUE) {
        LOG(HANDLE_VERBOSE_1, "WARNING: invalid handle to delete\n");
        return NULL;
    }
    table = handlecheck_get_handle_table(type
                                         _IF_DEBUG((void *)handle)
                                         _IF_DEBUG("deleted"));
    ASSERT(table != NULL, "fail to get handle table");
    DOLOG(HANDLE_VERBOSE_3, { report_callstack(drcontext, mc); });
    handle_table_lock();
    if (!handlecheck_handle_remove(table, handle, &hci)) {
        LOG(HANDLE_VERBOSE_1, "WARNING: fail to remove handle "PFX"\n", handle);
    }
    handle_table_unlock();
    return (void *)hci;
}

void
handlecheck_delete_handle_post_syscall(void *drcontext, HANDLE handle,
                                       drsys_sysnum_t sysnum, dr_mcontext_t *mc,
                                       int type, void *handle_info, bool success)
{
    handle_callstack_info_t *hci;
    hashtable_t *table;

    if (handle_info == NULL) {
        if (success) {
            LOG(HANDLE_VERBOSE_1,
                "WARNING: delete handle succeeded unexpectedly");
        } else {
            LOG(HANDLE_VERBOSE_1,
                "WARNING: no handle info for adding back\n");
        }
        return;
    }
    hci = (handle_callstack_info_t *)handle_info;
    if (success) {
        /* add the pair info */
        if (options.filter_handle_leaks) {
            hashtable_lock(&open_close_table);
            open_close_pair_add(hci, sysnum, mc);
            hashtable_unlock(&open_close_table);
        }
        /* closed handle successfully, free the handle info now */
        handle_callstack_info_free(hci);
    } else {
        /* failed to delete handle, add handle back */
        ASSERT(handle != INVALID_HANDLE_VALUE, "add back invalid handle value");
        table = handlecheck_get_handle_table(type
                                             _IF_DEBUG((void *)handle)
                                             _IF_DEBUG("added back"));
        ASSERT(table != NULL, "fail to get handle table");
        DOLOG(HANDLE_VERBOSE_3, { packed_callstack_log(hci->pcs, INVALID_FILE); });
        handle_table_lock();
        if (!handlecheck_handle_add(table, handle, hci)) {
            LOG(HANDLE_VERBOSE_1,
                "WARNING: failed to add handle "PFX" back\n", handle);
        }
        handle_table_unlock();
    }
}

#ifdef STATISTICS
void
handlecheck_dump_statistics(void)
{
    dr_fprintf(f_global, "handles opened: %6u, closed: %6u\n",
               num_handle_add, num_handle_remove);
}
#endif /* STATISTICS */

void
handlecheck_nudge(void *drcontext)
{
    handlecheck_iterate_handles();
}
