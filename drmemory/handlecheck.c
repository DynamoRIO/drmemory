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

#ifndef WINDOWS
# error WINDOWS-only
#endif

#ifdef STATISTICS
static uint num_handle_add;
static uint num_handle_remove;
#endif /* STATISTICS */

/* handle table payload */
typedef struct _handle_create_info_t {
    app_loc_t loc;
    packed_callstack_t *pcs;
} handle_create_info_t;

/* Table of handle entries: [handle, hci]
 * there are multiple handle namespaces: kernel object, gdi object, user object,
 * and they are disjoint, so we have different hashtables for each type.
 */
#define HANDLE_TABLE_HASH_BITS 6
static hashtable_t kernel_handle_table;
static hashtable_t gdi_handle_table;
static hashtable_t user_handle_table;


static handle_create_info_t *
handle_create_info_alloc(int sysnum, app_pc pc, dr_mcontext_t *mc)
                         
{
    handle_create_info_t *hci;
    hci = global_alloc(sizeof(*hci), HEAPSTAT_CALLSTACK);
    /* assuming pc will never be NULL */
    if (pc == NULL)
        syscall_to_loc(&hci->loc, sysnum, NULL);
    else
        pc_to_loc(&hci->loc, pc);
    packed_callstack_record(&hci->pcs, mc, &hci->loc);
    return hci;
}

static void
handle_create_info_free(handle_create_info_t *hci)
{
    packed_callstack_free(hci->pcs);
    global_free(hci, sizeof(*hci), HEAPSTAT_CALLSTACK);
}

static bool
handlecheck_handle_add(hashtable_t *table, HANDLE handle,
                       handle_create_info_t *hci)
{
    void *res;

    STATS_INC(num_handle_add);
    res = hashtable_add_replace(table, (void *)handle, (void *)hci);
    if (res != NULL) {
        handle_create_info_free(res);
        LOG(1, "Error: duplicated handle in handle table");
        return false;
    }
    return true;
}

static bool
handlecheck_handle_remove(hashtable_t *table, HANDLE handle)
{
    bool res;

    STATS_INC(num_handle_remove);
    res = hashtable_remove(table, (void *)handle);
    return res;
}

#define HANDLECHECK_PRE_MSG_SIZE 0x100
static void
handlecheck_iterate_handle_table(void *drcontext, hashtable_t *table, char *name)
{
    uint i;
    char msg[HANDLECHECK_PRE_MSG_SIZE];
    hashtable_lock(table);
    for (i = 0; i < HASHTABLE_SIZE(table->table_bits); i++) {
        hash_entry_t *entry, *next;
        for (entry = table->table[i]; entry != NULL; entry = next) {
            HANDLE handle = (HANDLE)entry->key;
            handle_create_info_t *hci = (handle_create_info_t *) entry->payload;
            next = entry->next;
            dr_snprintf(msg, BUFFER_SIZE_ELEMENTS(msg),
                        "%s Handle "PFX" was opened but not closed:", name, handle);
            report_handle_leak(drcontext, msg, &hci->loc, hci->pcs);
        }
    }
    hashtable_unlock(table);
}

static void
handlecheck_iterate_handles(void)
{
    void *drcontext = dr_get_current_drcontext();
    LOG(3, "iterating kernel handle table");
    handlecheck_iterate_handle_table(drcontext, &kernel_handle_table, "Kernel");
    LOG(3, "iterating gdi handle table");
    handlecheck_iterate_handle_table(drcontext, &gdi_handle_table, "GDI");
    LOG(3, "iterating user handle table");
    handlecheck_iterate_handle_table(drcontext, &user_handle_table, "USER");
}

void
handlecheck_init(void)
{
    ASSERT(options.check_handle_leaks, "incorrectly called");
    hashtable_init_ex(&kernel_handle_table, HANDLE_TABLE_HASH_BITS, HASH_INTPTR,
                      false/*!str_dup*/, true/*synch*/,
                      handle_create_info_free, NULL, NULL);
    hashtable_init_ex(&gdi_handle_table, HANDLE_TABLE_HASH_BITS, HASH_INTPTR,
                      false/*!str_dup*/, true/*synch*/,
                      handle_create_info_free, NULL, NULL);
    hashtable_init_ex(&user_handle_table, HANDLE_TABLE_HASH_BITS, HASH_INTPTR,
                      false/*!str_dup*/, true/*synch*/,
                      handle_create_info_free, NULL, NULL);
}

void
handlecheck_exit(void)
{
    ASSERT(options.check_handle_leaks, "incorrectly called");
    handlecheck_iterate_handles();
    hashtable_delete_with_stats(&kernel_handle_table, "Kernel Handle Table");
    hashtable_delete_with_stats(&gdi_handle_table,    "GDI Handle table");
    hashtable_delete_with_stats(&user_handle_table,   "USER Handle table");
}

void
handlecheck_create_handle(void *drcontext, HANDLE handle, int type,
                          int sysnum, app_pc pc, dr_mcontext_t *mc)
{
    handle_create_info_t *hci;
    hashtable_t *table;

    if (handle == INVALID_HANDLE_VALUE) {
        LOG(1, "WARNING: application created an invalid handle");
        return;
    }
    switch (type) {
    case HANDLE_TYPE_KERNEL:
        LOG(2, "kernel handle "PFX" is created\n", (void *)handle);
        table = &kernel_handle_table;
        break;
    case HANDLE_TYPE_GDI:
        LOG(2, "gdi handle "PFX" is created\n", (void *)handle);
        table = &gdi_handle_table;
        break;
    case HANDLE_TYPE_USER:
        LOG(2, "user handle "PFX" is created\n", (void *)handle);
        table = &user_handle_table;
        break;
    default:
        ASSERT(false, "wrong handle type for creation");
    }

    hci = handle_create_info_alloc(sysnum, pc, mc);;
    DOLOG(3, { packed_callstack_log(hci->pcs, INVALID_FILE); });
    if (!handlecheck_handle_add(table, handle, hci)) {
        LOG(1, "WARNING: fail to add handle "PFX"\n", handle);
    }
}

void
handlecheck_delete_handle(void *drcontext, HANDLE handle, int type,
                          int sysnum, app_pc pc, dr_mcontext_t *mc)
{
    hashtable_t *table;

    if (handle == INVALID_HANDLE_VALUE) {
        LOG(1, "WARNING: invalid handle to delete");
        return;
    }
    switch (type) {
    case HANDLE_TYPE_KERNEL:
        LOG(2, "kernel handle "PFX" is deleted\n", (void *)handle);
        table = &kernel_handle_table;
        break;
    case HANDLE_TYPE_GDI:
        LOG(2, "gdi handle "PFX" is deleted\n", (void *)handle);
        table = &gdi_handle_table;
        break;
    case HANDLE_TYPE_USER:
        LOG(2, "user handle "PFX" is deleted\n", (void *)handle);
        table = &user_handle_table;
        break;
    default:
        ASSERT(false, "wrong handle type for deletion");
    }

    DOLOG(3, {
        handle_create_info_t *hci = handle_create_info_alloc(sysnum, pc, mc);
        packed_callstack_log(hci->pcs, INVALID_FILE);
        handle_create_info_free(hci);
    });
    if (!handlecheck_handle_remove(table, handle)) {
        LOG(1, "WARNING: fail to remove handle "PFX"\n", handle);
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
