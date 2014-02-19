/* **********************************************************
 * Copyright (c) 2014 Google, Inc.  All rights reserved.
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
#include "drsyscall.h"
#include "drsyscall_os.h"

#include <sys/syscall.h>
#include <string.h>

/* FIXME i#1440: port Dr. Syscall to Mac OSX */

/***************************************************************************
 * SYSTEM CALLS FOR MAC
 */

/* 64-bit and 32-bit have the same numbers, which is convenient */

/* Table that maps system call number to a syscall_info_t* */
#define SYSTABLE_HASH_BITS 9 /* ~2x the # of entries */
hashtable_t systable;

#define OK (SYSINFO_ALL_PARAMS_KNOWN)
#define UNKNOWN 0
#define W (SYSARG_WRITE)
#define R (SYSARG_READ)
#define WI (SYSARG_WRITE | SYSARG_LENGTH_INOUT)
#define CT (SYSARG_COMPLEX_TYPE)
#define HT (SYSARG_HAS_TYPE)
#define CSTRING (SYSARG_TYPE_CSTRING)
#define RET (SYSARG_POST_SIZE_RETVAL)
#define RLONG (DRSYS_TYPE_SIGNED_INT) /* they all return type "long" */
static syscall_info_t syscall_info[] = {
    /* FIXME i#1440: fill in this table for BSD syscalls */
    {{SYS_read},"read", OK, RLONG, 3,
     {
         {1, -2, W},
         {1, RET, W},
     }
    },
};
#define NUM_SYSCALL_STATIC_ENTRIES (sizeof(syscall_info)/sizeof(syscall_info[0]))

/* FIXME i#1440: add mach syscall table */

/* FIXME i#1440: add machdep syscall table */

#undef OK
#undef UNKNOWN
#undef W
#undef R
#undef WI
#undef CT
#undef HT
#undef CSTRING
#undef RET
#undef RLONG

/***************************************************************************
 * PER-SYSCALL HANDLING
 */

void
os_handle_pre_syscall(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    switch (ii->arg->sysnum.number) {
        /* FIXME i#1440: add handling */
    }
    /* If you add any handling here: need to check ii->abort first */
}

void
os_handle_post_syscall(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    /* each handler checks result for success */
    switch (ii->arg->sysnum.number) {
        /* FIXME i#1440: add handling */
    }
    /* If you add any handling here: need to check ii->abort first */
}

/***************************************************************************
 * SHADOW PER-ARG-TYPE HANDLING
 */

static bool
os_handle_syscall_arg_access(sysarg_iter_info_t *ii,
                             const sysinfo_arg_t *arg_info,
                             app_pc start, uint size)
{
    if (!TEST(SYSARG_COMPLEX_TYPE, arg_info->flags))
        return false;

    switch (arg_info->misc) {
        /* FIXME i#1440: add handling -- probably want SYSARG_TYPE_CSTRING,
         * SYSARG_TYPE_SOCKADDR, DRSYS_TYPE_CSTRARRAY?  Share w/ Linux?
         */
    }
    return false;
}

bool
os_handle_pre_syscall_arg_access(sysarg_iter_info_t *ii,
                                 const sysinfo_arg_t *arg_info,
                                 app_pc start, uint size)
{
    return os_handle_syscall_arg_access(ii, arg_info, start, size);
}

bool
os_handle_post_syscall_arg_access(sysarg_iter_info_t *ii,
                                  const sysinfo_arg_t *arg_info,
                                  app_pc start, uint size)
{
    return os_handle_syscall_arg_access(ii, arg_info, start, size);
}

/***************************************************************************
 * TOP_LEVEL
 */

/* Table that maps syscall names to numbers.  Payload points at num in syscall_info[]. */
#define NAME2NUM_TABLE_HASH_BITS 10 /* <500 of them */
static hashtable_t name2num_table;

drmf_status_t
drsyscall_os_init(void *drcontext)
{
    uint i;
    hashtable_init_ex(&systable, SYSTABLE_HASH_BITS, HASH_INTPTR, false/*!strdup*/,
                      false/*!synch*/, NULL, sysnum_hash, sysnum_cmp);

    hashtable_init(&name2num_table, NAME2NUM_TABLE_HASH_BITS, HASH_STRING,
                   false/*!strdup*/);

    dr_recurlock_lock(systable_lock);
    for (i = 0; i < NUM_SYSCALL_STATIC_ENTRIES; i++) {
        IF_DEBUG(bool ok =)
            hashtable_add(&systable, (void *) &syscall_info[i].num,
                          (void *) &syscall_info[i]);
        ASSERT(ok, "no dups");

        IF_DEBUG(ok =)
            hashtable_add(&name2num_table, (void *) syscall_info[i].name,
                          (void *) &syscall_info[i].num);
        ASSERT(ok || strcmp(syscall_info[i].name, "ni_syscall") == 0, "no dups");
    }
    dr_recurlock_unlock(systable_lock);
    return DRMF_SUCCESS;
}

void
drsyscall_os_exit(void)
{
    hashtable_delete(&systable);
    hashtable_delete(&name2num_table);
}

void
drsyscall_os_thread_init(void *drcontext)
{
}

void
drsyscall_os_thread_exit(void *drcontext)
{
}

void
drsyscall_os_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
}

bool
os_syscall_get_num(const char *name, drsys_sysnum_t *num_out OUT)
{
    drsys_sysnum_t *num = (drsys_sysnum_t *)
        hashtable_lookup(&name2num_table, (void *)name);
    if (num != NULL) {
        *num_out = *num;
        return true;
    }
    return false;
}

/* Either sets arg->reg to DR_REG_NULL and sets arg->start_addr, or sets arg->reg
 * to non-DR_REG_NULL
 */
void
drsyscall_os_get_sysparam_location(cls_syscall_t *pt, uint argnum, drsys_arg_t *arg)
{
#ifdef X64
    switch (argnum) {
    case 0: arg->reg = DR_REG_RDI;
    case 1: arg->reg = DR_REG_RSI;
    case 2: arg->reg = DR_REG_RDX;
    case 3: arg->reg = DR_REG_R10; /* rcx = retaddr for OP_syscall */
    case 4: arg->reg = DR_REG_R8;
    case 5: arg->reg = DR_REG_R9;
    default: arg->reg = DR_REG_NULL; /* error */
    }
    arg->start_addr = NULL;
#else
    /* Args are on stack, past retaddr from syscall wrapper */
    arg->reg = DR_REG_NULL;
    arg->start_addr = (app_pc) (((reg_t *)arg->mc->esp) + 1/*retaddr*/ + argnum);
#endif
}

drmf_status_t
drsys_syscall_type(drsys_syscall_t *syscall, drsys_syscall_type_t *type OUT)
{
    if (syscall == NULL || type == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    *type = DRSYS_SYSCALL_TYPE_KERNEL;
    return DRMF_SUCCESS;
}

bool
os_syscall_succeeded(drsys_sysnum_t sysnum, syscall_info_t *info, ptr_int_t res)
{
    /* FIXME i#1440: need to pass in mcxt for eflags CF */
    return true;
}
