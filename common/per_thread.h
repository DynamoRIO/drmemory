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

#ifndef _PER_THREAD_H_
#define _PER_THREAD_H_ 1

/***************************************************************************
 * DATA SHARING ACROSS MODULES
 *
 * The user must set up a per_thread_t pointer in the drcontext tls.
 */

#ifdef WINDOWS
# define SYSCALL_NUM_ARG_STORE 10
#else
# define SYSCALL_NUM_ARG_STORE 6 /* 6 is max on Linux */
#endif

#define MAX_HEAP_NESTING 4

/* Per-thread data.
 * Fields are assumed to be callback-context-private on Windows.
 * If they should be shared they must be explicitly copied
 * in client_handle_callback().
 */
typedef struct _per_thread_t {
    /* These fields are shared across callbacks on Windows: */
    file_t f;  /* logfile */
    char *errbuf; /* buffer for atomic writes to global logfile */
    size_t errbufsz;
    app_pc stack_lowest_frame; /* optimization for recording callstacks */
    
    /* communicating from pre to post alloc routines */
#ifdef LINUX
    app_pc sbrk;
#else
    ptr_int_t auxarg; /* heap or blocktype or generic additional arg */
#endif
    uint alloc_flags;
    size_t alloc_size;
    size_t realloc_old_size;
    app_pc alloc_base;
    bool syscall_this_process;
    /* we need to split these to handle cases like exception inside RtlFreeHeap */
    bool expect_sys_to_fail;
    bool expect_lib_to_fail;
    uint valloc_type;
    bool valloc_commit;
    app_pc munmap_base;
    /* indicates thread is inside a heap creation routine */
    int in_heap_routine;
    /* at what value of in_heap_routine did we adjust heap routine args?
     * (we only allow one level of recursion to do so)
     */
    int in_heap_adjusted;
    bool in_realloc;
    app_pc tailcall_target;
    app_pc tailcall_post_call;
    /* record which heap routine */
    app_pc last_alloc_routine[MAX_HEAP_NESTING];

    /* for recording args so post-syscall can examine */
    reg_t sysarg[SYSCALL_NUM_ARG_STORE];

    bool in_calloc;
    bool malloc_from_calloc;
#ifdef WINDOWS
    bool in_create; /* are we inside RtlCreateHeap */
    bool malloc_from_realloc;
#endif

#ifdef WINDOWS
    /* callback stack: one per_thread_t per depth level */
    struct _per_thread_t *prev;
    struct _per_thread_t *next;
#endif

    /* For client's own data.  Up to client to create new or share across callbacks. */
    void *client_data;
} per_thread_t;


#endif /* _PER_THREAD_H_ */
