/* **********************************************************
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

#ifndef _CLIENT_PER_THREAD_
#define _CLIENT_PER_THREAD_ 1

#include "dr_api.h"
#include "utils.h"

#define SYSCALL_NUM_ARG_STORE  6 /* if raise this need to stop at 6 on Linux */
#define SYSCALL_NUM_ARG_TRACK IF_WINDOWS_ELSE(12, 6)

/* Additonal per-thread data.
 * Fields are assumed to be callback-context-private on Windows.
 * If they should be shared they must be explicitly copied
 * in client_handle_callback() in alloc_drmem.c.
 */
typedef struct _client_per_thread_t {
    /* Dr. Heapstat must share the same struct since sharing so much
     * Dr. Memory code.  For Dr. Heapstat this struct is shared
     * across callbacks!
     */
#ifdef TOOL_DR_MEMORY
# ifdef LINUX
    /* PR 406333: linux signal delivery */
    app_pc signal_xsp;
    app_pc sigframe_top;
    app_pc sigaltstack;
    size_t sigaltsize;
    app_pc prev_sigaltstack; /* used on syscall failure */
    size_t prev_sigaltsize;  /* used on syscall failure */
# else
    app_pc pre_callback_esp;
# endif

    /* for comparing memory across unknown system calls */
    app_pc sysarg_ptr[SYSCALL_NUM_ARG_TRACK];
    size_t sysarg_sz[SYSCALL_NUM_ARG_TRACK];
    /* dynamically allocated */
    size_t sysarg_val_bytes[SYSCALL_NUM_ARG_TRACK];
    uint *sysarg_val[SYSCALL_NUM_ARG_TRACK];
#endif /* TOOL_DR_MEMORY */

    /* pointer for finding shadow regs for other threads */
    void *shadow_regs;

    /* for jmp-to-slowpath optimization where we xl8 to get app pc (PR 494769) */
    bool self_translating;

#ifdef TOOL_DR_HEAPSTAT
# ifdef LINUX
    int64 filepos; /* f_callstack file position */
# endif
#endif /* TOOL_DR_HEAPSTAT */
} client_per_thread_t;

#endif /* _CLIENT_PER_THREAD_ */
