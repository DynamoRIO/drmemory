/* **********************************************************
 * Copyright (c) 2010-2017 Google, Inc.  All rights reserved.
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

/* Additonal per-thread data.
 * Fields are callback-context-private on Windows.
 * This struct is memset to 0 at init time.
 */
typedef struct _cls_drmem_t {
    /* Dr. Heapstat must share the same struct since sharing so much
     * Dr. Memory code.  For Dr. Heapstat this struct is shared
     * across callbacks!
     */
#ifdef TOOL_DR_MEMORY
# ifdef UNIX
    /* PR 406333: linux signal delivery */
    app_pc sigaltstack;
    size_t sigaltsize;
    app_pc prev_sigaltstack; /* used on syscall failure */
    size_t prev_sigaltsize;  /* used on syscall failure */
# else
    app_pc pre_callback_esp;
    /* for heap seh accesses (i#689) */
    RTL_CRITICAL_SECTION *heap_critsec;
# endif
#endif /* TOOL_DR_MEMORY */

    /* Was mostly used for jmp-to-slowpath optimization where we xl8
     * to get app pc (PR 494769) which was now removed, but also used
     * for logging.
     */
    bool self_translating;

    /* for i#471 and i#1453: mem2mem via fp or mm reg heuristic */
    app_pc mem2fpmm_source;
    app_pc mem2fpmm_dest;
    size_t mem2fpmm_prev_shadow;
    app_pc mem2fpmm_pc;
#ifdef DEBUG
    app_pc mem2fpmm_load_pc;
#endif
} cls_drmem_t;

extern int cls_idx_drmem;

/* Per-thread data shared across callbacks */
typedef struct _tls_drmem_t {
#ifdef WINDOWS
    /* since we can't get TEB via syscall for some threads (i#442) */
    TEB *teb;
#else
    void *empty; /* not worth code ugliness to have no TLS at all */
#endif
} tls_drmem_t;

extern int tls_idx_drmem;

#endif /* _CLIENT_PER_THREAD_ */
