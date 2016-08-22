/* **********************************************************
 * Copyright (c) 2011-2016 Google, Inc.  All rights reserved.
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

#ifndef _DRMEMORY_H_
#define _DRMEMORY_H_ 1

#include "drmgr.h"
#include "client_per_thread.h"
#include "options.h"
#include "utils.h"

/***************************************************************************
 * PARAMETERS
 */

extern client_id_t client_id;

/* instrumentation ordering */
enum {
    /* replace first, then app2app */
#if 0
    DRMGR_PRIORITY_APP2APP_DRWRAP   = -500, /* from drwrap.h */
#endif
    DRMGR_PRIORITY_APP2APP_ANNOTATE = -100,
#if 0
    DRMGR_PRIORITY_INSERT_CLS       =    0, /* from drmgr.h */
#endif
#if 0
    /* we need our alloc wrapping to go before main instru, so that it
     * has access to restored app registers
     */
    DRMGR_PRIORITY_INSERT_DRWRAP    =  500, /* from drwrap.h */
#endif
    /* b/c we're using the 4-at-once interface we have the same priority
     * for string loop app2app, annotation app2app, and main insertion.
     * we want main insertion to g
     */
    DRMGR_PRIORITY_INSTRU           = 1000,
    /* we want to insert clean calls after the main instru to avoid reachability
     * issues w/ main instru that jmps to restore code before app instr
     */
    DRMGR_PRIORITY_INSERT_ANNOTATE  = 2000,
    DRMGR_PRIORITY_INSERT_PERTURB   = 2010,
#if 0
    /* we need our alloc wrapping to go after CLS tracking */
    DRMGR_PRIORITY_INSERT_ALLOC     = 2020, /* from alloc.h */
#endif
};

/***************************************************************************
 * DATA SHARED ACROSS MODULES
 */

extern char logsubdir[MAXIMUM_PATH];

#define RESULTS_FNAME "results.txt"
#define RESULTS_POTENTIAL_FNAME "potential_errors.txt"
#define POTENTIAL_PREFIX        "potential"
#define POTENTIAL_PREFIX_CAP    "Potential"
#define POTENTIAL_PREFIX_ALLCAP "POTENTIAL"

#ifdef USE_DRSYMS
extern file_t f_results;
extern file_t f_suppress;
extern file_t f_missing_symbols;
extern file_t f_potential;
#else
extern file_t f_fork;
#endif

#ifdef WINDOWS
extern app_pc ntdll_base;
extern app_pc ntdll_end;
#endif
extern app_pc app_base;
extern app_pc app_end;
extern char app_path[MAXIMUM_PATH];

#ifdef STATISTICS
void
dump_statistics(void);

extern uint num_nudges;
#endif /* STATISTICS */

volatile bool go_native;

bool
obtain_configfile_path(char *buf OUT, size_t bufsz, const char *fname);

#ifdef UNIX

/* for strchr in linux, which will bring in libc: FIXME */
# include <string.h>

bool
is_in_client_or_DR_lib(app_pc pc);

#endif /* UNIX */

/* We can't get app xsp at init time so we call this on 1st bb */
void
set_initial_layout(void);

byte *
mmap_walk(app_pc start, size_t size,
          IF_WINDOWS_(MEMORY_BASIC_INFORMATION *mbi_start) bool add);

#ifdef WINDOWS
void
set_teb_initial_shadow(TEB *teb);
#endif

#endif /* _DRMEMORY_H_ */
