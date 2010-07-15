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

#ifndef _OPTIONS_H_
#define _OPTIONS_H_ 1

/***************************************************************************
 * RUNTIME OPTIONS
 *
 * With Dr. Heapstat starting to share more and more options with Dr. Memory,
 * it's time for a shared options struct.  Xref PR 487993: should we instead
 * have file-private options?  Also, should use DR-like optionsx.h to
 * automate parsing.
 */

/* If this gets much longer, should use macros to automate the parsing and
 * keep default values next to field names
 */
typedef struct _drmemory_options_t {
    /**************************************************
     * SHARED OPTIONS
     */

    /* location of output log files */
    char logdir[MAXIMUM_PATH];

    /* whether to write the path to the results file to <logdir>/resfile.<pid> */
    bool resfile_out;

    /* verbosity level of logging: 0=none, 1=warnings, 2+=diagnostic */
    uint verbose;

    /* print summary messages on stderr? */
    bool stderr;

    /* Post messagebox (win32) or wait for stdin (linux) at each error */
    bool pause_at_assert;
    /* PR 406725: on Linux, infinite loop rather than waiting for stdin */
    bool pause_via_loop;

    /* This is signed so we don't have to cast on all uses */
    int stack_swap_threshold;

    /* how many frames to output */
    uint callstack_max_frames;

    /* PR 520916: leak-check-only mode */
    bool leaks_only;

    /* for debugging: -no_ to disable all shadowing and do nothing but track mallocs */
    bool shadowing;

    /* Whether to record call stacks for allocations for reporting
     * when leaks are detected.
     * Requires -count_leaks and -track_heap.
     */
    bool check_leaks;

    /* Ignore leaked memory allocated prior to taking over.
     */
    bool ignore_early_leaks;

    /* Whether to print out callstacks for "possible leaks", which are
     * allocations reachable not by head pointers but by
     * mid-allocation pointers (PR 476482).
     */
    bool possible_leaks;

    /* Whether to report as leaks live allocs in heap when heap is destroyed */
    bool check_leaks_on_destroy;

    /* FIXME PR 487993: switch to file-private sets of options and option parsing
     * so we can move these options to inside leak.c?
     */ 
    /* Consider mid-chunk post-size-field pointers legitimate (PR 513954). */
    bool midchunk_size_ok;

    /* Consider new[] post-size-field pointers legitimate (PR 484544). */
    bool midchunk_new_ok;

    /* Consider multi-inheritance mid-chunk pointers legitimate (PR 484544). */
    bool midchunk_inheritance_ok;

    /* Consider std::string mid-chunk pointers legitimate (PR 535344). */
    bool midchunk_string_ok;

    /* Whether to print out reachable "leaks". */
    bool show_reachable;

    /**************************************************
     * TOOL-SPECIFIC OPTIONS
     */
    /* drmem-specific but drheapstat needs to share same code: */

    /* Whether to check for invalid frees. */
    bool check_invalid_frees;

    /* Whether to analyze reachability and count leaks. */
    bool count_leaks;

    /* Whether to report what could be mistakes but are not technically bugs:
     * passing NULL to free() or realloc()
     */
    bool warn_null_ptr;

    /* If false, Dr. Memory only tracks memory allocations at the system call
     * level and does not delve into individual malloc units.
     * This is required to track leaks, even for system-call-only leaks.
     * Nowadays we use the heap info for other things, like thread
     * stack identification (PR 418629), and don't really support
     * turning this off.
     */
    bool track_heap;

    /* Place extra unaddressable space on each side of each allocation, to help
     * catch heap underflow and overflow.  We also use this space to store the
     * allocation size, if SIZE_IN_REDZONE is enabled.
     * FIXME: This should be large, to catch stride accesses: Valgrind uses 128?
     */
    uint redzone_size; /* extra space on each side of each allocation */

    /* Store size in redzone, or use RtlSizeHeap?  The disadvantage of
     * RtlSizeHeap is that we must then treat extra space beyond that requested
     * as addressable since we don't want to use a hashtable to store
     * the requested sizes.
     * This can only be enabled if redzone_size >= sizeof(size_t)
     */
    bool size_in_redzone;

    /* FIXME: should also support different checks on a per-module
     * basis to be more stringent w/ non-3rd-party code?
     */
    bool check_non_moves;

    /* If we check when eflags is written, we can mark the source
     * undefined reg as defined (since we're reporting there)
     * and avoid multiple errors on later jcc, etc.
     */
    bool check_cmps;

    /* Post messagebox (win32) or wait for stdin (linux) at each error */
    bool pause_at_unaddressable;
    bool pause_at_uninitialized;

    /* whether to use fastpath */
    bool fastpath;

    /* whether to use adjust_esp fastpath */
    bool esp_fastpath;

    /* whether to use shared slowpath */
    bool shared_slowpath;

    /* whether to use a table lookup to check addressability, or to
     * check for definedness and perhaps bail to slowpath too often
     */
    bool loads_use_table;
    bool stores_use_table;

    /* how many of our own spill slots to use */
    uint num_spill_slots;

    /* whether to suppress instrumentation (vs dynamic exceptions) for heap code
     * PR 578892: this is now done dynamically and is pretty safe
     */
    bool check_ignore_unaddr;

    /* PR 456181/PR 457001: on some filesystems we can't create a file per
     * thread, so we support sending everything to the global log.
     * For now, the only multi-write sequence we ensure is atomic is a
     * reported error.
     * FIXME: though for most development this option should be turned on,
     * maybe we should also support:
     *  - locking all sequences of writes to global log
     *  - prepending all writes w/ the writing thread id
     */
    bool thread_logs;

    /* print out error summary? (normally we prefer postprocess to do so: PR 477013) */
    bool summary;

    /* whether to calculate stats in the fastpath */
    bool statistics;

    /* how often to dump statistics, in units of slowpath executions */
    uint stats_dump_interval;

    /* throttle thresholds to avoid creating enormous logfiles 
     * -1 means "no limit"     
     */
    int report_max;
    int report_leak_max;

    /* file that contains errors to suppress */
    char suppress_file[MAXIMUM_PATH];

    /* use default suppression file? */
    bool use_default_suppress;

    /* PR 406762: how many frees to queue up before committing */
    uint delay_frees;

    /* PR 464106: handle memory allocated by other processes by treating
     * as fully defined, after reporting 1st UNADDR
     */
    bool define_unknown_regions;

    /* PR 485412: whether to replace libc str/mem routines */
    bool replace_libc;

    /* PR 485412: addresses of statically-included libc routines for replacement.
     * Must be a comma-separated list of hex addresses with 0x prefixes,
     * in this order:
     *   memset, memcpy, memchr, strchr, strrchr, strlen,
     *   strcmp, strncmp, strcpy, strncpy, strcat, strncat
     * FIXME: should we expose this option, or should users w/ custom or inlined
     * versions be expected to use suppression?
     */
    char libc_addrs[MAXIMUM_PATH];

    /* whether to check that pushes are writing to unaddressable memory */
    bool check_push;

    /* use single arg for jmp-to-slowpath and derive second (PR 494769) */
    bool single_arg_slowpath;

    /* disable instrumentation on seeing prctl(PR_SET_NAME) that does not
     * match any of these ,-separated names (PR 574018)
     */
    char prctl_whitelist[MAXIMUM_PATH];

    /* PR 580123: add fastpath for rep string instrs by converting to normal loop */
    bool repstr_to_loop;

#ifdef TOOL_DR_HEAPSTAT

    /* Unit of time.  Simpler to use bools than a single-option string. */
    bool time_instrs;
    bool time_allocs;
    bool time_bytes;
    bool time_clock;

    /* Whether to dump to a file instead of keeping constant # of in-memory
     * snapshots.
     */
    bool dump;
    /* How often to take snapshots, if -dump. */
    uint dump_freq;
    /* Number of in-memory snapshots, if -no_dump. */
    uint snapshots;
    /* Peak snapshot accuracy */
    uint peak_threshold;

    /* Whether to track staleness of heap allocations */
    bool staleness;
    /* Granularity of staleness, in milliseconds */
    bool stale_granularity;
    /* Undocumented performance-tweaking option */
    bool stale_blind_store;
    /* Ignore stack pointer-based references for performance */
    bool stale_ignore_sp;
#endif /* TOOL_DR_HEAPSTAT */

} drmemory_options_t;

extern drmemory_options_t options;

extern bool stack_swap_threshold_fixed;

void
options_init(const char *opstr);

void
usage_error(const char *msg, const char *submsg);

#ifdef TOOL_DR_MEMORY
# define SHADOW_STACK_POINTER() (!options.leaks_only)
#else
/* we zero for leaks, and staleness does not care about xsp */
# define SHADOW_STACK_POINTER() (false)
#endif

#endif /* _OPTIONS_H_ */
