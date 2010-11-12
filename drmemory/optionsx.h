/* **********************************************************
 * Copyright (c) 2009 VMware, Inc.  All rights reserved.
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

/* Options list that is used for:
 * - usage message from front-end perl script
 * - Doxygen documentation
 * - usage message from client
 * - parsing of options, including default and min-max values, by client
 *
 * We have to split into two different macros in order to populate the
 * client struct: no conditionals there.
 *
 * OPTION_CLIENT and OPTION_FRONT, both take these args:
 * (scope, name, type, default_val, min, max, val_descr, short_descr, long_descr)
 *
 * scope values:
 * - front    = for front-end script for data gathering run
 * - side     = for front-end script to target application in progress
 * - post     = for front-end script for post-run analysis
 * - script   = for front-end script for any use
 * - client   = for client; a documented option
 * - internal = for client; not a documented option (developer use only)
 */

/* XXX: PR 487993: should we support file-private options?
 * Then we wouldn't need op_ globals, and could move midchunk_* options
 * inside leak.c, etc.
 */ 

/* Common min+max values */
#define OPTION_FRONT_BOOL(scope, name, defval, short, long) \
    OPTION_FRONT(scope, name, bool, defval, 0, 0, short, long)
#define OPTION_FRONT_STRING(scope, name, defval, short, long) \
    OPTION_FRONT(scope, name, opstring_t, defval, 0, 0, short, long)
#define OPTION_CLIENT_BOOL(scope, name, defval, short, long) \
    OPTION_CLIENT(scope, name, bool, defval, 0, 0, short, long)
#define OPTION_CLIENT_STRING(scope, name, defval, short, long) \
    OPTION_CLIENT(scope, name, opstring_t, defval, 0, 0, short, long)

#ifndef TOOLNAME
# define TOOLNAME "Dr. Memory"
#endif
#ifndef drmemscope
# define drmemscope client
#endif
/* Extra reference to expand drmemscope */
#define OPTION_CLIENT_SCOPE(scope, name, type, defval, min, max, short, long) \
    OPTION_CLIENT(scope, name, type, defval, min, max, short, long)

/****************************************************************************
 * Front-end-script options.  We present a unified list of options to users.
 */

OPTION_FRONT_BOOL(front, version, false,
                  "Display "TOOLNAME" version",
                  "Display "TOOLNAME" version")
OPTION_FRONT_STRING(front, dr, "",
                    "Path to DynamoRIO installation",
                    "The path to the DynamoRIO installation to use.  Not needed when using a released "TOOLNAME" package.")

#ifdef TOOL_DR_MEMORY
OPTION_FRONT_STRING(front, drmemory, "",
                    "Path to "TOOLNAME" installation",
                    "The path to the base of the "TOOLNAME" installation.  Not needed when invoking "TOOLNAME" from an unmodified installation tree.")
OPTION_FRONT_STRING(front, srcfilter, "",
                    "Only show errors referencing named file",
                    "Do not show errors that do not reference the named source file somewhere in their callstacks.")
#endif /* TOOL_DR_MEMORY */

OPTION_FRONT(side, nudge, uint, 0, 0, UINT_MAX,
             "Process id to nudge",
             "Use this option to 'nudge' an already-running process in order to request leak checking and other "TOOLNAME" actions that normally only occur when the process exits.")

OPTION_FRONT_BOOL(script, v, false,
                  "Display verbose information in the "TOOLNAME" front end",
                  "Display verbose information in the "TOOLNAME" front end")

#ifdef TOOL_DR_MEMORY
OPTION_FRONT_BOOL(front, skip_results, false,
                  "No results during run: use -results afterward",
                  "Do not produce results while running the application.  This can reduce resource usage if the symbol files for the application are large.  To obtain the results, after the application run is finished, use the -results option in a separate step.")
OPTION_FRONT_STRING(post, results, "",
                    "Produce results from specified -skip_results log dir",
                    "Use this option as the second step in a -skip_results run.  Pass the name of the log directory created by the -skip_results application run.  The results.txt will then be filled in.")
OPTION_FRONT_STRING(post, results_app, "",
                    "Use with -results: specify app from -skip_results run",
                    "Use this option when invoking -results on a different machine from where the application was run with -skip_results.  When -results is invoked without this option also specified, the path to the application that was used to run it with -skip_results is assumed.")
OPTION_FRONT_STRING(post, aggregate, "",
                    "Produce aggregate error report on log dirs",
                    "Pass a list of log directories to produce an aggregate error report.  Useful for applications that consist of a group of separate processes.")
# ifdef VMX86_SERVER
OPTION_FRONT_BOOL(front, use_vmtree, true,
                  "Use VMTREE and VMBLD env vars to locate symbols",
                  "See \\ref sec_setup_syms.")
# endif
#endif /* TOOL_DR_MEMORY */

/****************************************************************************
 * Public client options
 */

/* The client default is "c:\\|/tmp" but the front-end script uses install/logs */
OPTION_CLIENT_STRING(client, logdir, "<install>/logs",
                     "Destination for log files",
                     "Destination for log files and result files.")
OPTION_CLIENT(client, verbose, uint, 1, 0, 32,
              "Verbosity level in log files",
              "Verbosity level in log files: 0=none, 1=warnings, 2+=diagnostic.  Primarily for debugging of "TOOLNAME" itself.")
OPTION_CLIENT_BOOL(client, quiet, false,
                   "Suppress stderr messages",
                   "Suppress stderr messages and, on Windows, popup messages.")
OPTION_CLIENT_BOOL(client, ignore_asserts, false,
                   "Do not abort on debug-build asserts",
                   "Display, but do not abort, on asserts in debug build (in release build asserts as automatically disabled).")
OPTION_CLIENT_BOOL(drmemscope, pause_at_unaddressable, false,
                   "Pause at each unaddressable access",
                   ""TOOLNAME" pauses at the point of each unaddressable access error that is identified.  On Windows, this pause is a popup window.  On Linux, the pause involves waiting for a keystroke, which may not work well if the application reads from stdin.  In that case consider -pause_via_loop as an additional option.")
OPTION_CLIENT_BOOL(drmemscope, pause_at_uninitialized, false,
                   "Pause at each uninitialized read",
                   "Identical to -pause_at_unaddressable, but applies to uninitialized access errors.")
OPTION_CLIENT_BOOL(client, pause_at_assert, false,
                   "Pause at each debug-build assert",
                   ""TOOLNAME" pauses at the point of each debug-build assert.  On Windows, this pause is a popup window.  On Linux, the pause involves waiting for a keystroke, which may not work well if the application reads from stdin.  In that case consider -pause_via_loop as an additional option.")
OPTION_CLIENT_BOOL(client, pause_via_loop, false,
                   "Pause via loop (not wait for stdin)",
                   "Used in conjunction with -pause_at_uninitialized and -pause_at_uninitialized on Linux, this option causes "TOOLNAME" to pause via an infinite loop instead of waiting for stdin.  "TOOLNAME" will not continue beyond the first such error found.")

#ifdef TOOL_DR_MEMORY
OPTION_CLIENT(client, callstack_max_frames, uint, 20, 0, 4096,
              "How many call stack frames to record",
              "How many call stack frames to record for each error report.  A larger maximum will ensure that no call stack is truncated, but can use more memory if many stacks are large, especially if -check_leaks is enabled.")
OPTION_CLIENT_BOOL(client, check_leaks, true,
                   /* Requires -count_leaks and -track_heap */
                   "Store leak callstacks",
                   "Whether to store callstacks for each allocation in order to report them when leaks are detected.  If this option is disabled, the count of leaks will be shown, but leaks will not be listed individually in the results file.")
#endif /* TOOL_DR_MEMORY */

#ifdef USE_DRSYMS
OPTION_CLIENT_BOOL(client, symbol_offsets, false,
                   "Show offsets from symbol start in callstacks",
                   "Display offsets for symbols in callstacks: library!symbol+offs.")
#endif

OPTION_CLIENT_BOOL(client, ignore_early_leaks, true,
                   "Ignore pre-app leaks",
                   "Whether to ignore leaks from memory allocated by system code prior to "TOOLNAME" taking over.")
OPTION_CLIENT_BOOL(client, check_leaks_on_destroy, true,
                   "Report leaks on heap destruction",
                   "If enabled, when a heap is destroyed (HeapDestroy on Windows), report any live allocations inside it as possible leaks.")
OPTION_CLIENT_BOOL(client, possible_leaks, true,
                   "Show possible-leak callstacks",
                   "Whether to list possibly-reachable allocations when leak checking.  Requires -check_leaks.")
OPTION_CLIENT_BOOL(client, midchunk_size_ok, true,
                   "Consider mid-chunk post-size pointers legitimate",
                   "Consider allocations reached by a mid-allocation pointer that points past a size field at the head of the allocation to be reachable instead of possibly leaked.  Currently this option looks for a very specific pattern.  If your application's header is slightly different please contact the authors about generalizing this check.")
OPTION_CLIENT_BOOL(client, midchunk_new_ok, true,
                   "Consider mid-chunk post-new[]-header pointers legitimate",
                   "Consider allocations reached by a mid-allocation pointer that points past a size field at the head of the allocation that looks like a new[] header to be reachable instead of possibly leaked.  A heuristic is used for this identification that is not perfect.")
OPTION_CLIENT_BOOL(client, midchunk_inheritance_ok, true,
                   "Consider mid-chunk multi-inheritance pointers legitimate",
                   "Consider allocations reached by a mid-allocation pointer that points to a parent class instantiation to be reachable instead of possibly leaked.  A heuristic is used for this identification that is not perfect.")
OPTION_CLIENT_BOOL(client, midchunk_string_ok, true,
                   "Consider mid-chunk std::string pointers legitimate",
                   "Consider allocations reached by a mid-allocation pointer that points to a char array inside an instance of a std::string representation to be reachable instead of possibly leaked.  A heuristic is used for this identification that is not perfect.")
OPTION_CLIENT_BOOL(client, show_reachable, false,
                   "List reachable allocs",
                   "Whether to list reachable allocations when leak checking.  Requires -check_leaks.")
OPTION_CLIENT_STRING(client, suppress, "",
                     "File containing errors to suppress",
                     "File containing errors to suppress.  See \\ref sec_suppress.")
OPTION_CLIENT_BOOL(client, default_suppress, true,
                   "Use the set of default suppressions",
                   "Use the set of default suppressions that come with "TOOLNAME".  See \\ref sec_suppress.")


/* Exposed for Dr. Memory only */
OPTION_CLIENT_BOOL(drmemscope, check_cmps, true,
                   /* If we check when eflags is written, we can mark the source
                    * undefined reg as defined (since we're reporting there)
                    * and avoid multiple errors on later jcc, etc.
                    */
                   "Check register definedness of cmps",
                   "Report definedness errors on compares instead of waiting for conditional jmps.")
OPTION_CLIENT_BOOL(drmemscope, check_non_moves, false,
                   /* XXX: should also support different checks on a per-module
                    * basis to be more stringent w/ non-3rd-party code?
                    */
                   "Check register definedness of non-moves",
                   "Report definedness errors on any instruction that is not a move.  Note: turning this option on may result in false positives, but can also help diagnose errors through earlier error reporting.")
OPTION_CLIENT_SCOPE(drmemscope, stack_swap_threshold, int, 0x9000, 256, INT_MAX,
                    "Stack change amount to consider a swap",
                    "Stack change amount to consider a swap instead of an allocation or de-allocation on the same stack.  "TOOLNAME" attempts to dynamically tune this value unless it is changed from its default.")
OPTION_CLIENT_SCOPE(drmemscope, redzone_size, uint, 8, 0, 32*1024,
                    "Buffer on either side of each malloc",
                    "Buffer on either side of each malloc.  This should be a multiple of 8.")
OPTION_CLIENT_SCOPE(drmemscope, report_max, int, 20000, -1, INT_MAX,
                    "Maximum non-leak errors to report (-1=no limit)",
                    "Maximum non-leak errors to report (-1=no limit).")
OPTION_CLIENT_SCOPE(drmemscope, report_leak_max, int, 10000, -1, INT_MAX,
                    "Maximum leaks to report (-1=no limit)",
                    "Maximum leaks to report (-1=no limit).")
#ifdef USE_DRSYMS
OPTION_CLIENT_BOOL(drmemscope, batch, false,
                   "Do not invoke notepad at the end",
                   "Do not launch notepad with the results file at application exit.")
OPTION_CLIENT_BOOL(drmemscope, summary, true,
                   "Display a summary of results to stderr",
                   "Display a summary of errors to stderr at app exit.")
#else
OPTION_CLIENT_BOOL(drmemscope, summary, false,
                   "Display a summary prior to symbol processing",
                   "Display a summary of errors prior to symbol-based suppression and other processing.")
#endif
OPTION_CLIENT_BOOL(drmemscope, warn_null_ptr, false,
                   "Warn if NULL passed to free/realloc",
                   "Whether to warn when NULL is passed to free() or realloc().")
OPTION_CLIENT_SCOPE(drmemscope, delay_frees, uint, 2000, 0, UINT_MAX,
                    "Frees to delay before committing",
                    "Frees to delay before committing.  The larger this number, the greater the likelihood that "TOOLNAME" will identify use-after-free errors.  However, the larger this number, the more memory will be used.")
OPTION_CLIENT_BOOL(drmemscope, leaks_only, false,
                   "Check only for leaks and not memory access errors",
                   "Puts "TOOLNAME" into a leak-check-only mode that has lower overhead but does not detect other types of errors other than invalid frees.")
OPTION_CLIENT_STRING(drmemscope, prctl_whitelist, "",
                     "Disable instrumentation unless PR_SET_NAME is on list",
                     "If this list is non-empty, when "TOOLNAME" sees prctl(PR_SET_NAME) and the name is not on the list, then "TOOLNAME" will disable its instrumentation for the rest of the process and for all of its child processes.  The list is ,-separated.")
OPTION_CLIENT_STRING(drmemscope, auxlib, "",
                     "Load auxiliary system call handling library",
                     "This option should specify the basename of an auxiliary system call handling library found in the same directory as the Dr. Memory client library.")

/* not supporting perturb with heapstat: can add easily later */
/* XXX: some of the other options here shouldn't be allowed for heapstat either */
OPTION_CLIENT_BOOL(drmemscope, perturb, false,
                   "Perturb thread scheduling to increase chances of catching races",
                   "Adds random delays to thread synchronization and other operations to try and increase the chances of catching race conditions.")
OPTION_CLIENT_BOOL(drmemscope, perturb_only, false,
                   "Perturb thread scheduling but disable memory checking",
                   "Adds random delays to thread synchronization and other operations to try and increase the chances of catching race conditions, but disables all memory checking to create a low-overhead tool that executes significantly faster.  However, without memory checking race conditions will only be detected if they result in an actual crash or other externally visible change in behavior.  When this option is enabled, "TOOLNAME" will not produce an error summary or results.txt.")
OPTION_CLIENT_SCOPE(drmemscope, perturb_max, uint, 50, 0, UINT_MAX,
                    "Maximum delay added by -perturb",
                    "This option sets the maximum delay added by -perturb, in milliseconds for thread operations and in custom units for instruction-level operations.  Delays added will be randomly selected from 0 up to -perturb_max.")
OPTION_CLIENT_SCOPE(drmemscope, perturb_seed, uint, 0, 0, UINT_MAX,
                    "Seed used for random delays added by -perturb",
                    "To reproduce the random delays added by -perturb, pass the seed from the logfile from the target run to this option.  There may still be non-determinism in the rest of the system, however.")


/****************************************************************************
 * Un-documented client options, for developer use only
 */

OPTION_CLIENT_BOOL(internal, resfile_out, false, 
                   "Write the result file path to <logdir>/resfile.<pid>",
                   "Whether to write the result file path to <logdir>/resfile.<pid>")
OPTION_CLIENT_BOOL(internal, stderr, true,
                   "Print summary messages on stderr",
                   "Print summary messages on stderr")
OPTION_CLIENT_BOOL(internal, shadowing, true,
                   "Enable memory shadowing",
                   "For debugging and -leaks_only and -perturb_only modes: can disable all shadowing and do nothing but track mallocs")
OPTION_CLIENT_BOOL(internal, track_allocs, true,
                   "Enable malloc and alloc syscall tracking",
                   "for debugging and -leaks_only and -perturb_only modes: can disable all malloc and alloc syscall tracking")
OPTION_CLIENT_BOOL(internal, check_invalid_frees, true,
                   "Check for invalid frees",
                   "Check for invalid frees")
OPTION_CLIENT_BOOL(internal, count_leaks, true,
                   "Perform leak scan",
                   "Perform leak scan")
OPTION_CLIENT_BOOL(internal, track_heap, true,
                   "Track malloc and other library allocations",
                   "If false, "TOOLNAME" only tracks memory allocations at the system call level and does not delve into individual malloc units.  This is required to track leaks, even for system-call-only leaks.  Nowadays we use the heap info for other things, like thread stack identification (PR 418629), and don't really support turning this off.  Requires track_allocs.")
OPTION_CLIENT_BOOL(internal, size_in_redzone, true,
                   "Store alloc size in redzone",
                   "Store size in redzone.  This can only be enabled if redzone_size >= sizeof(size_t).")
OPTION_CLIENT_BOOL(internal, fastpath, true,
                   "Enable fastpath",
                   "Enable fastpath")
OPTION_CLIENT_BOOL(internal, esp_fastpath, true,
                   "Enable esp-adjust fastpath",
                   "Enable esp-adjust fastpath")
OPTION_CLIENT_BOOL(internal, shared_slowpath, true,
                   "Enable shared slowpath calling code",
                   "Enable shared slowpath calling code")
OPTION_CLIENT_BOOL(internal, loads_use_table, true,
                   "Use a table lookup to stay on fastpath",
                   "Use a table lookup to check load addressability and stay on fastpath more often")
OPTION_CLIENT_BOOL(internal, stores_use_table, true,
                   "Use a table lookup to stay on fastpath",
                   "Use a table lookup to check store addressability and stay on fastpath more often")
OPTION_CLIENT(internal, num_spill_slots, uint, 5, 0, 16,
              "How many of our own spill slots to use",
              "How many of our own spill slots to use")
OPTION_CLIENT_BOOL(internal, check_ignore_unaddr, true,
                   "Suppress instrumentation (vs dynamic exceptions) for heap code",
                   "Suppress instrumentation (vs dynamic exceptions) for heap code.  PR 578892: this is now done dynamically and is pretty safe")
OPTION_CLIENT_BOOL(internal, thread_logs, false,
                   /* PR 456181/PR 457001: on some filesystems we can't create a file per
                    * thread, so we support sending everything to the global log.
                    * For now, the only multi-write sequence we ensure is atomic is a
                    * reported error.
                    * FIXME: though for most development this option should be turned on,
                    * maybe we should also support:
                    *  - locking all sequences of writes to global log
                    *  - prepending all writes w/ the writing thread id
                    */
                   "Use per-thread logfiles",
                   "Use per-thread logfiles")
OPTION_CLIENT_BOOL(internal, statistics, false,
                   "Calculate stats in the fastpath",
                   "Calculate stats in the fastpath")
OPTION_CLIENT(internal, stats_dump_interval, uint, 500000, 1, UINT_MAX,
              "How often to dump statistics, in units of slowpath executions",
              "How often to dump statistics, in units of slowpath executions")
OPTION_CLIENT_BOOL(internal, define_unknown_regions, true,
                   "Mark unknown regions as defined after 1st UNADDR",
                   "PR 464106: handle memory allocated by other processes by treating as fully defined, after reporting 1st UNADDR")
OPTION_CLIENT_BOOL(internal, replace_libc , true,
                   "Replace libc str/mem routines w/ our own versions",
                   "Replace libc str/mem routines w/ our own versions")
OPTION_CLIENT_STRING(internal, libc_addrs, "",
                     /* XXX: should we expose this option, or should users w/ custom
                      * or inlined versions be expected to use suppression?
                      * This option is only needed on Linux or on Windows when
                      * we don't have symbols.
                      */
                     "Addresses of statically-included libc routines for replacement.",
                     "Addresses of statically-included libc routines for replacement.  Must be a comma-separated list of hex addresses with 0x prefixes,  in this order: memset, memcpy, memchr, strchr, strrchr, strlen, strcmp, strncmp, strcpy, strncpy, strcat, strncat")
OPTION_CLIENT_BOOL(internal, check_push, true,
                   "Check that pushes are writing to unaddressable memory",
                   "Check that pushes are writing to unaddressable memory")
OPTION_CLIENT_BOOL(internal, single_arg_slowpath, false,
                   /* XXX: PR 494769: this feature is not yet finished */
                   "Use single arg for jmp-to-slowpath and derive second",
                   "Use single arg for jmp-to-slowpath and derive second")
OPTION_CLIENT_BOOL(internal, repstr_to_loop, true,
                   "Add fastpath for rep string instrs by converting to normal loop",
                   "Add fastpath for rep string instrs by converting to normal loop")
OPTION_CLIENT_BOOL(internal, replace_realloc, true,
                   "Replace realloc to avoid races and non-delayed frees",
                   "Replace realloc to avoid races and non-delayed frees")
