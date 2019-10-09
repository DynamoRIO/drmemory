/* **********************************************************
 * Copyright (c) 2010-2019 Google, Inc.  All rights reserved.
 * Copyright (c) 2009-2010 VMware, Inc.  All rights reserved.
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
#define OPTION_CLIENT_STRING_REPEATABLE(scope, name, defval, short, long) \
    OPTION_CLIENT(scope, name, multi_opstring_t, defval, 0, 0, short, long)

#ifndef TOOLNAME
# define TOOLNAME "Dr. Memory"
#endif
#ifndef drmemscope
# define drmemscope client
#endif
/* Extra reference to expand drmemscope */
#define OPTION_CLIENT_SCOPE(scope, name, type, defval, min, max, short, long) \
    OPTION_CLIENT(scope, name, type, defval, min, max, short, long)

#ifndef IF_WINDOWS_ELSE
# ifdef WINDOWS
#  define IF_WINDOWS_ELSE(x,y) x
# else
#  define IF_WINDOWS_ELSE(x,y) y
# endif
#endif

/****************************************************************************
 * Front-end-script options.  We present a unified list of options to users.
 */

OPTION_FRONT_BOOL(front, version, false,
                  "Display "TOOLNAME" version",
                  "Display "TOOLNAME" version")
OPTION_FRONT_BOOL(front, help, false,
                  "Display option list",
                  "Display the full option list")
OPTION_FRONT_STRING(front, dr, "",
                    "Path to DynamoRIO installation",
                    "The path to the DynamoRIO installation to use.  Not needed when using a released "TOOLNAME" package.")

#ifdef TOOL_DR_MEMORY
OPTION_FRONT_STRING(front, drmemory, "",
                    "Path to "TOOLNAME" installation",
                    "The path to the base of the "TOOLNAME" installation.  Not needed when invoking "TOOLNAME" from an unmodified installation tree.")
# ifdef WINDOWS
OPTION_FRONT_BOOL(front, top_stats, false,
                  "Show time taken and memory usage of whole process",
                  "Primarily for use by developers of the tool.  Shows time taken and memory usage of the whole process at the end of the run")
OPTION_FRONT_BOOL(front, fetch_symbols, false,
                  "Fetch missing symbol files at the end of the run",
                  "Fetch missing symbol files at the end of the run.  While fetching of arbitrary symbols is off by default, auto-fetching of C library symbols is enabled unless -no_fetch_symbols is explicitly requested.")
# endif
#endif /* TOOL_DR_MEMORY */
OPTION_FRONT_BOOL(front, follow_children, true,
                  "Monitor child processes",
                  "Monitor child processes by following across execve on Linux or CreateProcess on Windows.  On Linux, monitoring always continues across a fork.")

#ifndef MACOS /* XXX i#1286: implement nudge on MacOS */
OPTION_FRONT(side, nudge, uint, 0, 0, UINT_MAX,
             "Process id to nudge",
             "Use this option to 'nudge' an already-running process in order to request leak checking and other "TOOLNAME" actions that normally only occur when the process exits.  Not currently available on MacOS.")
#endif

OPTION_FRONT_BOOL(script, v, false,
                  "Display verbose information in the "TOOLNAME" front end",
                  "Display verbose information in the "TOOLNAME" front end")

/* FIXME i#614, i#446: add support for aggregate and post-process w/ USE_DRSYMS */
#if defined(UNIX) && defined(TOOL_DR_MEMORY) && !defined(USE_DRSYMS)
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
#endif /* UNIX + TOOL_DR_MEMORY + !USE_DRSYMS */

/****************************************************************************
 * Public client options
 */

OPTION_CLIENT_BOOL(drmemscope, light, false,
                   "Enables a lightweight mode that detects only critical errors",
                   "This option enables a lightweight mode that detects unaddressable accesses, free/delete/delete[] mismatches, and GDI API usage errors in Windows, but not uninitialized reads or memory leaks.")
OPTION_CLIENT_BOOL(client, brief, false,
                   "Show simplified and easier-to-read error reports",
                   "Show simplified and easier-to-read error reports that hide STL and CRT source paths, remove executable path prefixes from source files, omit absolute addresses, omit instruction disassembly, and omit thread timestamps.  Also enables -delay_frees_stack and disables -callstack_use_top_fp, trading off performance for better error reports.")
/* The client default is "c:\\|/tmp" but the front-end script uses install/logs */
#ifdef WINDOWS
OPTION_CLIENT_BOOL(client, visual_studio, false,
                   "Produce Visual Studio external tool output",
                   "Produce output suitable for a Visual Studio external tool.  Enables -prefix_style 2, -callstack_style 0x820, -batch, and -brief.  Windows-only.")
#endif
/* The client default is "c:\\|/tmp" but the front-end script uses install/logs */
OPTION_CLIENT_STRING(client, logdir, "<install>/logs",
                     "Base directory for result file subdirectories and symbol cache",
                     "Destination base directory for result files and the symbol cache (unless -symcache_dir is specified).  A subdirectory inside this base directory is created for each process that is run, along with a single shared symbol cache directory.  If you specify a separate base directory for every run, you will lose the benefits of symbol caching, unless you also specify a separate shared cache directory with the -symcache_dir option.")
OPTION_CLIENT(client, verbose, uint, 1, 0, 32,
              "Verbosity level in log files",
              "Verbosity level in log files: 0=none, 1=warnings, 2+=diagnostic.  Primarily for debugging of "TOOLNAME" itself.")
OPTION_CLIENT_BOOL(client, quiet, false,
                   "Suppress stderr messages and results",
                   "Suppress stderr messages and, on Windows, popup messages.  Overrides -results_to_stderr and -summary.")
#ifdef USE_DRSYMS
OPTION_CLIENT_BOOL(client, results_to_stderr, true,
                   "Print error reports to stderr in addition to results.txt",
                   "Print error reports to stderr in addition to results.txt, interleaving them with the application output.  The output will be prefixed by ~~Dr.M~~ for the main thread and by the thread id for other threads.  This interleaving can make it easier to see which part of an application run raised an error.")
OPTION_CLIENT(client, prefix_style, uint, 0, 0, 2,
              "Adjust the default output per-line prefix",
              "For -results_to_stderr, controls the per-line prefix:@@<ul>"
              "<li>0 = Default prefix: ~~Dr.M~~ for the main thread and the"
              " thread id for other threads.@@"
              "<li>1 = No prefix.@@"
              "<li>2 = Use blank spaces.  This makes the output compatible "
              " with Visual Studio file and line number parsing.@@"
              "</ul>@@")
OPTION_CLIENT_BOOL(client, log_suppressed_errors, false,
                   "Log suppressed error reports for postprocessing.",
                   "Log suppressed error reports for postprocessing.  Enabling this option will increase the logfile size, but will allow users to re-process suppressed reports with alternate suppressions or additional symbols.")
#endif
OPTION_CLIENT_BOOL(client, ignore_asserts, false,
                   "Do not abort on debug-build asserts",
                   "Display, but do not abort, on asserts in debug build (in release build asserts are automatically disabled).")
OPTION_CLIENT(client, exit_code_if_errors, int, 0, INT_MIN, INT_MAX,
              "If non-zero, the app's exit code is changed to this if errors are found",
              "If non-zero, the app's exit code is changed to this code if any errors are found.")
OPTION_CLIENT_BOOL(drmemscope, pause_at_error, false,
                   "Pause at each reported error of any type",
                   ""TOOLNAME" pauses at the point of each error that is identified.  On Windows, this pause is a popup window.  On Linux, the pause involves waiting for a keystroke, which may not work well if the application reads from stdin.  In that case consider -pause_via_loop as an additional option.")
OPTION_CLIENT_BOOL(drmemscope, pause_at_unaddressable, false,
                   "Pause at each unaddressable access",
                   ""TOOLNAME" pauses at the point of each unaddressable access error that is identified.  On Windows, this pause is a popup window.  On Linux, the pause involves waiting for a keystroke, which may not work well if the application reads from stdin.  In that case consider -pause_via_loop as an additional option.")
OPTION_CLIENT_BOOL(drmemscope, pause_at_uninitialized, false,
                   "Pause at each uninitialized read",
                   "Identical to -pause_at_unaddressable, but applies to uninitialized access errors.")
OPTION_CLIENT_BOOL(drmemscope, pause_at_exit, false,
                   "Pause at exit",
                   "Pauses at exit, using the same mechanism described in -pause_at_unaddressable.  Meant for examining leaks in the debugger.")
OPTION_CLIENT_BOOL(client, pause_at_assert, false,
                   "Pause at each debug-build assert",
                   ""TOOLNAME" pauses at the point of each debug-build assert.  On Windows, this pause is a popup window.  On Linux, the pause involves waiting for a keystroke, which may not work well if the application reads from stdin.  In that case consider -pause_via_loop as an additional option.")
OPTION_CLIENT_BOOL(client, pause_via_loop, false,
                   "Pause via loop (not wait for stdin)",
                   "Used in conjunction with -pause_at_uninitialized and -pause_at_uninitialized on Linux, this option causes "TOOLNAME" to pause via an infinite loop instead of waiting for stdin.  "TOOLNAME" will not continue beyond the first such error found.")
OPTION_CLIENT_BOOL(drmemscope, crash_at_unaddressable, false,
                   "Crash at the first reported unaddressable access",
                   ""TOOLNAME" terminates the process in a crash at the point of the first unaddressable access error that is identified.")
OPTION_CLIENT_BOOL(drmemscope, crash_at_error, false,
                   "Crash at the first reported error of any type",
                   ""TOOLNAME" terminates the process in a crash at the point of the first error that is identified.")
#ifdef WINDOWS
/* XXX: also add -crash_at_error_mask and -pause_at_error_mask options */
OPTION_CLIENT(client, dump_at_error_mask, uint, 0, 0, 0x2f,
              "Creates a memory dump file at the specified errors",
              "At each reported unique error selected by the mask value, a memory dump file is created.  This option is a work-in-progress and is currently experimental, using the DynamoRIO livedump format which is not yet publicly documented.  The mask takes the following bitfields: @@<ul>"
              "<li>0x0001 = unaddressable access@@"
              "<li>0x0002 = uninitialized read@@"
              "<li>0x0004 = invalid heap argument@@"
              "<li>0x0008 = GDI usage error@@"
              "<li>0x0020 = warning@@"
              "</ul>@@")
OPTION_CLIENT_BOOL(drmemscope, dump_at_unaddressable, false,
                   "Creates a memory dump file at unaddressable errors",
                   "Equivalent to -dump_at_error_mask 1.")
#endif

#ifdef TOOL_DR_MEMORY
OPTION_CLIENT(client, callstack_max_frames, uint, 20, 0, 4096,
              "How many call stack frames to record",
              "How many call stack frames to record for each non-leak error report.  A larger maximum will ensure that no call stack is truncated, but can use more memory and slow down the tool if there are many error reports with large callstacks.  This option must be larger than the largest suppression supplied to -suppress.  The separate option -malloc_max_frames controls the callstack size for leak reports, while -free_max_frames controls the callstack size for freed memory overlap reports from -delay_frees_stack.")
OPTION_CLIENT(client, malloc_max_frames, uint, 12, 0, 4096,
              "How many call stack frames to record on each malloc",
              "How many call stack frames to record on each malloc, for use in leak error reports as well as alloc/free mismatch error reports (unless leaks are disabled (via -no_count_leaks or -light) and -malloc_callstacks is also disabled).  A larger maximum will ensure that no call stack is truncated, but can use more memory and slow down the tool.")
OPTION_CLIENT(client, free_max_frames, uint, 6, 0, 4096,
              "How many call stack frames to record on each free",
              "If -delay_frees_stack is enabled, this controls how many call stack frames to record for each use-after-free informational report.  A larger maximum will ensure that no call stack is truncated, but can use more memory and slow down the tool.")
#endif

OPTION_CLIENT(client, callstack_style, uint, 0x0301, 0, 0x1fff,
              "Set of flags that controls the callstack printing style",
              "Set of flags that controls the callstack printing style: @@<ul>"
              "<li>0x0001 = show frame numbers@@"
              "<li>0x0002 = show absolute address@@"
              "<li>0x0004 = show offset from library base@@"
              "<li>0x0008 = show offset from symbol start:"
              " @&library!symbol+offs@&@@"
              "<li>0x0010 = show offset from line start: @&foo.c:44+0x8@&@@"
              "<li>0x0020 = @&file:line@& on separate line@@"
              "<li>0x0040 = @&file @ line@& instead of @&file:line@&@@"
              "<li>0x0080 = @&symbol library@& instead of @&library!symbol@&@@"
              "<li>0x0100 = put fields in aligned columns@@"
              "<li>0x0200 = show symbol and module offset when symbols are"
              " missing@@"
              "<li>0x0400 = print unique module id@@"
              "<li>0x0800 = show @&file(line):@& instead of @&file:line@&d@@"
              "<li>0x1000 = expand template parameters (from @&<>@&) for PDB symbols@@"
              "</ul>@@")
              /* (when adding, update the max value as well!) */

#ifdef TOOL_DR_MEMORY
# ifdef USE_DRSYMS /* NYI for postprocess */
/* _REPEATABLE would take too much capacity and too much option string space to
 * specify more than one or two.
 */
OPTION_CLIENT_STRING(client, callstack_truncate_below, "main,wmain,WinMain,wWinMain,*RtlUserThreadStart,_threadstartex,BaseThreadInitThunk",
                     ",-separated list of function names at which to truncate callstacks",
                     "Callstacks will be truncated at any frame that matches any of these ,-separated function names.  The function names can contain * or ? wildcards.")
OPTION_CLIENT_STRING(client, callstack_modname_hide, "*drmemory*",
                     ",-separated list of module names to hide in callstack frames",
                     "Callstack frames will not list module names matching any of these ,-separated patterns.  The names can contain * or ? wildcards.  The module name will be displayed whenever the function name is uknown, however.  The module name will only be hidden for error display purposes: it will still be included when considering suppressions, and it will be included in the generated suppression callstacks.")
OPTION_CLIENT_BOOL(client, callstack_exe_hide, true,
                   "Whether to omit the executable name from callstack frames",
                   "Callstack frames will not list the executable name.  The executable name will be displayed whenever the function name is uknown, however.  The executable name will only be hidden for error display purposes: it will still be included when considering suppressions, and it will be included in the generated suppression callstacks.")
OPTION_CLIENT_STRING(client, callstack_srcfile_hide, "",
                     ",-separated list of source file paths to hide in callstack frames",
                     "Callstack frames will not list source file paths matching any of these ,-separated patterns.  The paths can contain * or ? wildcards.")
OPTION_CLIENT_STRING(client, callstack_srcfile_prefix, "",
                     ",-separated list of path prefixes to remove",
                     "Callstack frame source paths that match any of these ,-separated prefixes will be printed without the leading portion up to and including the match.")
OPTION_CLIENT_STRING(client, lib_blacklist, "",
                     ",-separated list of path patterns to treat as non-app libs",
                     "Error reports whose top N frames' module paths match any of these ,-separated patterns will be separated by default as merely potential errors, where N is -lib_blacklist_frames.  These errors are reported to potential_errors.txt rather than results.txt.  This feature is disabled if -lib_blacklist_frames is 0.  The -lib_whitelist takes priority over this blacklist: i.e., if any top frame matches the whitelist, the error will be reported normally, even if all frames also match the blacklist. Each pattern can use * and ? wildcards (which have the same semantics as in suppression files) and is matched against the full path of each module.  The default on Windows is set to $SYSTEMROOT*.d?? if not otherwise specified.")
OPTION_CLIENT(client, lib_blacklist_frames, uint, 4, 0, 4096,
              "The number of frames to match vs -lib_blacklist",
              "The number of frames, starting from the top, that must match -lib_blacklist in a callstack in order for an error report to be separated from the regularly reported errors.  Setting this value to 0 disables blacklist-based error separation.  If the top frame is a system call or a replace_* Dr. Memory routine, it is ignored and matching starts from the second frame.")
OPTION_CLIENT_STRING(client, lib_whitelist, "",
                     ",-separated list of path patterns for which to report errors",
                     "Error reports where not a single one of the top N frames' module paths match any of these ,-separated patterns will be separated by default as merely potential errors, where N is -lib_whitelist_frames.  These errors are reported to potential_errors.txt rather than results.txt.  This feature is disabled if -lib_whitelist_frames is 0 or if -lib_whitelist is empty.  This whitelist takes priority over -lib_blacklist: i.e., if any top frame matches the whitelist, the error will be reported normally, even if all frames also match the blacklist.  Each pattern can use * and ? wildcards (which have the same semantics as in suppression files) and is matched against the full path of each module.")
OPTION_CLIENT(client, lib_whitelist_frames, uint, 4, 0, 4096,
                     "The number of frames to match vs -lib_whitelist",
                     "The number of frames, starting from the top, that must not match -lib_whitelist in a callstack in order for an error report to be separated from the regularly reported errors.  Setting this value to 0 disables -lib_whitelist-based error separation.  If the top frame is a system call or a replace_* Dr. Memory routine, it is ignored and matching starts from the second frame.")
OPTION_CLIENT_STRING(client, src_whitelist, "",
                     ",-separated list of source patterns for which to report errors",
                     "Error reports where not a single one of the top N frames' source file paths match any of these ,-separated patterns will be separated by default as merely potential errors, where N is -src_whitelist_frames.  These errors are reported to potential_errors.txt rather than results.txt.  This feature is disabled if -src_whitelist_frames is 0 or if -src_whitelist is empty.  This whitelist takes priority over -lib_blacklist: i.e., if any top frame matches the whitelist, the error will be reported normally, even if all frames also match the blacklist.  If combined with -lib_whitelist, the -lib_whitelist will perform its check first, followed by -src_whitelist.  Each pattern can use * and ? wildcards (which have the same semantics as in suppression files) and is matched against the full path of each source file.")
OPTION_CLIENT(client, src_whitelist_frames, uint, 4, 0, 4096,
                     "The number of frames to match vs -src_whitelist",
                     "The number of frames, starting from the top, that must not match -src_whitelist in a callstack in order for an error report to be separated from the regularly reported errors.  Setting this value to 0 disables -src_whitelist-based error separation.  If the top frame is a system call or a replace_* Dr. Memory routine, it is ignored and matching starts from the second frame.")
# endif
OPTION_CLIENT_STRING(drmemscope, check_uninit_blacklist, "",
                     ",-separated list of module basenames in which to not check uninits",
                   "For each library or executable basename on this list, Dr. Memory suspends checking of uninitialized reads.  Instead Dr. Memory marks all memory written by such modules as defined.  This is a more efficient way to ignore all errors from a module than suppressing them or adding to the lib_blacklist option.  Dr. Memory does automatically turn a whole-module suppression consisting of a single frame of the form 'modulename!*' into an entry on this list.  The entries on this list can contain wildcards.")
#endif

OPTION_CLIENT_BOOL(client, callstack_use_top_fp, true,
              "Use the top-level ebp/rbp register as the first frame pointer",
              "Whether to trust the top-level ebp/rbp register to hold the next frame pointer.  If enabled, overridden when -callstack_use_top_fp_selectively is enabled.  Normally trusting the register is correct.  However, if a frameless function is on top of the stack, using the ebp register can cause a callstack to skip the next function.  If this option is set to false, the callstack walk will perform a stack scan at the top of every callstack.  This adds additional overhead in exchange for more accuracy, although in -light mode the additional accuracy has some tradeoffs and can result in incorrect frames.  It should not be necessary to disable this option normally, unless an application or one of its static libraries is built with optimizations that omit frame pointers.")
OPTION_CLIENT_BOOL(client, callstack_use_top_fp_selectively, true,
              "Use the top-level ebp/rbp register as the first frame pointer in certain situations",
              "Whether to trust the top-level ebp/rbp register to hold the next frame pointer in certain situations.  When enabled, this overrides -callstack_use_top_fp if it is enabled; but if -callstack_use_top_fp is disabled then the top fp is never used.  When this option is enabled, in full or -leaks_only modes then the top fp is not used for all non-leak errors, while in -light mode the top fp is only not used for non-leak errors where the top frame is in an application module.  See the -callstack_use_top_fp option for further information about the top frame pointer.")
OPTION_CLIENT_BOOL(client, callstack_use_fp, true,
              "Use frame pointers to walk the callstack",
              "Whether to use frame pointers at all.  The -callstack_use_top_fp and -callstack_use_top_fp_selectively options control whether to use the top frame pointer.  This option controls whether to continue walking the frame pointer chain.  Turning this off may be necessary if a mixture of frame pointer optimized code and un-optimized code is in use in the application, to avoid skipping interior callstack frames.")
OPTION_CLIENT_BOOL(client, callstack_conservative, false,
              "Perform extra checks for more accurate callstacks",
              "By default, callstack walking is tuned for performance.  It is possible to miss some frames when application code is optimized.  Enabling this option causes extra checks to be performed to attempt to create more accurate callstacks.  These checks add extra overhead.")
/* by default scan forward a fraction of a page: good compromise bet perf (scanning
 * can be the bottleneck) and good callstacks
 */
OPTION_CLIENT(client, callstack_max_scan, uint, 2048, 0, 16384,
              "How far to scan to locate the first or next stack frame",
              "How far to scan to locate the first stack frame when starting in a frameless function, or to locate the next stack frame when crossing loader or glue stub thunks or a signal or exception frame.  Increasing this can produce better callstacks but may incur noticeable overhead for applications that make many allocation calls.")
OPTION_CLIENT_STRING(client, callstack_bad_fp_list, IF_WINDOWS_ELSE("", "libstdc++*"),
              ",-separated list of path patterns where frame pointers are untrustworthy",
              "When walking frame pointers and transitioning from any module on this list to a frame not in the same module, the frame pointer chain is assumed to be suspect and a stack scan is performed.  Use this option to avoid missing frames in your application's code that are skipped due to frame pointer optimizations in other libraries.")

#ifdef TOOL_DR_MEMORY
OPTION_CLIENT_BOOL(client, check_leaks, true,
                   /* Requires -count_leaks and -track_heap */
                   "List details on memory leaks detected",
                   "Whether to list details of each individual memory leak.  If this option is disabled and -count_leaks is enabled, leaks will still be detected, but only the count of leaks will be shown.")
OPTION_CLIENT_BOOL(client, count_leaks, true,
                   "Look for memory leaks",
                   "Whether to detect memory leaks.  Whether details on each leak are shown is controlled by the -check_leaks option.  Disabling this option can reduce execution overhead as less information must be kept internally, while disabling -check_leaks will not affect execution overhead.")
#endif /* TOOL_DR_MEMORY */

#ifdef USE_DRSYMS
OPTION_CLIENT_BOOL(client, symbol_offsets, false,
                   "Deprecated: use -callstack_style flag 0x4",
                   "Deprecated: use -callstack_style flag 0x4")
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
#ifdef WINDOWS
OPTION_CLIENT_BOOL(client, check_encoded_pointers, true,
                   "Check for encoded pointers",
                   "Check for encoded pointers to eliminate false positives from pointers kept in encoded form.")
#endif
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
OPTION_CLIENT_BOOL(client, scan_read_only_files, false,
                   "Whether the leak scan should scan read-only file-mapped memory",
                   "Whether the leak scan should scan read-only file-mapped memory when looking for pointers to the heap.  The leak scan does not track whether pages have been read-only since they were mapped, so it's possible for the application to store heap pointers in a file-mapped region and then mark it read-only.  If your application does so, you may want to turn on this option.")
OPTION_CLIENT_BOOL(client, strings_vs_pointers, true,
                   "Use heuristics to rule out sub-strings as leak scan pointers",
                   "Use heuristics to rule out sub-strings as leak scan pointers, preventing strings from anchoring heap objects and resulting in false negatives.")
OPTION_CLIENT_BOOL(client, show_reachable, false,
                   "List reachable allocs",
                   "Whether to list reachable allocations when leak checking.  Requires -check_leaks.")
OPTION_CLIENT_STRING_REPEATABLE(client, suppress, "",
                     "File containing errors to suppress",
                     "File containing errors to suppress.  May be repeated.  See \\ref page_suppress.")
OPTION_CLIENT_BOOL(client, default_suppress, true,
                   "Use the set of default suppressions",
                   "Use the set of default suppressions that come with "TOOLNAME".  See \\ref page_suppress.")
OPTION_CLIENT_BOOL(client, gen_suppress_offs, true,
                   "Generate mod+offs suppressions in the output suppress file",
                   "Generate mod+offs suppressions in addition to mod!sym suppressions in the output suppress file")
OPTION_CLIENT_BOOL(client, gen_suppress_syms, true,
                   "Generate mod!syms suppressions in the output suppress file",
                   "Generate mod!syms suppressions in addition to mod+offs suppressions in the output suppress file")
OPTION_CLIENT_BOOL(client, show_threads, true,
                   "Print the callstack of each thread creation point referenced in an error",
                   "Whether to print the callstack of each thread creation point referenced in an error report to the global logfile, which can be useful to identify which thread was involved in the error report.  Look for 'NEW THREAD' in the global.pid.log file in the log directory where the results.txt file is found.")
OPTION_CLIENT_BOOL(client, show_all_threads, false,
                   "Print the callstack of each thread creation point",
                   "Whether to print the callstack of each thread creation point (whether referenced in an error report or not) to the global logfile.  This can be useful to identify which thread was involved in error reports, as well as general diagnostics for what threads were present during a run.  Look for 'NEW THREAD' in the global.pid.log file in the log directory where the results.txt file is found.")
OPTION_CLIENT_BOOL(client, conservative, false,
                   "Be conservative reading app memory and assuming dead regs",
                   "Be conservative whenever reading application memory and when assuming registeres are dead.  When this option is disabled, "TOOLNAME" may read return addresses and arguments passed to functions without fault-handling code, which gains performance but can sacrifice robustness when running hand-crafted assembly code.  Additionally, with this option disabled, register liveness does not consider faults.")

/* Exposed for Dr. Memory only */
OPTION_CLIENT_BOOL(drmemscope, check_uninit_cmps, true,
                   /* If we check when eflags is written, we can mark the source
                    * undefined reg as defined (since we're reporting there)
                    * and avoid multiple errors on later jcc, etc.
                    */
                   "Check definedness of comparison instructions",
                   "Report definedness errors on compares instead of waiting for conditional jmps.")
OPTION_CLIENT_BOOL(drmemscope, check_uninit_non_moves, false,
                   /* XXX: should also support different checks on a per-module
                    * basis to be more stringent w/ non-3rd-party code?
                    */
                   "Check definedness of all non-move instructions",
                   "Report definedness errors on any instruction that is not a move.  Note: turning this option on may result in false positives, but can also help diagnose errors through earlier error reporting.")
OPTION_CLIENT_BOOL(drmemscope, check_uninit_all, false,
                   "Check definedness of all instructions",
                   "Report definedness errors on any instruction, rather than the default of waiting until something meaningful is done, which reduces false positives.  Note: turning this option on may result in false positives, but can also help diagnose errors through earlier error reporting.")
OPTION_CLIENT_BOOL(drmemscope, strict_bitops, false,
                   "Fully check definedness of bit operations",
                   "Currently, Dr. Memory's definedness granularity is per-byte.  This can lead to false positives on code that uses bitfields.  By default, Dr. Memory relaxes its uninitialized checking on certain bit operations that are typically only used with bitfields, to avoid these false positives.  However, this can lead to false negatives.  Turning this option on will eliminate all false negatives (at the cost of potential false positives).  Eventually Dr. Memory will have bit-level granularity and this option will go away.")
OPTION_CLIENT_BOOL(drmemscope, check_pc, true,
                   "Check the program counter for unaddressable execution",
                   "Check the program counter on each instruction to ensure it is executing from valid memory.")
OPTION_CLIENT_SCOPE(drmemscope, stack_swap_threshold, int, 0x9000, 256, INT_MAX,
                    "Stack change amount to consider a swap",
                    "Stack change amount to consider a swap instead of an allocation or de-allocation on the same stack.  "TOOLNAME" attempts to dynamically tune this value unless it is changed from its default.")
OPTION_CLIENT_SCOPE(drmemscope, redzone_size, uint, 16, 0, 32*1024,
                    "Buffer on either side of each malloc",
                    "Buffer on either side of each malloc.  This should be a multiple of 8 for 32-bit and 16 for 64-bit.")
OPTION_CLIENT_SCOPE(drmemscope, report_max, int, 20000, -1, INT_MAX,
                    "Maximum non-leak errors to report (-1=no limit)",
                    "Maximum non-leak errors to report (-1=no limit).  This includes 'potential' errors listed separately.")
OPTION_CLIENT_SCOPE(drmemscope, report_leak_max, int, 10000, -1, INT_MAX,
                    "Maximum leaks to report (-1=no limit)",
                    "Maximum leaks to report (-1=no limit).  This includes 'potential' leaks listed separately.")
OPTION_CLIENT_BOOL(drmemscope, report_write_to_read_only, true,
                   "Report writes to read-only memory as unaddressable errors",
                   "Report writes to read-only memory as unaddressable errors.")

OPTION_CLIENT_BOOL(drmemscope, show_duplicates, false,
                   "Print details on each duplicate error",
                   "Print details on each duplicate error rather than only showing unique error details")
#ifdef USE_DRSYMS
OPTION_CLIENT_BOOL(drmemscope, batch, false,
                   "Do not invoke notepad at the end",
                   "Do not launch notepad with the results file at application exit.")
OPTION_CLIENT_BOOL(drmemscope, summary, true,
                   "Display a summary of results to stderr",
                   "Display process startup information and a summary of errors to stderr at app exit.")
OPTION_CLIENT_BOOL(drmemscope, use_symcache, true,
                   "Cache results of symbol lookups to speed up future runs",
                   "Cache results of symbol lookups to speed up future runs")
OPTION_CLIENT_STRING(drmemscope, symcache_dir, "<install>/logs/symcache",
                     "Directory for symbol cache files",
                     "Destination for symbol cache files.  When using a unique log directory for each run, symbols will not be shared across runs because the default cache location is inside the log directory.  Use this option to set a shared directory.")
OPTION_CLIENT(client, symcache_minsize, uint, 1000, 0, UINT_MAX,
                   "Minimum module size to cache symbols for",
                   "Minimum module size to cache symbols for.  Note that there's little downside to caching and it is pretty much always better to cache.")
OPTION_CLIENT_BOOL(drmemscope, use_symcache_postcall, true,
                   "Cache post-call sites to speed up future runs",
                   "Cache post-call sites to speed up future runs.  Requires -use_symcache to be true.")
# ifdef WINDOWS
OPTION_CLIENT_BOOL(drmemscope, preload_symbols, false,
                   "Preload debug symbols on module load",
                   "Preload debug symbols on module load.  Debug symbols cannot be loaded during leak reporting on Vista, so this option is on by default on Vista.  This option may cause excess memory usage from unneeded debugging symbols.")
OPTION_CLIENT_BOOL(drmemscope, skip_msvc_importers, true,
                   "Do not search for alloc routines in modules that import from msvc*",
                   "Do not search for alloc routines in modules that import from msvc*")
# endif /* WINDOWS */
#else
OPTION_CLIENT_BOOL(drmemscope, summary, false,
                   "Display a summary prior to symbol processing",
                   "Display process startup information and a summary of errors prior to symbol-based suppression and other processing.")
#endif
OPTION_CLIENT_BOOL(drmemscope, warn_null_ptr, false,
                   "Warn if NULL passed to free/realloc",
                   "Whether to warn when NULL is passed to free() or realloc().")
OPTION_CLIENT_SCOPE(drmemscope, delay_frees, uint, 2000, 0, UINT_MAX,
                    "Frees to delay before committing",
                    "Frees to delay before committing.  The larger this number, the greater the likelihood that "TOOLNAME" will identify use-after-free errors.  However, the larger this number, the more memory will be used.  This value is separate for each set of allocation routines and each Windows Heap.")
OPTION_CLIENT_SCOPE(drmemscope, delay_frees_maxsz, uint, 20000000, 0, UINT_MAX,
                    "Maximum size of frees to delay before committing",
                    "Maximum size of frees to delay before committing.  The larger this number, the greater the likelihood that "TOOLNAME" will identify use-after-free errors.  However, the larger this number, the more memory will be used.  This value is separate for each set of allocation routines and each Windows Heap.")
OPTION_CLIENT_BOOL(drmemscope, delay_frees_stack, true,
                   "Record callstacks on free to use when reporting use-after-free",
                   "Record callstacks on free to use when reporting use-after-free or other errors that overlap with freed objects.  There is a slight performance hit incurred by this feature for malloc-intensive applications.  The callstack size is controlled by -free_max_frames.")
OPTION_CLIENT_BOOL(drmemscope, leaks_only, false,
                   "Check only for leaks and not memory access errors",
                   "Puts "TOOLNAME" into a leak-check-only mode that has lower overhead but does not detect other types of errors other than invalid frees.")
#ifdef WINDOWS
OPTION_CLIENT_BOOL(drmemscope, handle_leaks_only, false,
                   "Check only for handle leak errors and no other errors",
                   "Puts "TOOLNAME" into a handle-leak-check-only mode that has lower overhead but does not detect other types of errors other than handle leaks in Windows.")
#endif /* WINDOWS */
/* XXX i#1726: only pattern is currently supported on ARM */
OPTION_CLIENT_BOOL(drmemscope, check_uninitialized, IF_ARM_ELSE(false, true),
                   "Check for uninitialized read errors",
                   "Check for uninitialized read errors.  When disabled, puts "TOOLNAME" into a mode that has lower overhead but does not detect definedness errors.  Furthermore, the lack of definedness information reduces accuracy of leak identification, resulting in potentially failing to identify some leaks.")
OPTION_CLIENT_BOOL(drmemscope, check_stack_bounds, false,
                   "For -no_check_uninitialized, whether to check for beyond-top-of-stack accesses",
                   "Only applies for -no_check_uninitialized.  Determines whether to check for beyond-top-of-stack accesses.")
OPTION_CLIENT_BOOL(drmemscope, check_stack_access, false,
                   "For -no_check_uninitialized, whether to check for errors on stack or frame references",
                   "Only applies for -no_check_uninitialized.  Determines whether to check for errors on memory references that use %esp or %ebp as a base.  These are normally local variable and function parameter references only, but for optimized or unusual code they could point elsewhere in memory.  Checking these incurs additional overhead.")
OPTION_CLIENT_BOOL(drmemscope, check_alignment, false,
                   "For -no_check_uninitialized, whether to consider alignment",
                   "Only applies for -no_check_uninitialized.  Determines whether to incur additional overhead in order to handle memory accesses that are not aligned to their size.  With this option off, the tool may miss bounds overflows that involve unaligned memory references.")
OPTION_CLIENT_BOOL(drmemscope, fault_to_slowpath, true,
                   "For -no_check_uninitialized, use faults to exit to slowpath",
                   "Only applies for -no_check_uninitialized.  Determines whether to use faulting instructions rather than explicit jump-and-link to exit from fastpath to slowpath.")
#ifdef WINDOWS
OPTION_CLIENT_BOOL(internal, check_tls, true,
                   "Check for access to un-reserved TLS slots",
                   "Check for access to un-reserved TLS slots")
OPTION_CLIENT_BOOL(drmemscope, check_gdi, true,
                   "Check for GDI API usage errors",
                   "Check for GDI API usage errors.  Any errors detected will be reported as errors of type GDI USAGE ERROR.")
OPTION_CLIENT_BOOL(drmemscope, check_gdi_multithread, false,
                   "Check for GDI API usage error of one DC used by multiple threads",
                   "Check for GDI API usage error of one DC used by multiple threads.  Some system libraries violate this guideline, however, resulting in potential false positives.")
OPTION_CLIENT_BOOL(drmemscope, check_handle_leaks, true,
                   "Check for handle leak errors",
                   "Check for handle leak errors.  Any errors detected will be reported as errors of type HANDLE LEAK.  This is currently an experimental option and is very conservative, placing any error it is not sure about in potential_errors.txt rather than reporting in the main set of errors found.")
OPTION_CLIENT_BOOL(internal, filter_handle_leaks, true,
                   "Filter handle leaks for better error reports",
                   "Filter handle leaks and only report those that are more likely to be real leaks.  The rest of the leaks are reported to potential_errors.txt rather than results.txt.")
OPTION_CLIENT(internal, handle_leak_threshold, uint, 50, 1, 65535,
              "Report leaks of handles created more often than this threshold",
              "Only applies for -filter_handle_leaks.  Report leaks of handles created more often than this threshold.")
/* XXX i#1839: on 64-bit, false positive Windows vs C mismatches are
 * proving difficult to handle.  We are disabling the feature for now.
 */
OPTION_CLIENT_BOOL(drmemscope, check_heap_mismatch, IF_X64_ELSE(false, true),
                   "Whether to check for Windows API vs C library mismatches",
                   "Whether to check for Windows API vs C library mismatches")
#endif
OPTION_CLIENT_BOOL(drmemscope, check_delete_mismatch, true,
                   "Whether to check for free/delete/delete[] mismatches",
                   "Whether to check for free/delete/delete[] mismatches")
OPTION_CLIENT_BOOL(drmemscope, check_prefetch, true,
                   "Whether to report unaddressable prefetches as warnings",
                   "Whether to report unaddressable prefetches as warnings")
OPTION_CLIENT_BOOL(drmemscope, malloc_callstacks, false,
                   "Record callstacks on allocs to use when reporting mismatches",
                   "Record callstacks on allocations to use when reporting alloc/free mismatches.  If leaks are enabled (i.e., -count_leaks is on), this option is always enabled.  The callstack size is controlled by -malloc_max_frames.  When enabled in light mode, this option incurs additional overhead, particularly on malloc-intensive applications.")

OPTION_CLIENT_STRING(drmemscope, prctl_whitelist, "",
                     "Disable instrumentation unless PR_SET_NAME is on list",
                     "If this list is non-empty, when "TOOLNAME" sees prctl(PR_SET_NAME) and the name is not on the list, then "TOOLNAME" will disable its instrumentation for the rest of the process and for all of its child processes.  The list is ,-separated.")
OPTION_CLIENT_STRING(drmemscope, auxlib, "",
                     "Load auxiliary system call handling library",
                     "This option should specify the basename of an auxiliary system call handling library found in the same directory as the Dr. Memory client library.")
OPTION_CLIENT_BOOL(drmemscope, analyze_unknown_syscalls, true,
                   "For unknown syscalls use memory comparison to find output params",
                   "For unknown syscalls use memory comparison to find output params")
OPTION_CLIENT_BOOL(drmemscope, syscall_dword_granularity, true,
                   "For unknown syscall comparisons, use dword granularity",
                   "For unknown syscall comparisons (-analyze_unknown_syscalls), when changes are detected, consider the containing dword to have changed")
OPTION_CLIENT_BOOL(drmemscope, syscall_sentinels, false,
                   "Use sentinels to detect writes on unknown syscalls.",
                   "Use sentinels to detect writes on unknown syscalls and reduce false positives, in particular for uninitialized reads.  Can potentially result in incorrect behavior if definedness information is incorrect or application threads read syscall parameter info simultaneously.  This option requires -analyze_unknown_syscalls to be enabled.")
/* for chromium we need to ignore malloc_usable_size, and for most windows
 * uses it doesn't exist, so we have this on by default (xref i#314, i#320)
 */
OPTION_CLIENT_BOOL(drmemscope, prefer_msize, IF_WINDOWS_ELSE(true, false),
                   "Prefer _msize to malloc_usable_size when both are present",
                   "Prefer _msize to malloc_usable_size when both are present")

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
/* We know this is logically a little weird to have -light be shadow and
 * -unaddr_only be pattern, but from the outside we're pretending that
 * shadow-based light and pattern-based light are the same.
 */
OPTION_CLIENT_BOOL(drmemscope, unaddr_only, false,
                   "Enables a lightweight mode that detects only unaddressable errors",
                   "This option enables a lightweight mode that only detects critical errors of unaddressable accesses on heap data.  This option cannot be used with 'light' or 'check_uninitialized'.")
/* XXX i#1726: only pattern is currently supported on ARM */
OPTION_CLIENT_SCOPE(drmemscope, pattern, uint, IF_ARM_ELSE(DEFAULT_PATTERN, 0),
                    0, USHRT_MAX,
                    "Enables pattern mode. A non-zero 2-byte value must be provided",
                    "Use sentinels to detect accesses on unaddressable regions around allocated heap objects.  When this option is enabled, checks for uninitialized read errors will be disabled.  The value passed as the pattern must be a non-zero 2-byte value.")
OPTION_CLIENT_BOOL(drmemscope, persist_code, false,
                   "Cache instrumented code to speed up future runs (light mode only)",
                   "Cache instrumented code to speed up future runs.  For short-running applications, this can provide a performance boost.  It may not be worth enabling for long-running applications.  Currently, this option is only supported with -light or -no_check_uninitialized.  It also currently fails to re-use randomized libraries on Windows, resulting in less of a performance boost for applications that use many libraries with ASLR enabled.")
OPTION_CLIENT_STRING(drmemscope, persist_dir, "<install>/logs/codecache",
                     "Directory for code cache files",
                     "Destination for code cache files.  When using a unique log directory for each run, symbols will not be shared across runs because the default cache location is inside the log directory.  Use this option to set a shared directory.")
OPTION_CLIENT_BOOL(drmemscope, soft_kills, true,
                   "Ensure external processes terminated by this one exit cleanly",
                   "Ensure external processes terminated by this one exit cleanly.  Often applications forcibly terminate child processes, which can prevent proper leak checking and error and suppression summarization as well as generation of symbol and code cache files needed for performance.  When this option is enabled, every termination call to another process will be replaced with a directive to the Dr. Memory running in that process to perform a clean shutdown.  If there is no DynamoRIO-based tool in the target process, the regular termination call will be carried out.")
OPTION_CLIENT_BOOL(drmemscope, ignore_kernel, false,
                   "Attempt execution on an unsupported kernel",
                   "Continue past the normally-fatal usage error of running on an unsupported kernel version.  This risks false positives and potential tool failure due to unknown system call behavior.")
OPTION_CLIENT_BOOL(drmemscope, use_syscall_tables, true,
                   "Use Dr. Memory's own syscall tables where possible",
                   "On by default, this allows disabling the use of Dr. Memory's own syscall tables, in case the check for whether they match the underlying kernel is inaccurate.")
OPTION_CLIENT_STRING(drmemscope, syscall_number_path, "",
                   "Points at a directory containing a system call number file",
                   "When running on an operating system version that this version of Dr. Memory does not have direct support for, a system call number file can be used to provide needed operating system information.  These files are named syscalls_{x86,wow64,x64}.txt.  This parameter should point at the directory containing the file.  By default these are located in -symcache_dir.")
OPTION_CLIENT_BOOL(drmemscope, coverage, false,
                   "Measure and provide code coverage information",
                   "Measure code coverage during application execution.  The resulting data is written to a separate file named with a 'drcov' prefix in the same directory as Dr. Memory's other results files.  The raw data can be turned into a human-readable format using the drcov2lcov utility.")
OPTION_CLIENT_BOOL(drmemscope, fuzz, false,
                   "Enable fuzzing by Dr. Memory",
                   "Enable fuzzing by Dr. Memory.  See the other fuzz_* options for all of the different fuzzing options.")
OPTION_CLIENT_STRING(drmemscope, fuzz_module, "",
                     "The fuzz target module name. The application main executable is used by default.",
                     "The fuzz target module name. The application main executable is used by default.")
# define FUZZ_FUNC_DEFAULT_NAME "DrMemFuzzFunc"
OPTION_CLIENT_STRING(drmemscope, fuzz_function, FUZZ_FUNC_DEFAULT_NAME,
                     "The fuzz target function symbol name. "FUZZ_FUNC_DEFAULT_NAME" is used by default.",
                     "The fuzz target function symbol name. "FUZZ_FUNC_DEFAULT_NAME" is used by default.")
OPTION_CLIENT_SCOPE(drmemscope, fuzz_offset, uint, 0, 0, UINT_MAX,
                     "The fuzz target function offset in the module.",
                     "The fuzz target function offset in the module.")
OPTION_CLIENT_SCOPE(drmemscope, fuzz_num_args, uint, 2, 0, 32,
                    "The number of arguments passed to the fuzz target function.",
                    "The number of arguments passed to the fuzz target function.  For vararg functions this must match the actual number of arguments passed by the caller.")
OPTION_CLIENT_SCOPE(drmemscope, fuzz_data_idx, uint, 0, 0, 31,
                    "The fuzz data argument index.",
                    "The fuzz data argument index.")
OPTION_CLIENT_SCOPE(drmemscope, fuzz_size_idx, uint, 1, 0, 31,
                    "The fuzz data size argument index.",
                    "The fuzz data size argument index.")
OPTION_CLIENT_SCOPE(drmemscope, fuzz_num_iters, int, 100, 0, INT_MAX,
                    "The number of times to repeat executing the target function.",
                    "The number of times to repeat executing the target function. "
                    "Use 0 for no repeat and no mutation, and -1 to repeat until the mutator is exhausted.")
OPTION_CLIENT_BOOL(drmemscope, fuzz_replace_buffer, false,
                   "Replace the input data buffer with separately allocated memory.",
                   "Replace the input data buffer with separately allocated memory.  This can be used for fuzzing functions whose input data is stored in read-only memory, or for fuzzing functions with different input data sizes, e.g., loading data via -fuzz_input_file.  Note: this may cause problems if other pointers point to the original buffer, or the replaced buffer is used after the fuzzing iterations.")
OPTION_CLIENT_STRING(drmemscope, fuzz_call_convention, "",
                     "The calling convention used by the fuzz target function."NL
                     "        The possible calling convention codes are:"NL
                     "             arm32    = ARM32"NL
                     "             amd64    = AMD64"NL
                     "             fastcall = fastcall"NL
                     "             ms64     = Microsoft x64 (Visual Studio)"NL
                     "             stdcall  = cdecl or stdcall"NL
                     "             thiscall = thiscall",
                     "The calling convention used by the fuzz target function. It can be specified using one of the following codes:"
                     "<pre>"
                     "&nbsp;&nbsp;&nbsp;&nbsp;<code>arm32    = ARM32</code>\n"
                     "&nbsp;&nbsp;&nbsp;&nbsp;<code>amd64    = AMD64</code>\n"
                     "&nbsp;&nbsp;&nbsp;&nbsp;<code>fastcall = fastcall</code>\n"
                     "&nbsp;&nbsp;&nbsp;&nbsp;<code>ms64     = Microsoft x64 (Visual Studio)</code>\n"
                     "&nbsp;&nbsp;&nbsp;&nbsp;<code>stdcall  = cdecl or stdcall</code>\n"
                     "&nbsp;&nbsp;&nbsp;&nbsp;<code>thiscall = thiscall</code>"
                     "</pre>"
                     "If no calling convention is specified, the most common calling convention on the platform is used:"
                     "<pre>"
                     "&nbsp;&nbsp;&nbsp;&nbsp;<code>32-bit ARM:     arm32</code>\n"
                     "&nbsp;&nbsp;&nbsp;&nbsp;<code>32-bit Unix:    stdcall</code>\n"
                     "&nbsp;&nbsp;&nbsp;&nbsp;<code>32-bit Windows: stdcall</code>\n"
                     "&nbsp;&nbsp;&nbsp;&nbsp;<code>64-bit Unix:    amd64</code>\n"
                     "&nbsp;&nbsp;&nbsp;&nbsp;<code>64-bit Windows: ms64</code>\n"
                     "</pre>")
OPTION_CLIENT_BOOL(drmemscope, fuzz_dump_on_error, true,
                   "Dump the current fuzz input to current log directory on an error report.",
                   "Dump the current fuzz input to current log directory on an error report.  The file name can be found in the error report summary.")
OPTION_CLIENT_STRING(drmemscope, fuzz_input_file, "",
                     "Load data from specified file as fuzz input.",
                     "Load data from specified file as fuzz input.  It can be used with -fuzz_num_iters 0 to reproduce an error from the input generated by -fuzz_dump_on_error.  The data might be truncated if the data size is larger than the input buffer size.  Use -fuzz_replace_buffer to replace the input buffer with a separately allocated buffer.")
OPTION_CLIENT_STRING(drmemscope, fuzz_corpus, "",
                     "Load a corpus of input data files and perform coverage based fuzzing.",
                     "Load a corpus of input data files from the specified directory, perform coverage based fuzzing, and dump input data that causes more coverage.")
OPTION_CLIENT_STRING(drmemscope, fuzz_corpus_out, "",
                     "Create and store the minimized corpus inputs from -fuzz_corpus to -fuzz_corpus_out",
                     "Create the minimized corpus inputs from -fuzz_corpus and dump them to the directory specified by -fuzz_corpus_out.")
OPTION_CLIENT_BOOL(drmemscope, fuzz_coverage, false,
                   "Enable basic block coverage guided fuzzing.",
                   "Enable basic block coverage guided fuzzing for the default bit-flip based mutator.  A custom mutator that implements drfuzz_mutator_feedback must use this option to enable the coverage feedback guided mutation.")
/* long comment includes HTML escape characters (http://www.doxygen.nl/htmlcmds.html) */
OPTION_CLIENT_STRING(drmemscope, fuzz_target, "",
                     "Fuzz test the target program according to the specified descriptor"NL
                     "        Fuzz descriptor format: <target>|<arg-count>|<buffer-index>|<size-index>|<repeat-count>[|<calling-convention>]"NL
                     "        where <target> is one of:"NL
                     "             <module>!<symbol>"NL
                     "             <module>+<offset>"NL
                     "        The <arg-count> specifies the number of arguments to the function (for vararg"NL
                     "        functions this must match the actual number of arguments passed by the app)."NL
                     "        The <*-index> arguments specify the index of the corresponding parameter in"NL
                     "        the target function. The <repeat-count> indicates the number of times to repeat"NL
                     "        the target function (use 0 for no repeat and no mutation, and -1 to repeat until"NL
                     "        the mutator is exhausted. The alias <main> may be given as the <module> to"NL
                     "        specify the main module of the program."NL
                     "        The calling convention codes are:"NL
                     "             1 = AMD64"NL
                     "             2 = Microsoft x64 (Visual Studio)"NL
                     "             3 = ARM32"NL
                     "             4 = cdecl or stdcall"NL
                     "             5 = fastcall"NL
                     "             6 = thiscall"NL,
                     "Fuzz test the target program according to the specified descriptor, which should have the format:<pre>&nbsp;&nbsp;&nbsp;&nbsp;<code>&lt;target&gt;|&lt;arg-count&gt;|&lt;buffer-index&gt;|&lt;size-index&gt;|&lt;repeat-count&gt;[|&lt;calling-convention&gt;]</code></pre>where <code>&lt;target&gt;</code> has one of two formats:<pre>&nbsp;&nbsp;&nbsp;&nbsp;<code>&lt;module&gt;!&lt;symbol&gt;</code>\n&nbsp;&nbsp;&nbsp;&nbsp;<code>&lt;module&gt;+&lt;offset&gt;</code></pre>Here, <code>&lt;module&gt;</code> refers to a single binary image file such as a library (.so or .dll) or an application executable (.exe on Windows). The <code>&lt;offset&gt;</code> specifies the entry point of the target function as a hexadecimal offset (e.g. '0xf7d4') from the start of the module that contains it (i.e., the library or executable image). The <code>&lt;symbol&gt;</code> may be either a plain C function name, a mangled C++ symbol, or (Windows only) a de-mangled C++ symbol of the form returned by the \\ref page_symquery. The option <code>-fuzz_mangled_names</code> is required for using mangled names in Windows, and the mangled name must have every '@' character escaped by substituting a '-' in its place. The module alias &lt;main&gt; may be used to refer to the main module of the process, which is the program executable.<br/><br/>The &lt;arg-count&gt; specifies the number of arguments to the function (for vararg functions this must match the actual number of arguments passed by the app). The &lt;*-index&gt; arguments specify the index of the corresponding parameter in the target function. The &lt;repeat-count&gt; indicates the number of times to repeat the target function (use 0 to repeat until the mutator is exhuasted). The optional &lt;calling-convention&gt; can be specified using one of the following codes:<pre>&nbsp;&nbsp;&nbsp;&nbsp;<code>1 = AMD64</code>\n&nbsp;&nbsp;&nbsp;&nbsp;<code>2 = Microsoft x64 (Visual Studio)</code>\n&nbsp;&nbsp;&nbsp;&nbsp;<code>3 = ARM32</code>\n&nbsp;&nbsp;&nbsp;&nbsp;<code>4 = cdecl or stdcall</code>\n&nbsp;&nbsp;&nbsp;&nbsp;<code>5 = fastcall</code>\n&nbsp;&nbsp;&nbsp;&nbsp;<code>6 = thiscall</code></pre>")
OPTION_CLIENT_STRING(drmemscope, fuzz_mutator_lib, "",
                     "Specify a custom third-party mutator library",
                     "Specify a custom third-party mutator library to use instead of the default mutator library provided by Dr. Fuzz.")
OPTION_CLIENT_STRING_REPEATABLE(drmemscope, fuzz_mutator_ops, "",
                     "Specify mutator options",
                     "Specify options to pass to either the default mutator library or to the custom third-party mutator library named in -fuzz_mutator_lib.")

/* XXX: these fuzz_mutator docs and options essentially duplicate drfuzz.dox and
 * the default mutator options in drfuzz_mutator.c, but it may not be worth
 * sharing code/docs via some new *x.h file unless we start adding more and more
 * options.
 */
OPTION_CLIENT_STRING(drmemscope, fuzz_mutator_alg, "ordered",
                     "Specify the mutator algorithm: 'random' or 'ordered'",
                     "Specify the mutator algorithm as one of these strings:@@<ul>"
                     "<li>random = random selection of bits or numbers.@@"
                     "<li>ordered = ordered sequence of bits or numbers.@@"
                     "</ul>@@See also \\ref sec_drfuzz_mutators.@@")
OPTION_CLIENT_STRING(drmemscope, fuzz_mutator_unit, "bits",
                     "Specify the mutator unit: 'bits' or 'num'",
                     "Specify the mutator unit of operation as one of these strings:@@<ul>"
                     "<li>bits = mutation by bit flipping.@@"
                     "<li>num = mutation by random number generation.@@"
                     "<li>token = mutation by inserting tokens from -fuzz_dictionary.@@"
                     "</ul>@@See also \\ref sec_drfuzz_mutators.@@")
OPTION_CLIENT_SCOPE(drmemscope, fuzz_mutator_flags, uint, 1, 0, UINT_MAX,
                    "Specify mutator flags",
                    "Specify flags controlling mutator operation:@@<ul>"
                    "<li>0x1 = reset to the original buffer value passed by the app before each mutation.@@"
                    "<li>0x2 = seed the mutator's random number generator with the current clock time.@@"
                    "</ul>@@See also \\ref sec_drfuzz_mutators.@@")
OPTION_CLIENT_SCOPE(drmemscope, fuzz_mutator_sparsity, uint, 1, 0, UINT_MAX,
                    "Values to skip between mutations",
                    "Specifies a number of values to skip between mutations.  See also \\ref sec_drfuzz_mutators.")
OPTION_CLIENT_SCOPE(drmemscope, fuzz_mutator_max_value, uint64, 0, 0, ULLONG_MAX,
                    "Maximum mutation value for <8-byte buffers (0 is unlimited)",
                    "For buffers of size 8 bytes or smaller, specifies the maximum mutation value. Use value 0 to disable the maximum value (i.e., limit only by the buffer capacity).  See also \\ref sec_drfuzz_mutators.")
OPTION_CLIENT_SCOPE(drmemscope, fuzz_mutator_random_seed, uint64, 0x5a8390e9a31dc65fULL, 0, ULLONG_MAX,
                    "Randomization seed for the random algorithm",
                    "Randomization seed for -fuzz_mutator_alg random.  The default random seed is arbitrary, selected to have an equal number of 0 and 1 bits.  See also \\ref sec_drfuzz_mutators.")
OPTION_CLIENT_STRING(drmemscope, fuzz_dictionary, "",
                     "Specify a dictionary containing tokens for mutation",
                     "Specify a dictionary file listing tokens to use for mutation by insertion into the input buffer.  The file must be a text file with one double-quote-delimited token per line.  Specifying this option automatically selects -fuzz_mutator_unit token.")

OPTION_CLIENT_STRING(drmemscope, fuzz_one_input, "",
                     "Specify one fuzz input value to test."NL
                     "         The value is a hexadecimal byte sequence using the literal byte order (i.e., non-endian),"NL
                     "         for example '7f392a' represents byte array { 0x7f, 0x39, 0x2a }.",
                     "Specify one fuzz input value to test. The value is a hexadecimal byte sequence using the printed byte order (i.e., non-endian), for example '7f392a' represents byte array { 0x7f, 0x39, 0x2a }. If the value length does not match the fuzz target buffer length, it will be truncated or zero-padded to fit.")
OPTION_CLIENT_SCOPE(drmemscope, fuzz_buffer_fixed_size, uint, 0, 0, UINT_MAX,
                    "Set a fixed mutation span",
                    "Use this option to ignore the size of the buffer argument and instead mutate a fixed span of bytes. If the actual buffer size is smaller than the specified fixed size, the actual size will be used instead.")
OPTION_CLIENT_SCOPE(drmemscope, fuzz_buffer_offset, uint, 0, 0, UINT_MAX,
                    "Set an offset for the mutation span",
                    "Use this option to constrain mutation to a subset of buffer bytes starting at the specified offset from the buffer start.")
OPTION_CLIENT_SCOPE(drmemscope, fuzz_skip_initial, uint, 0, 0, UINT_MAX,
                    "Skip fuzzing for the specified number of target invocations",
                    "Skip fuzzing for the specified number of target invocations.")
OPTION_CLIENT_SCOPE(drmemscope, fuzz_stat_freq, uint, 0, 0, UINT_MAX,
                    "Enable fuzzer status logging with the specified frequency",
                    "Specify the fuzzer status log frequency in number of fuzz iterations (no status is logged when this option is not set).")
#ifdef WINDOWS
OPTION_CLIENT_BOOL(drmemscope, fuzz_mangled_names, false,
                   "Enable mangled names for fuzz targets on Windows",
                   "By default, fuzz targets on Windows must use demangled names. Use this option to enabled mangled names. It is required to escape every '@' character by replacing it with a '-' in the mangled name (due to delimiter conflicts over '@' in the toolchain).")
#endif

/****************************************************************************
 * Un-documented client options, for developer use only
 */

OPTION_CLIENT_SCOPE(internal, resfile, uint, 0, 0, UINT_MAX,
                   "For the given pid, write the result file path to <logdir>/resfile.<pid>",
                   "Write the result file path to <logdir>/resfile.<pid> if the process id equals the passed-in option value")
OPTION_CLIENT_BOOL(internal, use_stderr, true,
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
OPTION_CLIENT_BOOL(internal, track_heap, true,
                   "Track malloc and other library allocations",
                   "If false, "TOOLNAME" only tracks memory allocations at the system call level and does not delve into individual malloc units.  This is required to track leaks, even for system-call-only leaks.  Nowadays we use the heap info for other things, like thread stack identification (PR 418629), and don't really support turning this off.  Requires track_allocs.")
OPTION_CLIENT_BOOL(internal, size_in_redzone, true,
                   "Store alloc size in redzone",
                   "Store size in redzone.  This can only be enabled if redzone_size >= sizeof(size_t).")
OPTION_CLIENT_BOOL(internal, fastpath, true,
                   "Enable fastpath",
                   "Enable fastpath")
/* XXX i#2027: implement and enable for x64 */
OPTION_CLIENT_BOOL(internal, esp_fastpath, IF_X64_ELSE(false, true),
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
OPTION_CLIENT(internal, num_spill_slots, uint, 6, 0, 16,
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
/* We don't want or need this on Linux (xref i#1295) */
OPTION_CLIENT_BOOL(internal, define_unknown_regions, IF_WINDOWS_ELSE(true, false),
                   "Mark unknown regions as defined",
                   "Handle memory allocated by other processes (or that we miss due to unknown system calls or other problems) by treating as fully defined.  Xref PR 464106.")
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
OPTION_CLIENT_BOOL(internal, repstr_to_loop, true,
                   "Add fastpath for rep string instrs by converting to normal loop",
                   "Add fastpath for rep string instrs by converting to normal loop")
OPTION_CLIENT_BOOL(internal, replace_realloc, true,
                   "Replace realloc to avoid races and non-delayed frees",
                   "Replace realloc to avoid races and non-delayed frees")
/* XXX i#2025: enable for x64 once failures are fixed */
/* XXX i#2032, i#2009: disabling due to lack of confidence in the feature */
OPTION_CLIENT_BOOL(internal, share_xl8, IF_X64_ELSE(false, false),
                   "Share translations among adjacent similar references",
                   "Share translations among adjacent similar references")
OPTION_CLIENT(internal, share_xl8_max_slow, uint, 5000, 0, UINT_MAX/2,
              "How many slowpaths before abandoning sharing for an individual instr",
              "Sharing does not work across 64K boundaries, and if we get this many slowpaths we flush and re-instrument the at-fault instr without sharing")
OPTION_CLIENT(internal, share_xl8_max_diff, uint, 2048, 0, SHADOW_REDZONE_SIZE*4,
              "Maximum displacement difference to share translations across",
              "Maximum displacement difference to share translations across")
OPTION_CLIENT(internal, share_xl8_max_flushes, uint, 64, 0, UINT_MAX,
              "How many flushes before abandoning sharing altogether",
              "How many flushes before abandoning sharing altogether")
OPTION_CLIENT_BOOL(internal, check_memset_unaddr, true,
                   "Check for in-heap unaddr in memset",
                   "Check for in-heap unaddr in memset")
#ifdef WINDOWS
OPTION_CLIENT_BOOL(internal, disable_crtdbg, true,
                   "Disable debug CRT checks",
                   "Disable debug CRT checks")
#endif

/* XXX i#1726: port the zeroing loop to ARM */
/* FIXME i#1205: zeroing conflicts w/ UNIX x64 redzone: NYI */
OPTION_CLIENT_BOOL(internal, zero_stack,
                   IF_ARM_ELSE(false, IF_X64_ELSE(IF_UNIX_ELSE(false, true), true)),
                   "When detecting leaks but not keeping definedness info, zero old stack frames",
                   "When detecting leaks but not keeping definedness info, zero old stack frames in order to avoid false negatives from stale stack values.  This is potentially unsafe.")
OPTION_CLIENT_BOOL(internal, zero_retaddr, true,
                   "Zero stale return addresses for better callstacks",
                   "Zero stale return addresses for better callstacks.  When enabled, zeroing is performed in all modes of Dr. Memory.  This is theoretically potentially unsafe.  If your application does not work correctly because of this option please let us know.")

#ifdef SYSCALL_DRIVER
OPTION_CLIENT_BOOL(internal, syscall_driver, false,
                   "Use a syscall-info driver if available",
                   "Use a syscall-info driver if available")
#endif
OPTION_CLIENT_BOOL(internal, verify_sysnums, false,
                   "Check system call numbers at startup",
                   "Check system call numbers at startup")
OPTION_CLIENT_BOOL(internal, leave_uninit, false,
                   "Do not mark an uninitialized value as defined once reported",
                   "Do not mark an uninitialized value as defined once reported.  This may result in many reports for the same error.")
OPTION_CLIENT_BOOL(internal, fpxmm_mem2mem_prop, true,
                   "Use heuristic to propagate copies through float regs",
                   "Currently, Dr. Memory does not propagate shadow values through floating-point registers.  To avoid false positives on memory copies that use fld;fstp sequences, this option enables a heuristic that propagates just on such sequences.")
OPTION_CLIENT_BOOL(internal, leak_scan, true,
                   "Perform leak scan",
                   "Whether to perform the leak scan.  For performance measurement purposes only.")
OPTION_CLIENT_BOOL(internal, pattern_use_malloc_tree, false,
                   "Use red-black tree for tracking malloc/free",
                   "Use red-black tree for tracking malloc/free to reduce the overhead of maintaining the malloc tree on every memory allocation and free, but we have to do expensive hashtable walk to check if an address is in the redzone.")
OPTION_CLIENT_BOOL(internal, replace_malloc, true,
                   "Replace malloc rather than wrapping existing routines",
                   "Replace malloc with custom routines rather than wrapping existing routines.  Replacing is more efficient and avoids several issues with the Windows debug C library where wrapping must disable some of Dr. Memory's checks.")
OPTION_CLIENT_SCOPE(internal, pattern_max_2byte_faults, int, 0x1000, -1, INT_MAX,
                    "The max number of faults caused by 2-byte pattern checks we could tolerate before switching to 4-byte checks only",
                    "The max number of faults caused by 2-byte pattern checks we could tolerate before switching to 4-byte checks only. 0 means do not use 2-byte checks, and negative value means always use 2-byte checks")
OPTION_CLIENT(internal, callstack_dump_stack, uint, 0, 0, 512*1024,
              "How much of the stack to dump to the logfile",
              "How much of the stack to dump to the logfile prior to each callstack walk.  Debug-build only.")
OPTION_CLIENT_BOOL(internal, pattern_opt_repstr, true,
                   "For pattern mode, optimize each loop expanded from a rep string instruction",
                   "For pattern mode, optimize each loop expanded from a rep string instruction by using an inner loop to avoid unnecessary aflags save/restore.")
OPTION_CLIENT_BOOL(internal, pattern_opt_elide_overlap, false,
                   "For pattern mode, remove redundant checks",
                   "For pattern mode, remove redundant checks if they overlap with other existing checks. This can result in not reporting an error in favor of reporting another error whose memory reference is adjacent. Thus, this gives up the property of reporting any particular error before it happens: a minor tradeoff in favor of performance.")
OPTION_CLIENT_BOOL(internal, track_origins_unaddr, false,
                   "Report possible origins of unaddressable errors caused by using uninitialized variables as pointers",
                   "Report possible origins of unaddressable errors caused by using uninitialized variables as pointers by reporting the alloc context of the memory being referenced by uninitialized pointers. This can result in additional overhead.")
OPTION_CLIENT(internal, native_until_thread, uint, 0, 0, UINT_MAX,
              "Run natively until the Nth thread is created",
              "Run natively until the Nth thread is created.  This is an experimental option and should be used with care.  This option is only supported with the -unaddr_only, -light, or -no_check_uninitialized modes.")
OPTION_CLIENT_BOOL(internal, native_parent, false,
                   "Run this process natively, but follow into children.",
                   "Run natively the entire execution of the initial process, but configure child processes to execute normally.  This mode also watches for process termination and implements -soft_kills (unless termination is not done via standard system call wrapper).")
#ifdef WINDOWS
OPTION_CLIENT_BOOL(internal, replace_nosy_allocs, false,
                   "Attempt to replace allocations whose headers are scrutinized.",
                   "Some Rtl allocations are scrutinized and freed without going through interfaces, making it difficult for Dr. Memory to replace them.  If this option is off, Dr. Memory leaves such allocations as native allocations.  Its methodology may also leave some normal allocations as native.  Xref i#1565.")
#endif
