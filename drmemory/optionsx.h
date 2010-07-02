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

/* Options list that can be processed and sent to drmemory.c, drmemory.pl, and
 * using.dox.
 *
 * FIXME PR 487993: also use this to construct the options struct and parsing code.
 */

/* OPTION(name, default val, short descr, long descr) */

/* Front-end-script options.  We present a unified list of options to users. */
OPTION("-dr <path>", "", "Path to DynamoRIO installation",
       "The path to the DynamoRIO installation to use.  Not needed when using a released Dr. Memory package.")
OPTION("-drmemory <path>", "", "Path to Dr. Memory installation",
       "The path to the base of the Dr. Memory installation.  Not needed when invoking Dr. Memory from an unmodified installation tree.")
OPTION("-srcfilter <name>", "", "Only show errors referencing named file",
       "Do not show errors that do not reference the named source file somewhere in their callstacks.")
OPTION("-nudge <pid>", "", "Process id to nudge",
       "Use this option to 'nudge' an already-running process in order to request leak checking and other Dr. Memory actions that normally only occur when the process exits.")
OPTION("-aggregate <logdir list>", "", "Produce aggregate error report",
       "Pass a list of log directories to produce an aggregate error report.  Useful for applications that consist of a group of separate processes.")
#ifdef VMX86_SERVER
OPTION("-use_vmtree", "true", "Use VMTREE and VMBLD env vars to locate symbols",
       "See \\ref sec_setup_syms.")
#endif
OPTION("-v", "", "Display verbose information in the Dr. Memory front end",
       "Display verbose information in the Dr. Memory front end")
#ifdef USE_DRSYMS
OPTION("-version", "", "Display Dr. Memory version", "Display Dr. Memory version")
#endif

/* Client options */
OPTION("-check_leaks", "false", "Whether to store leak callstacks",
       "Whether to store callstacks for each allocation in order to report them when leaks are detected.")
OPTION("-[no_]ignore_early_leaks", "true", "Whether to ignore pre-app leaks",
       "Whether to ignore leaks from system code prior to Dr. Memory taking over.")
OPTION("-[no_]check_leaks_on_destroy", "true", "Whether to report leaks on heap destruction",
       "If enabled, when a heap is destroyed (HeapDestroy on Windows), report any live allocations inside it as possible leaks.")
OPTION("-possible_leaks", "false", "Show possible-leak callstacks?",
       "Whether to list possibly-reachable allocations when leak checking.  Requires -check_leaks.")
OPTION("-[no_]midchunk_size_ok", "true", "Consider mid-chunk post-size pointers legitimate",
       "Consider allocations reached by a mid-allocation pointer that points past a size field at the head of the allocation to be reachable instead of possibly leaked.  Currently this option looks for a very specific pattern.  If your application's header is slightly different please contact the authors about generalizing this check.")
OPTION("-[no_]midchunk_new_ok", "true", "Consider mid-chunk post-new[]-header pointers legitimate",
       "Consider allocations reached by a mid-allocation pointer that points past a size field at the head of the allocation that looks like a new[] header to be reachable instead of possibly leaked.  A heuristic is used for this identification that is not perfect.")
OPTION("-[no_]midchunk_inheritance_ok", "true", "Consider mid-chunk multi-inheritance pointers legitimate",
       "Consider allocations reached by a mid-allocation pointer that points to a parent class instantiation to be reachable instead of possibly leaked.  A heuristic is used for this identification that is not perfect.")
OPTION("-[no_]midchunk_string_ok", "true", "Consider mid-chunk std::string pointers legitimate",
       "Consider allocations reached by a mid-allocation pointer that points to a char array inside an instance of a std::string representation to be reachable instead of possibly leaked.  A heuristic is used for this identification that is not perfect.")
OPTION("-show_reachable", "false", "Whether to list reachable allocs",
       "Whether to list reachable allocations when leak checking.  Requires -check_leaks.")
OPTION("-suppress <file>", "", "File containing errors to suppress",
       "File containing errors to suppress.  See \\ref sec_suppress.")
OPTION("-[no_]default_suppress", "", "Use the set of default suppressions",
       "Use the set of default suppressions that come with Dr. Memory.  See \\ref sec_suppress.")
OPTION("-callstack_max_frames <N>", "20", "How many call stack frames to display",
       "How many call stack frames to display in each error report.")
OPTION("-check_cmps", "true", "Check register definedness of cmps",
       "Report definedness errors on compares instead of waiting for conditional jmps.")
OPTION("-check_non_moves", "false", "Check register definedness of non-moves",
       "Report definedness errors on any instruction that is not a move.  Note: turning this option on may result in false positives, but can also help diagnose errors through earlier error reporting.")
/* The client default is "c:\\|/tmp" but the front-end script uses install/logs */
OPTION("-logdir <path>", "<install>/logs", "Destination for log files",
       "Destination for log files and result files.")
OPTION("-resfile_out", "false", "Whether to write the result file path to <logdir>/resfile.<pid>",
       "Whether to write the result file path to <logdir>/resfile.<pid>")
OPTION("-stack_swap_threshold <size>", "0x9000", "Stack change amount to consider a swap",
       "Stack change amount to consider a swap instead of an allocation or de-allocation on the same stack.  Dr. Memory attempts to dynamically tune this value unless it is changed from its default.")
OPTION("-redzone_size <N>", "8", "Buffer on either side of each malloc",
       "Buffer on either side of each malloc.  This should be a multiple of 8.")
OPTION("-report_max <N>", "20000", "Maximum non-leak errors to report (-1=no limit)",
       "Maximum non-leak errors to report (-1=no limit).")
OPTION("-report_leak_max <N>", "10000", "Maximum leaks to report (-1=no limit)",
       "Maximum leaks to report (-1=no limit).")
OPTION("-verbose <N>", "1", "Verbosity level in log files",
       "Verbosity level in log files.  Primarily for debugging of Dr. Memory itself.")
OPTION("-quiet", "false", "Suppress stderr messages",
       "Suppress stderr messages and, on Windows, popup messages.")
#ifdef USE_DRSYMS
OPTION("-batch", "false", "Do not invoke notepad at the end",
       "Do not launch notepad with the results file at application exit.")
OPTION("-summary", "true", "Display a summary of results to stderr",
       "Display a summary of errors to stderr at app exit.")
#else
OPTION("-summary", "false", "Display a summary prior to symbol processing",
       "Display a summary of errors prior to symbol-based suppression and other processing.")
#endif
OPTION("-warn_null_ptr", "false", "Warn if NULL passed to free/realloc",
       "Whether to warn when NULL is passed to free() or realloc().")
OPTION("-thread_logs", "false", "Use per-thread log files",
       "Use per-thread log files.")
OPTION("-delay_frees <N>", "2000", "Frees to delay before committing",
       "Frees to delay before committing.  The larger this number, the greater the likelihood that Dr. Memory will identify use-after-free errors.  However, the larger this number, the more memory will be used.")
OPTION("-pause_at_unaddressable", "false", "Messagebox at each unaddressable access",
       "Dr. Memory pauses at the point of each unaddressable access error that is identified.  On Windows, this pause is a popup window.  On Linux, the pause involves waiting for a keystroke, which may not work well if the application reads from stdin.  In that case consider -pause_via_loop as an additional option.")
OPTION("-pause_at_uninitialized", "false", "Messagebox at each uninitialized read",
       "Identical to -pause_at_unaddressable, but applies to uninitialized access errors.")
OPTION("-pause_via_loop", "false", "Pause via loop (not wait for stdin)",
       "Used in conjunction with -pause_at_uninitialized and -pause_at_uninitialized on Linux, this option causes Dr. Memory to pause via an infinite loop instead of waiting for stdin.  Dr. Memory will not continue beyond the first such error found.")
OPTION("-leaks_only", "false", "Check only for leaks and not memory access errors",
       "Puts Dr. Memory into a leak-check-only mode that has lower overhead but does not detect other types of errors other than invalid frees.")
OPTION("-prctl_whitelist", "''", "Disable instrumentation unless PR_SET_NAME is on list",
       "If this list is non-empty, when Dr. Memory sees prctl(PR_SET_NAME) and the name is not on the list, then Dr. Memory will disable its instrumentation for the rest of the process and for all of its child processes.")
