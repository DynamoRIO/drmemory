/* **********************************************************
 * Copyright (c) 2011 Google, Inc.  All rights reserved.
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
 * (scope, name, type, default_val, min, max, short_descr, long_descr)
 *
 * scope values:
 * - front    = for front-end script for data gathering run
 * - side     = for front-end script to target application in progress
 * - post     = for front-end script for post-run analysis
 * - script   = for front-end script for any use
 * - client   = for client; a documented option
 * - internal = for client; not a documented option (developer use only)
 */

/* We share a number of options with Dr. Memory */
#ifndef TOOLNAME
# define TOOLNAME "Dr. Heapstat"
#endif
#define drmemscope internal
#include "../drmemory/optionsx.h"

/****************************************************************************
 * Front-end-script options.  We present a unified list of options to users.
 */

OPTION_FRONT_STRING(front, drheapstat, "",
                    "Path to "TOOLNAME" installation",
                    "The path to the base of the "TOOLNAME" installation.  Not needed when invoking "TOOLNAME" from an unmodified installation tree.")

/* Visualization tool options */
OPTION_FRONT_BOOL(post, visualize, false,
                   "Launches the visualization tool",
                  "The profile data collected is presented graphically.  The -profdir and -x options must also be specified with this option.")
OPTION_FRONT_BOOL(post, view_leaks, false,
                   "Views leaks found in a prior run",
                  "Leaks found are written to results.txt in -profdir with symbolic callstacks for each allocation.  The -profdir and -x options must also be specified with this option.")
OPTION_FRONT_STRING(post, profdir, "",
                    "Profile data directory (must use with -visualize and -view_leaks).",
                    "Specifies the directory that contains the heap profile data to be visualized.  This option is only valid, and is required, with the -visualize or -view_leaks options.")
OPTION_FRONT_STRING(post, x, "",
                    "Path of exe profiled (must use with -visualize and -view_leaks).",
                    "Specifies the executable (with path) for which heap profile data was collected.  This option is only valid, and is required, with the -visualize or -view_leaks options.")
#ifdef VMX86_SERVER
/* Different descr from Dr. Memory */
OPTION_FRONT_BOOL(post, use_vmtree, true,
                   "Use VMTREE and VMBLD env vars to locate symbols (must use with -visualize and -view_leaks).",
                  "See \\ref sec_setup_syms.  This option is only valid, and is required, with the -visualize or -view_leaks options.")
#endif
OPTION_FRONT(post, from_nudge, int, -1, -1, INT_MAX,
             "Nudge to begin visualization from; use with -to_nudge",
             "Specifies which nudge to begin visualization from.  Must specify -to_nudge also.  Option value has to be 0 or greater but less than the -to_nudge value.  Valid only for a variable number of snapshots, i.e., with the -dump option.  For use only with -visualize.")
OPTION_FRONT(post, to_nudge, int, -1, -1, INT_MAX,
             "Nudge to end visualization with; use with -from_nudge",
             "Specifies which nudge to end visualization with.  Must specify -from_nudge also.  Option value has to be 0 or greater but less than or equal to the maximum reference points available.  Valid only for a variable number of snapshots, i.e., with the -dump option.  For use only with -visualize.")
OPTION_FRONT(post, view_nudge, int, -1, -1, INT_MAX,
             "Nudge to visualize",
             "Specifies which nudge to visualize.  Option value has to be greater than 0 but less than or equal to the maximum number of reference points available.  Valid only for a constant number of snapshots.  For use only with -visualize.")
OPTION_FRONT(post, stale_since, int, -1, -1, INT_MAX,
             "Show memory that wasn't accessed since specified time",
             "If staleness data was collected (via the -staleness option), this option displays a line in the graph that shows how much dynamically allocated memory (which was requested by the process, without padding or malloc headers) wasn't used since the specified time, in units corresponding to the -time_option specified (ticks, allocs, bytes or instruction counts)")
OPTION_FRONT(post, stale_for, int, -1, -1, INT_MAX,
             "Show memory that wasn't accessed for specified time",
             "If staleness data was collected (via the -staleness option), this option displays a line in the graph that shows how much dynamically allocated memory (which was requested by the process, without padding or malloc headers) wasn't used for the specified time, in units corresponding to the -time_option specified (ticks, allocs, bytes or instruction counts)")
OPTION_FRONT_BOOL(post, group_by_files, false,
                  "Break down memory usage by source files",
                  "For a selected snapshot, this option displays a list of files in a separate tab showing memory usage by source files.  It is sorted by total memory consumed, i.e., requested + pad + headers")

/****************************************************************************
 * Public client options
 */

OPTION_CLIENT_BOOL(client, time_instrs, false,
                   "Use instrs executed as time unit",
                   "Select the number of instructions executed as the time unit.")
OPTION_CLIENT_BOOL(client, time_allocs, false,
                   "Use allocations and frees as time unit",
                   "Select the number of allocations and frees made as the time unit.")
OPTION_CLIENT_BOOL(client, time_bytes, false,
                   "Use bytes allocated/deallocated as time unit",
                   "Select the number of bytes allocated and deallocated as the time unit.")
OPTION_CLIENT_BOOL(client, time_clock, true,
                   "Use wall-clock time as time unit",
                   "Select wall-clock time as the time unit.")
OPTION_CLIENT(client, snapshots, uint, 64, 2, 0xfffffff0,
              "Number of snapshots (unless -dump) (N=power of 2)",
              "The number of snapshots to dump at the end of the run.  It must be a power of 2.")
OPTION_CLIENT_BOOL(client, dump, false,
                   "Continuous snapshot dumps",
                   "Dump snapshots continuously every -dump_freq rather than maintaining a constant number and only dumping at a nudge or at exit.  Specifying this option disables the use of a constant number of snapshots regardless of the execution time of the application, which is the default.")
OPTION_CLIENT(client, dump_freq, uint, 1, 0, UINT_MAX,
              "Frequency at which to take snapshots for -dump",
              "If explicitly set to a non-zero value, enables -dump and indicates the frequency at which data will be written to the log files.  For -time_instrs, the frequency is -dump_freq*1000 instructions.  For -time_clock, the frequency is -dump_freq*10 milliseconds.  For -time_allocs, the frequency is -dump_freq instances of allocations and deallocations.  For -time_bytes, the frequency is -dump_freq bytes of allocations and deallocations.  For all cases the exact point of each snapshot may vary slightly from the precise -dump_freq specified.")
OPTION_CLIENT(client, peak_threshold, uint, 5, 0, 99,
              "Accuracy of peak snapshot, in percentage from the true peak.",
              "A new peak snapshot will only be taken if it is more than this percentage different from the existing peak snapshot in any of total size, number of allocations and frees, and timestamp.  Lowering this number can reduce performance but will also increase accuracy.")

OPTION_CLIENT_BOOL(client, staleness, true,
                   "Record staleness data for each allocation",
                   "Whether to record the time at which each allocation was last accessed.")
OPTION_CLIENT(client, stale_granularity, uint, 1000, 0, UINT_MAX,
              "Granularity of staleness, in milliseconds",
              "The granularity with which staleness is measured, in milliseconds.")
OPTION_CLIENT_BOOL(client, stale_ignore_sp, true,
                   "Ignore memory references off the stack",
                   "Do not track staleness of memory references that use only the stack pointer.  If your application allocates stacks in the heap, or uses the stack pointer register for purposes other than to point at the stack, then you should disable this option.  Disabling this option will decrease the performance of the Dr. Heapstat.")
OPTION_CLIENT_BOOL(internal/*undocumented perf option*/, stale_blind_store, false,
                   "Disables checking before storing to shadow mem",
                   "Disables checking before storing to shadow mem")

/* Different default and different descr from Dr. Memory */
OPTION_CLIENT(client, callstack_max_frames, uint, 150, 0, 4096,
              /* We need a big default so we can get all the way to
               * the bottom and have a nice tree of callstacks.  I've
               * seen 65 frames on hostd.  Update: later seeing >100
               * due to recursive calls.  Our stacks are dynamically
               * sized so a large max doesn't waste memory.
               */
              "How many call stack frames to record",
              "How many call stack frames to record for each allocation.  Any additional frames will be truncated, and any two call stacks with identical frames up to the maximum are considered identical.  A larger maximum will ensure that no call stack is truncated and that all unique call stacks remain separate, but can use more memory if many stacks are large.")

/* Different descr from Dr. Memory.  There is no separate -count_leaks here. */
OPTION_CLIENT_BOOL(client, check_leaks, true,
                   "Cheak for leaks at exit and each nudge",
       "In addition to profiling heap usage, check for leaks.  This is done when the application exits and on each nudge.  Leaks found can be seen afterward with the -view_leaks option.")
