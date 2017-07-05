/* ***************************************************************************
 * Copyright (c) 2013-2017 Google, Inc.  All rights reserved.
 * ***************************************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of Google, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "droption.h"
#include "drltrace_options.h"

/* Frontend scope is defined here because if logdir is a forbidden path we have to change
 * it and provide for our client manually.
 */
droption_t<std::string> op_logdir
(DROPTION_SCOPE_ALL, "logdir", ".", "Log directory to print library call data",
 "Specify log directory where library call data will be written, in a separate file per "
 "process.  The default value is \".\" (current dir).  If set to \"-\", data for all "
 "processes are printed to stderr (warning: this can be slow).");

droption_t<bool> op_only_from_app
(DROPTION_SCOPE_CLIENT, "only_from_app", false, "Reports only library calls from the app",
 "Only reports library calls from the application itself, as opposed to all calls even "
 "from other libraries or within the same library.");

droption_t<bool> op_follow_children
(DROPTION_SCOPE_FRONTEND, "follow_children", true, "Trace child processes",
 "Trace child processes created by a target application. Specify -no_follow_children "
 "to disable.");

droption_t<bool> op_print_ret_addr
(DROPTION_SCOPE_CLIENT, "print_ret_addr", false, "Print library call's return address",
 "Print return addresses of library calls.");

droption_t<unsigned int> op_unknown_args
(DROPTION_SCOPE_CLIENT, "num_unknown_args", 2, "Number of unknown libcall args to print",
 "Number of arguments to print for unknown library calls.  Specify 0 to disable "
 "unknown args printing.");

droption_t<int> op_max_args
(DROPTION_SCOPE_CLIENT, "num_max_args", 6, "Maximum number of arguments to print",
 "Maximum number of arguments to print.  This option allows to limit the number of "
 "arguments to be printed.  Specify 0 to disable args printing (including unknown).");

droption_t<bool> op_config_file_default
(DROPTION_SCOPE_FRONTEND, "default_config", true, "Use default config file.",
 "Use config file that comes with drltrace and located in the same path. Specify "
 "no_use_config and provide a path to custom config file using -config option.");

droption_t<std::string> op_config_file
(DROPTION_SCOPE_ALL, "config", "", "The path to custom config file.",
 "Specify a custom path where config is located. The config file describes the prototype"
 " of library functions for printing library call arguments.  See drltrace documentation"
 " for more details.");

droption_t<bool> op_ignore_underscore
(DROPTION_SCOPE_CLIENT, "ignore_underscore", false, "Ignores library routine names "
 "starting with \"_\".", "Ignores library routine names starting with \"_\".");

droption_t<std::string> op_only_to_lib
(DROPTION_SCOPE_CLIENT, "only_to_lib", "", "Only reports calls to the library <lib_name>. ",
 "Only reports calls to the library <lib_name>. Argument is case insensitive on Windows.");

droption_t<bool> op_help
(DROPTION_SCOPE_FRONTEND, "help", false, "Print this message.", "Print this message");

droption_t<bool> op_version
(DROPTION_SCOPE_FRONTEND, "version", 0, "Print version number.", "Print version number.");

droption_t<unsigned int> op_verbose
(DROPTION_SCOPE_ALL, "verbose", 1, "Change verbosity.", "Change verbosity.");

droption_t<bool> op_use_config
(DROPTION_SCOPE_CLIENT, "use_config", true, "Use config file",
 "Use config file for library call arguments printing. Specify no_use_config to disable.");

droption_t<std::string> op_ltracelib_ops
(DROPTION_SCOPE_CLIENT, "ltracelib_ops",
 DROPTION_FLAG_SWEEP | DROPTION_FLAG_ACCUMULATE | DROPTION_FLAG_INTERNAL,
 "", "(For internal use: sweeps up drltracelib options)",
 "This is an internal option that sweeps up other options to pass to the drltracelib.");

