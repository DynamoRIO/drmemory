/* **********************************************************
 * Copyright (c) 2011-2012 Google, Inc.  All rights reserved.
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

#ifdef LINUX
/* avoid depending on __isoc99_sscanf */
# define _GNU_SOURCE 1
# include <stdio.h>
# undef _GNU_SOURCE
#endif

#include "dr_api.h"
#include "drmgr.h"
#include "utils.h"
#include "options.h"
#include "shadow.h"
#include "pattern.h"

#undef sscanf /* eliminate warning from utils.h b/c we have _GNU_SOURCE above */

/***************************************************************************
 * OPTIONS
 */

/* not part of the default in optionsx.h b/c that's what front-end passes */
#ifdef LINUX
# define DEFAULT_LOGDIR "/tmp"
#else
# define DEFAULT_LOGDIR "c:"
#endif

enum {
    SCOPE_IS_PUBLIC_front    = true,
    SCOPE_IS_PUBLIC_side     = true,
    SCOPE_IS_PUBLIC_post     = true,
    SCOPE_IS_PUBLIC_script   = true,
    SCOPE_IS_PUBLIC_client   = true,
    SCOPE_IS_PUBLIC_internal = false,
};

enum {
    TYPE_IS_BOOL_bool       = true,
    TYPE_IS_BOOL_opstring_t = false,
    TYPE_IS_BOOL_multi_opstring_t = false,
    TYPE_IS_BOOL_uint       = false,
    TYPE_IS_BOOL_int        = false,
    TYPE_IS_STRING_bool       = false,
    TYPE_IS_STRING_opstring_t = true,
    TYPE_IS_STRING_multi_opstring_t = false,
    TYPE_IS_STRING_uint       = false,
    TYPE_IS_STRING_int        = false,
    TYPE_HAS_RANGE_bool       = false,
    TYPE_HAS_RANGE_opstring_t = false,
    TYPE_HAS_RANGE_multi_opstring_t = false,
    TYPE_HAS_RANGE_uint       = true,
    TYPE_HAS_RANGE_int        = true,
};

static const char * const bool_string[2] = {
    "false",
    "true",
};

drmemory_options_t options = {
#define OPTION_CLIENT(scope, name, type, defval, min, max, short, long) \
    defval,
#define OPTION_FRONT(scope, name, type, defval, min, max, short, long) \
    /*nothing*/
    /* we use <> so other tools can override the optionsx.h in "." */
#include <optionsx.h>
};
#undef OPTION_CLIENT
#undef OPTION_FRONT

option_specified_t option_specified = {
#define OPTION_CLIENT(scope, name, type, defval, min, max, short, long) \
    false,
#define OPTION_FRONT(scope, name, type, defval, min, max, short, long) \
    /*nothing*/
    /* we use <> so other tools can override the optionsx.h in "." */
#include <optionsx.h>
};
#undef OPTION_CLIENT
#undef OPTION_FRONT

/* If the user sets a value, we disable our dynamic adjustments */
bool stack_swap_threshold_fixed;

void
usage_error(const char *msg, const char *submsg)
{
    NOTIFY_ERROR("Usage error: %s%s.  Aborting."NL, msg, submsg);
    dr_abort();
}

static void
option_error(const char *whichop, const char *msg)
{
    NOTIFY_ERROR("Usage error on option \"%s\"%s%s: aborting"NL,
                 whichop, (msg[0] == '\0') ? "" : ": ", msg);
    NOTIFY_NO_PREFIX("Dr. Memory options (use -no_<op> to disable bool):"NL);
#define OPTION_CLIENT(scope, name, type, defval, min, max, short, long) \
    if (SCOPE_IS_PUBLIC_##scope) {                                      \
        if (TYPE_IS_BOOL_##type) { /* turn "(0)" into "false" */        \
            NOTIFY_NO_PREFIX("  -%-28s [%6s]  %s"NL, #name,             \
                             bool_string[(int)defval], short);          \
        } else if (TYPE_HAS_RANGE_##type)                               \
            NOTIFY_NO_PREFIX("  -%-28s [%6s]  %s"NL, #name" <int>", #defval, short); \
        else                                                            \
            NOTIFY_NO_PREFIX("  -%-28s [%6s]  %s"NL, #name" <string>", #defval, short); \
    }
#define OPTION_FRONT OPTION_CLIENT
    /* we use <> so other tools can override the optionsx.h in "." */
#include <optionsx.h>
#undef OPTION_CLIENT
#undef OPTION_FRONT
    /* FIXME: have an option that asks for all messages to messageboxes */
    dr_abort();
    ASSERT(false, "should not get here");
}

static inline const char *
option_read_uint(const char *s, char *word, void *var_in /* really uint* */,
                 const char *opname, uint minval, uint maxval)
{
    uint *var = (uint *) var_in;
    ASSERT(s != NULL && word != NULL && var != NULL && opname != NULL, "invalid param");
    s = get_option_word(s, word);
    if (s == NULL || word[0] == '\0')
        option_error(opname, "missing value");
    /* %u allows negative so we explicitly check */
    if (word[0] == '-')
        option_error(opname, "negative value not allowed");
    /* allow hex: must read it first, else 0 in 0x will be taken */
    if (sscanf(word, "0x%x", var) != 1 &&
        sscanf(word, "%u", var) != 1)
        option_error(opname, "invalid unsigned integer");
    if (*var < minval || *var > maxval)
        option_error(opname, "value is outside allowed range");
    return s;
}

static inline const char *
option_read_int(const char *s, char *word, void *var_in /* really int* */,
                const char *opname, int minval, int maxval)
{
    int *var = (int *) var_in;
    ASSERT(s != NULL && word != NULL && var != NULL && opname != NULL, "invalid param");
    s = get_option_word(s, word);
    if (s == NULL || word[0] == '\0')
        option_error(opname, "missing value");
    /* allow hex: must read it first, else 0 in 0x will be taken */
    if (sscanf(word, "0x%x", var) != 1 &&
        sscanf(word, "%d", var) != 1)
        option_error(opname, "invalid integer");
    if (*var < minval || *var > maxval)
        option_error(opname, "value is outside allowed range");
    return s;
}

static inline const char *
option_read_opstring_t(const char *s, char *word, void *var_in /* really opstring_t* */,
                       const char *opname, /*ignored: */int minval, int maxval)
{
    opstring_t *var = (opstring_t *) var_in;
    const char *pre_s = s;
    s = get_option_word(s, word);
    if (s == NULL)
        option_error(opname, "missing value");
    else if (*word == '-') {
        /* assume an empty value that wasn't double-quoted and so didn't
         * survive through shell and frontend to us
         */
        word = "";
        s = pre_s;
    }
    dr_snprintf(*var, BUFFER_SIZE_ELEMENTS(*var), "%s", word);
    NULL_TERMINATE_BUFFER(*var);
    return s;
}

static inline const char *
option_read_multi_opstring_t(const char *s, char *word,
                             void *var_in /* really multi_opstring_t* */,
                             const char *opname, /*ignored: */int minval, int maxval)
{
    multi_opstring_t *var = (multi_opstring_t *) var_in;
    char *c;
    s = get_option_word(s, word);
    if (s == NULL)
        option_error(opname, "missing value");
    for (c = *var;
         (c - *var < BUFFER_SIZE_ELEMENTS(*var) - 1) &&
             (*c != '\0' || *(c+1) != '\0');
         c++)
        ; /* nothing */
    dr_snprintf((c == *var) ? c : c + 1,
                BUFFER_SIZE_ELEMENTS(*var) - (c + 1 - *var), "%s", word);
    NULL_TERMINATE_BUFFER(*var);
    return s;
}

static inline const char *
option_read_bool(const char *s, char *word, void *var_in /* really bool* */,
                 const char *opname, int minval/*really bool*/, int maxval/*ignored*/)
{
    bool *var = (bool *) var_in;
    *var = (bool) minval;
    return s;
}

void
options_init(const char *opstr)
{
    const char *s;
    char word[MAX_OPTION_LEN];
#ifdef TOOL_DR_HEAPSTAT
    uint time_args = 0;
#endif
    for (s = get_option_word(opstr, word); s != NULL; s = get_option_word(s, word)) {

#define OPTION_CLIENT(scope, name, type, defval, min, max, short, long) \
        if (TYPE_IS_BOOL_##type) {                                      \
            if (stri_eq(word, "-"#name)) {                              \
                option_specified.name = true;                           \
                s = option_read_bool(s, NULL, (void *)&options.name,    \
                                     "-"#name, true, max);              \
                continue; /* match found */                             \
            } else if (stri_eq(word, "-no_"#name)) {                    \
                option_specified.name = true;                           \
                s = option_read_bool(s, NULL, (void *)&options.name,    \
                                     "-"#name, false, max);             \
                continue; /* match found */                             \
            }                                                           \
        } else if (stri_eq(word, "-"#name)) {                           \
            option_specified.name = true;                               \
            s = option_read_##type(s, word, (void *)&options.name,      \
                                   "-"#name, min, max);                 \
            continue; /* match found */                                 \
        }
#define OPTION_FRONT(scope, name, type, defval, min, max, short, long) \
    /*nothing*/
    /* we use <> so other tools can override the optionsx.h in "." */
#include <optionsx.h>
#undef OPTION_CLIENT
#undef OPTION_FRONT

       option_error(word, "unknown option");
    }

    if (!option_specified.logdir) {
        dr_snprintf(options.logdir, BUFFER_SIZE_ELEMENTS(options.logdir),
                    "%s", DEFAULT_LOGDIR);
        NULL_TERMINATE_BUFFER(options.logdir);
    }
#if defined(TOOL_DR_MEMORY) && defined(USE_DRSYMS)
    if (!option_specified.symcache_dir) {
        /* XXX: dynamically allocating option space would save some space;
         * could then just point at logdir: though we now put the "/symcache"
         * here instead of in symcache_init().
         */
        dr_snprintf(options.symcache_dir, BUFFER_SIZE_ELEMENTS(options.symcache_dir),
                    "%s/symcache", options.logdir);
        NULL_TERMINATE_BUFFER(options.symcache_dir);
    }
# ifdef WINDOWS
    /* i#723: Pre-load pdbs so that we can symbolize leak callstacks. */
    if (!option_specified.preload_symbols &&
        get_windows_version() == DR_WINDOWS_VERSION_VISTA) {
        options.preload_symbols = true;
    }
# endif /* WINDOWS */
#endif

    if (option_specified.stack_swap_threshold)
        stack_swap_threshold_fixed = true;

    /* Set dependent options after all processing in case overruled
     * by a later negative option.
     */
    if (options.leaks_only || options.perturb_only) {
        /* for performance use only DR's slots */
        options.num_spill_slots = 0;
        options.shadowing = false;
    }
    /* i#677: drmemory -leaks_only does not work with -no_esp_fastpath
     * XXX: there is nothing fundamentally impossible, it is just we didn't
     * bother to make it work as such combination is not very useful.
     */
    if (options.leaks_only && !options.esp_fastpath)
        usage_error("-leaks_only cannot be used with -no_esp_fastpath", "");
    if (options.perturb_only) {
        options.perturb = true;
        options.track_allocs = false;
        options.show_threads = false;
    }
    if (!options.track_allocs)
        options.track_heap = false;

#ifdef TOOL_DR_HEAPSTAT
    /* time_clock is default so don't require -no_time_clock */
    if (options.time_clock && option_specified.time_clock)
        time_args++;
    if (options.time_instrs) {
        options.time_clock = false;
        time_args++;
    }
    if (options.time_allocs) {
        options.time_clock = false;
        time_args++;
    }
    if (options.time_bytes) {
        options.time_clock = false;
        time_args++;
    }
    if (time_args > 1)
        usage_error("only one -time_* arg may be specified", "");

    if (option_specified.dump_freq) {
        if (options.dump_freq == 0)
            options.dump = false;
        else
            options.dump = true;
    }

    if ((options.snapshots & (~(options.snapshots-1))) != options.snapshots)
        usage_error("-snapshots must be power of 2", "");
#else
    if (options.light) {
        /* we can switch to pattern mode later */
        options.check_uninitialized = false;
        if (!option_specified.count_leaks)
            options.count_leaks = false;
    }
    if (options.pattern != 0) {
        /* we do not need shadow memory */
        options.shadowing = false;
        /* we need 1 spill slots for now */
        options.num_spill_slots = 1;
        /* the size is not stored in redzone */
        options.size_in_redzone = false;
        if (options.redzone_size == 0 ||
            !ALIGNED(options.redzone_size, sizeof(ptr_int_t))) {
            usage_error("redzone size must be pointer-size-aligned non-zero"
                        " in pattern mode", "");
        }
        /* we use two-byte pattern */
        options.pattern |= options.pattern << 16;
        /* no unknown syscalls analysis */
        options.analyze_unknown_syscalls = false;
        /* no uninitialized checks */
        options.check_uninitialized = false;
        /* no stack related checks */
        options.check_stack_bounds = false;
        options.check_stack_access = false;
        /* XXX: i#775, no unaligned reference check */
        options.check_alignment    = false;
        if (options.leaks_only)
            usage_error("-leaks_only cannot be used with pattern mode", "");
    }
    if (!options.count_leaks) {
        options.check_leaks_on_destroy = false;
    }
# ifdef USE_DRSYMS
    if (options.quiet) {
        /* quiet overrides both of these. */
        options.results_to_stderr = false;
        options.summary = false;
    }
# endif
    if (options.check_uninitialized) {
        if (options.check_stack_bounds)
            usage_error("-check_stack_bounds only valid w/ -no_check_uninitialized", "");
        if (options.check_stack_access)
            usage_error("-check_stack_access only valid w/ -no_check_uninitialized", "");
        if (options.check_alignment)
            usage_error("-check_alignment only valid w/ -no_check_uninitialized", "");
        /* but we do want these internally */
        options.check_stack_bounds = true;
        options.check_stack_access = true;
        options.check_alignment = true;
    }
    if (options.brief) {
        /* i#589: simpler error reports */
# ifdef USE_DRSYMS
        if (!option_specified.callstack_srcfile_hide) { /* overridable */
            /* Hide Visual Studio STL and CRT source file paths */
            dr_snprintf(options.callstack_srcfile_hide,
                        BUFFER_SIZE_ELEMENTS(options.callstack_srcfile_hide),
                        "*program files*visual studio*,*self_x86*");
            NULL_TERMINATE_BUFFER(options.callstack_srcfile_hide);
        }
        if (!option_specified.callstack_srcfile_prefix) { /* overridable */
            /* Truncate executable path prefix */
            extern char app_path[MAXIMUM_PATH];
            const char *sep = app_path + strlen(app_path);
            while (sep > app_path && *sep != '/' IF_WINDOWS(&& *sep != '\\'))
                sep--;
            ASSERT(sep - app_path <
                   BUFFER_SIZE_ELEMENTS(options.callstack_srcfile_prefix),
                   "impossible buffer diff");
            dr_snprintf(options.callstack_srcfile_prefix, sep - app_path,
                        "%s", app_path);
            NULL_TERMINATE_BUFFER(options.callstack_srcfile_prefix);
        }
# endif
        /* kind of a hack for now, making -brief "better reports", until
         * resolve perf issues w/ this option
         */
        if (!option_specified.delay_frees_stack)
            options.delay_frees_stack = true;
    }
#endif
}
