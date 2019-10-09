/* **********************************************************
 * Copyright (c) 2011-2019 Google, Inc.  All rights reserved.
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

#include "dr_api.h"
#include "drmgr.h"
#include "utils.h"
#include "options.h"
#include "shadow.h"
#include "pattern.h"
#include "drmemory.h"
#include <string.h>
#include <ctype.h> /* for isspace */

/* To use options.c in both the client and the frontend, we need
 * redefine a few utility macro and routines below for frontend:
 * - macros:
 *   ASSERT, NOTIFY_ERROR, NOTIFY_NO_PREFIX, stri_eq
 * - global variables:
 *   char app_path[MAXIMUM_PATH] (declared in frontend.c)
 * - routines:
 *   get_windows_version
 *
 * XXX: we should refactor options.c into a more cleanly separated module
 * that is not relying on global variables externally defined (app_path)
 * or global macros.
 */
#ifndef CLIENT_LIBNAME
# include <stdio.h> /* for stderr */
# undef ASSERT
# undef NOTIFY_ERROR
# undef NOTIFY_NO_PREFIX
# undef NOTIFY
# define NOTIFY_ERROR(...) do {   \
    fprintf(stderr, __VA_ARGS__); \
    fflush(stderr);               \
} while (0)
# define NOTIFY NOTIFY_ERROR
# define NOTIFY_NO_PREFIX NOTIFY_ERROR
# define ASSERT(x, msg) do {                      \
    if (!(x)) {                                   \
       NOTIFY_ERROR("ASSERT FAILURE: %s"NL, msg); \
       exit(1);                                   \
    }                                             \
} while (0)
# define stri_eq(s1, s2) (strcmp((s1), (s2)) == 0)

# ifdef WINDOWS
/* XXX: this is a temp solution for frontend using options.c.
 * We should use the function pointer as a parameter instead.
 */
static dr_os_version_t
get_windows_version(void)
{
    dr_os_version_info_t info;
    info.size = sizeof(info);
    if (dr_get_os_version(&info))
        return info.version;
    ASSERT(false, "fail to get windows version");
    /* assume latest just to make progress: good chance of working */
    return DR_WINDOWS_VERSION_7;
}
# endif /* WINDOWS */
#endif /* CLIENT_LIBNAME */

/***************************************************************************
 * OPTIONS
 */

/* not part of the default in optionsx.h b/c that's what front-end passes */
#ifdef UNIX
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
    TYPE_IS_BOOL_uint64     = false,
    TYPE_IS_BOOL_int        = false,
    TYPE_IS_STRING_bool       = false,
    TYPE_IS_STRING_opstring_t = true,
    TYPE_IS_STRING_multi_opstring_t = false,
    TYPE_IS_STRING_uint       = false,
    TYPE_IS_STRING_uint64     = false,
    TYPE_IS_STRING_int        = false,
    TYPE_HAS_RANGE_bool       = false,
    TYPE_HAS_RANGE_opstring_t = false,
    TYPE_HAS_RANGE_multi_opstring_t = false,
    TYPE_HAS_RANGE_uint       = true,
    TYPE_HAS_RANGE_uint64     = true,
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

drmemory_options_t option_defaults = {
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

const char *
get_option_word(const char *s, char buf[MAX_OPTION_LEN])
{
    int i = 0;
    bool quoted = false;
    char endquote = '\0';
    while (*s != '\0' && isspace(*s))
        s++;
    if (*s == '\"' || *s == '\'' || *s == '`') {
        quoted = true;
        endquote = *s;
        s++;
    }
    while (*s != '\0' && ((!quoted && !isspace(*s)) || (quoted && *s != endquote)) &&
           i < MAX_OPTION_LEN-1)
        buf[i++] = *s++;
    if (quoted && *s == endquote)
        s++;
    buf[i] = '\0';
    if (i == 0 && *s == '\0')
        return NULL;
    else
        return s;
}

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
    NOTIFY_NO_PREFIX("Run with -help for full option list."NL);
    /* FIXME: have an option that asks for all messages to messageboxes */
    dr_abort();
    ASSERT(false, "should not get here");
}

static inline const char *
option_read_uint64(const char *s, char *word, void *var_in /* really uint64* */,
                   const char *opname, uint64 minval, uint64 maxval)
{
    uint64 *var = (uint64 *) var_in;
    ASSERT(s != NULL && word != NULL && var != NULL && opname != NULL, "invalid param");
    s = get_option_word(s, word);
    if (s == NULL || word[0] == '\0')
        option_error(opname, "missing value");
    /* %u allows negative so we explicitly check */
    if (word[0] == '-')
        option_error(opname, "negative value not allowed");
    /* allow hex: must read it first, else 0 in 0x will be taken */
    if (dr_sscanf(word, "0x" HEX64_FORMAT_STRING, var) != 1 &&
        dr_sscanf(word, UINT64_FORMAT_STRING, var) != 1)
        option_error(opname, "invalid unsigned 64-bit integer");
    if (*var < minval || *var > maxval)
        option_error(opname, "value is outside allowed range");
    return s;
}

static inline const char *
option_read_uint(const char *s, char *word, void *var_in /* really uint* */,
                 const char *opname, uint minval, uint64 maxval)
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
    if (dr_sscanf(word, "0x%x", var) != 1 &&
        dr_sscanf(word, "%u", var) != 1)
        option_error(opname, "invalid unsigned integer");
    if (*var < minval || *var > maxval)
        option_error(opname, "value is outside allowed range");
    return s;
}

static inline const char *
option_read_int(const char *s, char *word, void *var_in /* really int* */,
                const char *opname, int minval, int64 maxval)
{
    int *var = (int *) var_in;
    ASSERT(s != NULL && word != NULL && var != NULL && opname != NULL, "invalid param");
    s = get_option_word(s, word);
    if (s == NULL || word[0] == '\0')
        option_error(opname, "missing value");
    /* allow hex: must read it first, else 0 in 0x will be taken */
    if (dr_sscanf(word, "0x%x", var) != 1 &&
        dr_sscanf(word, "%d", var) != 1)
        option_error(opname, "invalid integer");
    if (*var < minval || *var > maxval)
        option_error(opname, "value is outside allowed range");
    return s;
}

static inline const char *
option_read_opstring_t(const char *s, char *word, void *var_in /* really opstring_t* */,
                       const char *opname, /*ignored: */int minval, uint64 maxval)
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
                             const char *opname, /*ignored: */int minval, uint64 maxval)
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
                 const char *opname, int minval/*really bool*/, uint64 maxval/*ignored*/)
{
    bool *var = (bool *) var_in;
    *var = (bool) minval;
    return s;
}

static inline void
option_disable_memory_checks()
{
    /* for performance use only DR's slots */
    options.num_spill_slots = 0;
    options.shadowing = false;
    options.check_uninitialized = false;
    options.pattern = 0;
}

void
options_reset_to_defaults(void)
{
    memcpy(&options, &option_defaults, sizeof(options));
    memset(&option_specified, 0, sizeof(option_specified));
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
                                     "-"#name, true, 0);                \
                continue; /* match found */                             \
            } else if (stri_eq(word, "-no_"#name)) {                    \
                option_specified.name = true;                           \
                s = option_read_bool(s, NULL, (void *)&options.name,    \
                                     "-"#name, false, 0);               \
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
         * Update: we now always set this in the front-end on Windows.
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

#ifndef TOOL_DR_HEAPSTAT
    /* Set dependent options after all processing in case overruled
     * by a later negative option.
     */
    if (options.native_parent) {
        /* no reason to do any extra work */
        options.leaks_only = true;
        options.count_leaks = false;
        options.track_allocs = false;
        /* Avoid conflicts below.  We want to support the user passing this
         * as the child processes will use the original options.
         */
        options.light = false;
        options.pattern = 0;
    }
#endif
    if (options.leaks_only || options.perturb_only) {
        option_disable_memory_checks();
#ifdef WINDOWS
        /* i#1457-c#3: -perturb_only skips callstack ops init, so we must disable
         * check_gdi and check_handle_leaks
         */
        if (option_specified.check_gdi) {
            if (options.perturb_only && options.check_gdi)
                usage_error("-perturb_only cannot be used with -check_gdi", "");
        } else
            options.check_gdi = false;
        if (option_specified.check_handle_leaks) {
            if (options.check_handle_leaks && options.perturb_only)
                usage_error("-perturb_only cannot be used with -check_handle_leaks", "");
        } else
            options.check_handle_leaks = false;
#endif /* WINDOWS */
    }
#ifdef WINDOWS
    if (options.handle_leaks_only) {
        option_disable_memory_checks();
        /* disable memory alloc tracking */
        options.track_allocs = false;
        /* disable leak scan */
        options.leaks_only = false;
# ifndef TOOL_DR_HEAPSTAT
        options.count_leaks = false;
# endif
        options.check_handle_leaks = true;
        if (!option_specified.check_gdi)
            options.check_gdi = false;
    }
#endif
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
        options.check_uninitialized = false;
        if (!option_specified.count_leaks && !option_specified.check_leaks)
            options.count_leaks = false;
        if (!option_specified.pattern)
            options.pattern = DEFAULT_PATTERN;
# ifdef WINDOWS
        if (!option_specified.check_handle_leaks)
            options.check_handle_leaks = false;
# endif
    }
    if (options.unaddr_only) {
        if (!option_specified.pattern)
            options.pattern = DEFAULT_PATTERN;
        if (!option_specified.count_leaks)
            options.count_leaks = false;
        if (!option_specified.check_delete_mismatch)
            options.check_delete_mismatch = false;
# ifdef WINDOWS
        if (!option_specified.check_handle_leaks)
            options.check_handle_leaks = false;
        if (!option_specified.check_gdi)
            options.check_gdi = false;
# endif
    }
    if (options.pattern != 0) {
        /* we do not need shadow memory */
        options.shadowing = false;
        /* the size is not stored in redzone */
        options.size_in_redzone = false;
        if (options.redzone_size == 0 ||
            !ALIGNED(options.redzone_size, sizeof(ptr_int_t))) {
            usage_error("redzone size must be pointer-size-aligned non-zero"
                        " in pattern mode", "");
        }
        /* we use a two-byte pattern */
        if ((options.pattern & 0xffff0000) != 0)
            usage_error("pattern must be a 2-byte value", "");
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
# ifdef WINDOWS
        if (options.handle_leaks_only)
            usage_error("-handle_leaks_only cannot be used with pattern mode", "");
# endif
    } else {
        if (!ALIGNED(options.redzone_size, IF_X64_ELSE(16,8)))
            usage_error("redzone size must be " IF_X64_ELSE("16","8") "-aligned", "");
    }
    if (option_specified.fuzz ||
        option_specified.fuzz_module ||
        option_specified.fuzz_function ||
        option_specified.fuzz_offset ||
        option_specified.fuzz_num_args ||
        option_specified.fuzz_data_idx ||
        option_specified.fuzz_size_idx ||
        option_specified.fuzz_num_iters ||
        option_specified.fuzz_replace_buffer ||
        option_specified.fuzz_call_convention ||
        option_specified.fuzz_dump_on_error ||
        option_specified.fuzz_input_file ||
        option_specified.fuzz_corpus ||
        option_specified.fuzz_corpus_out ||
        option_specified.fuzz_coverage ||
        option_specified.fuzz_target ||
        option_specified.fuzz_mutator_lib ||
        option_specified.fuzz_mutator_ops ||
        option_specified.fuzz_mutator_alg ||
        option_specified.fuzz_mutator_unit ||
        option_specified.fuzz_mutator_flags ||
        option_specified.fuzz_mutator_sparsity ||
        option_specified.fuzz_mutator_max_value ||
        option_specified.fuzz_mutator_random_seed ||
        option_specified.fuzz_dictionary ||
        option_specified.fuzz_one_input ||
        option_specified.fuzz_buffer_fixed_size ||
        option_specified.fuzz_buffer_offset ||
        option_specified.fuzz_skip_initial ||
        IF_WINDOWS(option_specified.fuzz_mangled_names ||)
        option_specified.fuzz_stat_freq) {
        options.fuzz = true;
        /* enable replace_buffer by default if fuzzing with input files */
        if ((option_specified.fuzz_corpus || option_specified.fuzz_input_file) &&
            !option_specified.fuzz_replace_buffer)
            options.fuzz_replace_buffer = true;
        if (options.fuzz_replace_buffer && !options.replace_malloc) {
            usage_error("-fuzz_replace_buffer cannot be used with -no_replace_malloc",
                        "");
        }
        if (option_specified.fuzz_dictionary && option_specified.fuzz_mutator_unit &&
            strcmp(options.fuzz_mutator_unit, "token") != 0)
            usage_error("-fuzz_dictionary requires -fuzz_mutator_unit token", "");
        if (option_specified.fuzz_corpus_out && !option_specified.fuzz_corpus)
            usage_error("-fuzz_corpus_out requires -fuzz_corpus", "");
    }

    if (options.replace_malloc) {
        options.replace_realloc = false; /* no need for it */
        /* whole header is in redzone, but supports redzone being smaller than header */
        options.size_in_redzone = false;
        if (options.pattern == 0) {
            /* for non-pattern we share redzones, so *2 to get equiv on each side */
            options.redzone_size *= 2;
        }
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
# ifdef WINDOWS
    if (options.visual_studio) {
        /* Allow earlier options to override by checking all for whether specified.
         * Later can override individual components of this option as well.
         * XXX: have a -callstack_style_append that adds via OR for adding
         * stuff after -visual_studio?
         */
        if (!option_specified.callstack_style)
            options.callstack_style = PRINT_FOR_VSTUDIO;
        if (!option_specified.prefix_style)
            options.prefix_style = PREFIX_STYLE_BLANK;
        if (!option_specified.batch)
            options.batch = true; /* frontend has to also set this of course */
        /* The reasoning for -brief is that nobody's going to do perf measurements
         * inside VS so we may as well have -delay_frees_stack, etc.
         */
        if (!option_specified.brief)
            options.brief = true;
    }
# endif
    if (options.brief) {
        /* i#589: simpler error reports */
# ifdef USE_DRSYMS
        if (!option_specified.callstack_srcfile_hide) { /* overridable */
            /* Hide Visual Studio STL and CRT source file paths.
             * But, don't hide VS6 default project dir on win2k:
             * C:\Program Files\Microsoft Visual Studio\MyProjects
             */
            dr_snprintf(options.callstack_srcfile_hide,
                        BUFFER_SIZE_ELEMENTS(options.callstack_srcfile_hide),
                        "*program files*visual studio*vc*,*self_x86*");
            NULL_TERMINATE_BUFFER(options.callstack_srcfile_hide);
        }
        if (!option_specified.callstack_srcfile_prefix) { /* overridable */
            /* Truncate executable path prefix */
            extern char app_path[MAXIMUM_PATH];
            const char *sep = app_path + strlen(app_path);
            while (sep > app_path && *sep != DIRSEP IF_WINDOWS(&& *sep != ALT_DIRSEP))
                sep--;
            ASSERT(sep - app_path <
                   BUFFER_SIZE_ELEMENTS(options.callstack_srcfile_prefix),
                   "impossible buffer diff");
            dr_snprintf(options.callstack_srcfile_prefix, sep - app_path,
                        "%s", app_path);
            NULL_TERMINATE_BUFFER(options.callstack_srcfile_prefix);
        }
# endif
        /* Kind of a hack for now, making -brief "better reports", until
         * resolve perf issues w/ this option (i#205).  Those are now resolved:
         * but I'm leaving this so we don't lose it if we reverse the
         * default for -delay_frees_stack in the future.
         */
        if (!option_specified.delay_frees_stack)
            options.delay_frees_stack = true;
        /* another one of these perf vs accuracy tradeoffs (i#703) */
        if (!option_specified.callstack_use_top_fp && !HAVE_STALE_RETADDRS())
            options.callstack_use_top_fp = false;
    }
    if (!options.callstack_use_fp)
        options.callstack_use_top_fp = false;
    if (options.persist_code && !persistence_supported())
        usage_error("currently -persist_code only supports -light or "
                    "-no_check_uninitialized", "");
    /* N.B.: avoid any NOTIFY messages here as they will not honor -quiet: place them
     * in dr_init() underneath the version printout.
     */
#endif /* TOOL_DR_MEMORY */
    if (options.native_until_thread > 0 || options.native_parent) {
        go_native = true;
    }
}

void
options_print_usage()
{
    NOTIFY_NO_PREFIX("Dr. Memory options (use -no_<op> to disable bool):"NL);
#define OPTION_CLIENT(scope, name, type, defval, min, max, short, long) \
    if (SCOPE_IS_PUBLIC_##scope) {                                      \
        if (TYPE_IS_BOOL_##type) { /* turn "(0)" into "false" */        \
            type _tmp = defval; /* work around cl bogus integer overflow if in [] */ \
            NOTIFY_NO_PREFIX("  -%-28s [%6s]  %s"NL, #name,             \
                             bool_string[(ptr_int_t)_tmp], short);      \
            ASSERT((ptr_int_t)defval == 0 || (ptr_int_t)defval == 1,    \
                   "defval must be true/false");                        \
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
}
