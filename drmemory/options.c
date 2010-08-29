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

#include "dr_api.h"
#include "per_thread.h"
#include "utils.h"
#include "options.h"

/***************************************************************************
 * OPTIONS
 */

#define MAX_OPTION_LEN MAXIMUM_PATH

#ifdef LINUX
# define DEFAULT_LOGDIR "/tmp"
#else
# define DEFAULT_LOGDIR "c:"
#endif

drmemory_options_t options = {
    {'\0'},    /* logdir */
    false,     /* resfile_out */
    1,         /* verbose */
    true,      /* stderr */
    false,     /* pause_at_assert */
    false,     /* pause_via_loop */
    false,     /* ignore_asserts */
    0x9000,    /* stack_swap_threshold: better too small than too big */
#ifdef TOOL_DR_MEMORY
    20,        /* callstack_max_frames */
#else
    150,       /* callstack_max_frames: we need a big default so we
                * can get all the way to the bottom and have a nice
                * tree of callstacks.  I've seen 65 frames on hostd.
                * update: later seeing >100 due to recursive calls.
                * our stacks are dynamically sized so a large max
                * doesn't waste memory.
                */
#endif
    false,     /* leaks_only */
    true,      /* shadowing */
    true,      /* track_allocs */
    true,      /* check_leaks */
    true,      /* ignore_early_leaks */
    true,      /* possible_leaks */
    true,      /* check_leaks_on_destroy */
    true,      /* midchunk_size_ok */
    true,      /* midchunk_new_ok */
    true,      /* midchunk_inheritance_ok */
    true,      /* midchunk_string_ok */
    false,     /* show_reachable */
    false,     /* perturb */
    false,     /* perturb_only */
    50,        /* perturb_max */
    0,         /* perturb_seed */

    /* drmem-specific but drheapstat needs to share same code */
    true,      /* check_invalid_frees */
    true,      /* count_leaks */
    false,     /* warn_null_ptr */
    true,      /* track_heap */
    8,         /* redzone_size
                * Best to be multiple of 8 to match malloc alignment on both
                * Linux and Windows.  In fact, setting this to 4 causes
                * gui apps like notepad.exe to exit early.
                */
    true,      /* size_in_redzone */
    false,     /* check_non_moves */
    true,      /* check_cmps */
    false,     /* pause_at_unaddressable */
    false,     /* pause_at_uninitialized */
    true,      /* fastpath */
    true,      /* esp_fastpath */
    true,      /* shared_slowpath */
    true,      /* loads_use_table */
    true,      /* stores_use_table */
    5,         /* num_spill_slots */
    true,      /* check_ignore_unaddr, using dynamic checks from PR 578892 */
    false,     /* thread_logs */
    IF_DRSYMS_ELSE(true, false), /* summary */
    false,     /* statistics */
    500000,    /* stats_dump_interval */
    20000,     /* report_max */
    10000,     /* report_leak_max */
    {'\0'},    /* suppress_file */
    true,      /* use_default_suppress */
    2000,      /* delay_frees */
    true,      /* define_unknown_regions */
    true,      /* replace_libc */
    {'\0'},    /* libc_addrs */
    true,      /* check_push */
    false,     /* single_arg_slowpath */
    {'\0'},    /* prctl_whitelist */
    true,      /* repstr_to_loop */

#ifdef TOOL_DR_HEAPSTAT
    false,     /* time_instrs */
    false,     /* time_allocs */
    false,     /* time_bytes */
    true,      /* time_clock */

    false,     /* dump */
    1,         /* dump_freq */
    64,        /* snapshots: must be power of 2 */
    5,         /* peak_threshold */

    true,      /* staleness */
    1000,      /* stale_granularity */
    false,     /* stale_blind_store */
    true,      /* stale_ignore_sp */
#endif /* TOOL_DR_HEAPSTAT */
};

/* If the user sets a value, we disable our dynamic adjustments */
bool stack_swap_threshold_fixed;

void
usage_error(const char *msg, const char *submsg)
{
    NOTIFY_ERROR("Usage error: %s%s.  Aborting."NL, msg, submsg);
    dr_abort();
}

static void
option_error(const char *whichop)
{
    NOTIFY_ERROR("Usage error on option \"%s\": aborting\n", whichop);
    NOTIFY_NO_PREFIX("Dr. Memory options:\n");
#define OPTION(nm, def, short, long) \
    NOTIFY_NO_PREFIX("  %-30s [%8s]  %s\n", nm, def, short);
#include "optionsx.h"
#undef OPTION
    /* FIXME: have an option that asks for all messages to messageboxes */
    dr_abort();
}

void
options_init(const char *opstr)
{
    const char *s;
    char word[MAX_OPTION_LEN];
#ifdef TOOL_DR_HEAPSTAT
    uint time_args = 0;
#endif
    /* FIXME PR 487993: use optionsx.h to construct option parsing */
    for (s = get_option_word(opstr, word); s != NULL; s = get_option_word(s, word)) {
        if (stri_eq(word, "-verbose")) {
            s = get_option_word(s, word);
            if (s == NULL || sscanf(word, "%d", &options.verbose) <= 0)
                option_error("-verbose");
        } else if (stri_eq(word, "-resfile_out")) {
            options.resfile_out = true;
        } else if (stri_eq(word, "-report_max")) {
            s = get_option_word(s, word);
            if (s == NULL || sscanf(word, "%d", &options.report_max) <= 0)
                option_error("-report_max");
        } else if (stri_eq(word, "-report_leak_max")) {
            s = get_option_word(s, word);
            if (s == NULL || sscanf(word, "%d", &options.report_leak_max) == -1)
                option_error("-report_leak_max");
        } else if (stri_eq(word, "-suppress")) {
            s = get_option_word(s, word);
            if (s == NULL)
                option_error("-suppress");
            dr_snprintf(options.suppress_file, BUFFER_SIZE_ELEMENTS(options.suppress_file),
                        "%s", word);
            NULL_TERMINATE_BUFFER(options.suppress_file);
        } else if (stri_eq(word, "-logdir")) {
            s = get_option_word(s, word);
            if (s == NULL)
                option_error("-logdir");
            dr_snprintf(options.logdir, BUFFER_SIZE_ELEMENTS(options.logdir), "%s", word);
            NULL_TERMINATE_BUFFER(options.logdir);
        } else if (stri_eq(word, "-libc_addrs")) {
            s = get_option_word(s, word);
            if (s == NULL)
                option_error("-libc_addrs");
            dr_snprintf(options.libc_addrs, BUFFER_SIZE_ELEMENTS(options.libc_addrs),
                        "%s", word);
            NULL_TERMINATE_BUFFER(options.libc_addrs);
        } else if (stri_eq(word, "-callstack_max_frames")) {
            s = get_option_word(s, word);
            if (s == NULL || sscanf(word, "%d", &options.callstack_max_frames) <= 0)
                option_error("-callstack_max_frames");
        } else if (stri_eq(word, "-stack_swap_threshold")) {
            s = get_option_word(s, word);
            if (s == NULL ||
                ((sscanf(word, ""PIFX"", &options.stack_swap_threshold) <= 0 ) &&
                 (sscanf(word, "%d", &options.stack_swap_threshold) <= 0)))
                option_error("-stack_swap_threshold");
            stack_swap_threshold_fixed = true;
        } else if (stri_eq(word, "-redzone_size")) {
            s = get_option_word(s, word);
            if (s == NULL || sscanf(word, "%d", &options.redzone_size) <= 0)
                option_error("-redzone_size");
        } else if (stri_eq(word, "-stats_dump_interval")) {
            s = get_option_word(s, word);
            if (s == NULL || sscanf(word, "%d", &options.stats_dump_interval) <= 0)
                option_error("-stats_dump_interval");
        } else if (stri_eq(word, "-size_in_redzone")) {
            options.size_in_redzone = true;
        } else if (stri_eq(word, "-no_size_in_redzone")) {
            options.size_in_redzone = false;
        } else if (stri_eq(word, "-quiet")) {
            options.stderr = false;
        } else if (stri_eq(word, "-no_quiet")) {
            options.stderr = true;
        } else if (stri_eq(word, "-summary")) {
            options.summary = true;
        } else if (stri_eq(word, "-no_summary")) {
            options.summary = false;
        } else if (stri_eq(word, "-thread_logs")) {
            options.thread_logs = true;
        } else if (stri_eq(word, "-no_thread_logs")) {
            options.thread_logs = false;
        } else if (stri_eq(word, "-check_invalid_frees")) {
            options.check_invalid_frees = true;
        } else if (stri_eq(word, "-no_check_invalid_frees")) {
            options.check_invalid_frees = false;
        } else if (stri_eq(word, "-count_leaks")) {
            options.count_leaks = true;
        } else if (stri_eq(word, "-no_count_leaks")) {
            options.count_leaks = false;
        } else if (stri_eq(word, "-check_leaks")) {
            options.check_leaks = true;
        } else if (stri_eq(word, "-no_check_leaks")) {
            options.check_leaks = false;
        } else if (stri_eq(word, "-track_heap")) {
            options.track_heap = true;
        } else if (stri_eq(word, "-no_track_heap")) {
            options.track_heap = false;
        } else if (stri_eq(word, "-check_cmps")) {
            options.check_cmps = true;
        } else if (stri_eq(word, "-no_check_cmps")) {
            options.check_cmps = false;
        } else if (stri_eq(word, "-check_non_moves")) {
            options.check_non_moves = true;
        } else if (stri_eq(word, "-no_check_non_moves")) {
            options.check_non_moves = false;
        } else if (stri_eq(word, "-ignore_early_leaks")) {
            options.ignore_early_leaks = true;
        } else if (stri_eq(word, "-no_ignore_early_leaks")) {
            options.ignore_early_leaks = false;
        } else if (stri_eq(word, "-possible_leaks")) {
            options.possible_leaks = true;
        } else if (stri_eq(word, "-no_possible_leaks")) {
            options.possible_leaks = false;
        } else if (stri_eq(word, "-check_leaks_on_destroy")) {
            options.check_leaks_on_destroy = true;
        } else if (stri_eq(word, "-no_check_leaks_on_destroy")) {
            options.check_leaks_on_destroy = false;
        } else if (stri_eq(word, "-midchunk_size_ok")) {
            options.midchunk_size_ok = true;
        } else if (stri_eq(word, "-no_midchunk_size_ok")) {
            options.midchunk_size_ok = false;
        } else if (stri_eq(word, "-midchunk_new_ok")) {
            options.midchunk_new_ok = true;
        } else if (stri_eq(word, "-no_midchunk_new_ok")) {
            options.midchunk_new_ok = false;
        } else if (stri_eq(word, "-midchunk_inheritance_ok")) {
            options.midchunk_inheritance_ok = true;
        } else if (stri_eq(word, "-no_midchunk_inheritance_ok")) {
            options.midchunk_inheritance_ok = false;
        } else if (stri_eq(word, "-midchunk_string_ok")) {
            options.midchunk_string_ok = true;
        } else if (stri_eq(word, "-no_midchunk_string_ok")) {
            options.midchunk_string_ok = false;
        } else if (stri_eq(word, "-show_reachable")) {
            options.show_reachable = true;
        } else if (stri_eq(word, "-no_show_reachable")) {
            options.show_reachable = false;
        } else if (stri_eq(word, "-warn_null_ptr")) {
            options.warn_null_ptr = true;
        } else if (stri_eq(word, "-no_warn_null_ptr")) {
            options.warn_null_ptr = false;
        } else if (stri_eq(word, "-fastpath")) {
            options.fastpath = true;
        } else if (stri_eq(word, "-no_fastpath")) {
            options.fastpath = false;
        } else if (stri_eq(word, "-esp_fastpath")) {
            options.esp_fastpath = true;
        } else if (stri_eq(word, "-no_esp_fastpath")) {
            options.esp_fastpath = false;
        } else if (stri_eq(word, "-shared_slowpath")) {
            options.shared_slowpath = true;
        } else if (stri_eq(word, "-no_shared_slowpath")) {
            options.shared_slowpath = false;
        } else if (stri_eq(word, "-loads_use_table")) {
            options.loads_use_table = true;
        } else if (stri_eq(word, "-no_loads_use_table")) {
            options.loads_use_table = false;
        } else if (stri_eq(word, "-stores_use_table")) {
            options.stores_use_table = true;
        } else if (stri_eq(word, "-no_stores_use_table")) {
            options.stores_use_table = false;
        } else if (stri_eq(word, "-num_spill_slots")) {
            s = get_option_word(s, word);
            if (s == NULL || sscanf(word, "%d", &options.num_spill_slots) <= 0)
                option_error("-num_spill_slots");
        } else if (stri_eq(word, "-statistics")) {
            options.statistics = true;
        } else if (stri_eq(word, "-no_statistics")) {
            options.statistics = false;
        } else if (stri_eq(word, "-check_ignore_unaddr")) {
            options.check_ignore_unaddr = true;
        } else if (stri_eq(word, "-no_check_ignore_unaddr")) {
            options.check_ignore_unaddr = false;
        } else if (stri_eq(word, "-pause_at_unaddressable")) {
            options.pause_at_unaddressable = true;
        } else if (stri_eq(word, "-pause_at_uninitialized")) {
            options.pause_at_uninitialized = true;
        } else if (stri_eq(word, "-pause_at_assert")) {
            options.pause_at_assert = true;
        } else if (stri_eq(word, "-pause_via_loop")) {
            options.pause_via_loop = true;
        } else if (stri_eq(word, "-ignore_asserts")) {
            options.ignore_asserts = true;
        } else if (stri_eq(word, "-delay_frees")) {
            s = get_option_word(s, word);
            if (s == NULL || sscanf(word, "%d", &options.delay_frees) <= 0)
                option_error("-delay_frees");
        } else if (stri_eq(word, "-define_unknown_regions")) {
            options.define_unknown_regions = true;
        } else if (stri_eq(word, "-no_define_unknown_regions")) {
            options.define_unknown_regions = false;
        } else if (stri_eq(word, "-replace_libc")) {
            options.replace_libc = true;
        } else if (stri_eq(word, "-no_replace_libc")) {
            options.replace_libc = false;
        } else if (stri_eq(word, "-default_suppress")) {
            options.use_default_suppress = true;
        } else if (stri_eq(word, "-no_default_suppress")) {
            options.use_default_suppress = false;
        } else if (stri_eq(word, "-leaks_only")) {
            options.leaks_only = true;
        } else if (stri_eq(word, "-no_leaks_only")) {
            options.leaks_only = false;
        } else if (stri_eq(word, "-shadowing")) {
            options.shadowing = true;
        } else if (stri_eq(word, "-no_shadowing")) {
            options.shadowing = false;
        } else if (stri_eq(word, "-track_allocs")) {
            options.track_allocs = true;
        } else if (stri_eq(word, "-no_track_allocs")) {
            options.track_allocs = false;
#ifdef TOOL_DR_MEMORY
        /* not supporting perturb with heapstat: can add easily later */
        /* XXX: some of the other options here shouldn't be allowed for heapstat either */
        } else if (stri_eq(word, "-perturb")) {
            options.perturb = true;
        } else if (stri_eq(word, "-no_perturb")) {
            options.perturb = false;
        } else if (stri_eq(word, "-perturb_only")) {
            options.perturb_only = true;
        } else if (stri_eq(word, "-no_perturb_only")) {
            options.perturb_only = false;
        } else if (stri_eq(word, "-perturb_max")) {
            s = get_option_word(s, word);
            if (s == NULL || sscanf(word, "%d", &options.perturb_max) <= 0)
                option_error("-perturb_max");
        } else if (stri_eq(word, "-perturb_seed")) {
            s = get_option_word(s, word);
            if (s == NULL || sscanf(word, "%d", &options.perturb_seed) <= 0)
                option_error("-perturb_seed");
#endif
        } else if (stri_eq(word, "-check_push")) {
            options.check_push = true;
        } else if (stri_eq(word, "-no_check_push")) {
            options.check_push = false;
        } else if (stri_eq(word, "-single_arg_slowpath")) {
            options.single_arg_slowpath = true;
        } else if (stri_eq(word, "-no_single_arg_slowpath")) {
            options.single_arg_slowpath = false;
        } else if (stri_eq(word, "-repstr_to_loop")) {
            options.repstr_to_loop = true;
        } else if (stri_eq(word, "-no_repstr_to_loop")) {
            options.repstr_to_loop = false;
        } else if (stri_eq(word, "-prctl_whitelist")) {
            s = get_option_word(s, word);
            if (s == NULL)
                option_error("-prctl_whitelist");
            dr_snprintf(options.prctl_whitelist,
                        BUFFER_SIZE_ELEMENTS(options.prctl_whitelist),
                        "%s", word);
            NULL_TERMINATE_BUFFER(options.prctl_whitelist);
#ifdef TOOL_DR_HEAPSTAT
        } else if (stri_eq(word, "-time_instrs")) {
            options.time_instrs = true;
            options.time_allocs = false;
            options.time_bytes  = false;
            options.time_clock  = false;
            time_args++;
        } else if (stri_eq(word, "-time_allocs")) {
            options.time_instrs = false;
            options.time_allocs = true;
            options.time_bytes  = false;
            options.time_clock  = false;
            time_args++;
        } else if (stri_eq(word, "-time_bytes")) {
            options.time_instrs = false;
            options.time_allocs = false;
            options.time_bytes  = true;
            options.time_clock  = false;
            time_args++;
        } else if (stri_eq(word, "-time_clock")) {
            options.time_instrs = false;
            options.time_allocs = false;
            options.time_bytes  = false;
            options.time_clock  = true;
            time_args++;
        } else if (stri_eq(word, "-dump")) {
            options.dump = true;
        } else if (stri_eq(word, "-no_dump")) {
            options.dump = false;
        } else if (stri_eq(word, "-dump_freq")) {
            s = get_option_word(s, word);
            if (s == NULL || sscanf(word, "%d", &options.dump_freq) == -1)
                usage_error("-dump_freq", "");
            if (options.dump_freq == 0)
                options.dump = false;
            else
                options.dump = true;
        } else if (stri_eq(word, "-snapshots")) {
            s = get_option_word(s, word);
            if (s == NULL || sscanf(word, "%d", &options.snapshots) == -1)
                usage_error("-snapshots", "");
            if ((options.snapshots & (~(options.snapshots-1))) != options.snapshots)
                usage_error("-snapshots must be power of 2", "");
        } else if (stri_eq(word, "-peak_threshold")) {
            s = get_option_word(s, word);
            if (s == NULL || sscanf(word, "%d", &options.peak_threshold) == -1)
                usage_error("-peak_threshold", "");
        } else if (stri_eq(word, "-staleness")) {
            options.staleness = true;
        } else if (stri_eq(word, "-no_staleness")) {
            options.staleness = false;
        } else if (stri_eq(word, "-stale_granularity")) {
            s = get_option_word(s, word);
            if (s == NULL || sscanf(word, "%d", &options.stale_granularity) == -1)
                usage_error("-stale_granularity", "");
            if (options.stale_granularity <= 0)
                usage_error("-stale_granularity must be > 0", "");
        } else if (stri_eq(word, "-stale_blind_store")) {
            options.stale_blind_store = true;
        } else if (stri_eq(word, "-no_stale_blind_store")) {
            options.stale_blind_store = false;
        } else if (stri_eq(word, "-stale_ignore_sp")) {
            options.stale_ignore_sp = true;
        } else if (stri_eq(word, "-no_stale_ignore_sp")) {
            options.stale_ignore_sp = false;
#endif
        } else
            option_error(word);
    }

    if (options.logdir[0] == '\0') {
        dr_snprintf(options.logdir, BUFFER_SIZE_ELEMENTS(options.logdir),
                    "%s", DEFAULT_LOGDIR);
        NULL_TERMINATE_BUFFER(options.logdir);
    }
#ifdef TOOL_DR_HEAPSTAT
    if (time_args > 1)
        usage_error("only one -time_* arg may be specified", "");
#endif

    /* Set dependent options after all processing in case overruled
     * by a later negative option.
     */
    if (options.leaks_only || options.perturb_only) {
        /* for performance use only DR's slots */
        options.num_spill_slots = 0;
        /* we now disable shadowing for leaks_only so we could clean up
         * all the existing checks for both to only check shadowing
         */
        options.shadowing = false;
    }
    if (options.perturb_only) {
        options.perturb = true;
        options.track_allocs = false;
    }
    if (!options.track_allocs)
        options.track_heap = false;
}

