/* **********************************************************
 * Copyright (c) 2010-2017 Google, Inc.  All rights reserved.
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

/***************************************************************************
 * Dr. Heapstat heap profiler
 */

#include "dr_api.h"
#include "drwrap.h"
#include "drsyscall.h"
#include "drsymcache.h"
#include "umbra.h"
#include "drheapstat.h"
#include "alloc.h"
#include "heap.h"
#include "callstack.h"
#include "crypto.h"
#include "staleness.h"
#include "../drmemory/leak.h"
#include "../drmemory/stack.h"
#include "../drmemory/shadow.h"
#include "../drmemory/instru.h"
#include "../drmemory/slowpath.h"
#ifdef MACOS
# error NYI i#1438
#elif defined(LINUX)
# include "sysnum_linux.h"
# include <errno.h>
# define _GNU_SOURCE /* for sched.h */
# include <linux/sched.h>  /* for CLONE_VM */
# include <sys/time.h>
# include <signal.h> /* for SIGSEGV */
#endif
#include <stddef.h> /* for offsetof */

#ifdef USE_MD5
# define IF_MD5_ELSE(x, y) x
#else
# define IF_MD5_ELSE(x, y) y
#endif

/* for sharing data among instrumentation passes */
typedef struct _instru_info_t {
    bb_info_t bi;
    instr_t *where_dead;
    bool flags_dead;
    uint instrs_in_bb;
} instru_info_t;

char logsubdir[MAXIMUM_PATH];
file_t f_callstack = INVALID_FILE;
file_t f_snapshot = INVALID_FILE;
file_t f_staleness = INVALID_FILE;
file_t f_nudge = INVALID_FILE;      /* PR 502468 - nudge visualization */
static uint num_threads;

/* Counters for time unit intervals */
static int instr_count;
static int byte_count;
static int allocfree_count;

/* For -time_clock, the frequency is -dump_freq*10 milliseconds */
#define TIME_BASE_FREQ 10
/* These are all in milliseconds */
static uint timer_clock;
static uint timer_stale;
static uint timer_real;

/* Needed to compute the current partial snapshot (PR 548013) */
uint64 timestamp_last_snapshot;

static volatile bool sideline_exit;
/* FIXME i#297: DR synchs + terminates our sideline thread prior to
 * calling our exit event so we have no chance to clean up its memory.
 * DR then asserts about leaks.  Using a targeted solution for now.
 */
static tls_util_t *sideline_pt;
static int leak_count;
static int reachable_leak_count;

/* To avoid the code expansion from a clean call in every bb we use
 * a shared clean call sequence, entering it with a direct jump
 * and exiting with an indirect jump to a stored return point.
 */
static byte *shared_instrcnt_callout;
static byte *shared_code_region;
#define SHARED_CODE_SIZE \
    (PAGE_SIZE + (options.staleness ? (SHARED_SLOWPATH_SIZE) : 0))

/* We serialize snapshots since rare so not costly perf-wise, and this avoids
 * needing potentially very large buffers to try and get atomic writes
 */
static void *snapshot_lock;

/* We intercept libc/ntdll allocation routines instead of providing our
 * own, for maximum transparency.  Both use 8-byte (for 32-bit) headers.
 * FIXME: for 64-bit Windows, 8-byte-or-smaller allocs have special headers
 * that are only 8 bytes instead of 16?
 */
#ifdef UNIX
/* FIXME: mmap chunks have 2*size headers (xref PR 474912) */
# define HEADER_SIZE sizeof(size_t)
#else
# define HEADER_SIZE 2*sizeof(size_t)
#endif

static void reset_clock_timer(void);
static void reset_real_timer(void);
static void event_thread_exit(void *drcontext);

#ifdef STATISTICS
static void
dump_statistics(void);
# define STATS_DUMP_FREQ 10000
uint alloc_stack_count;
static uint peaks_detected;
static uint peaks_skipped;
#endif

/* PR 465174: share allocation site callstacks.
 * This table should only be accessed while holding the lock for
 * malloc_table (via malloc_lock(), which we enable via
 * alloc_ops.global_lock), which makes the coordinated operations with
 * malloc_table atomic.
 */
#define ASTACK_TABLE_HASH_BITS 8
static hashtable_t alloc_stack_table;
#ifdef CHECK_WITH_MD5
/* Used to check collisions with crc32 */
static hashtable_t alloc_md5_table;
#endif

/***************************************************************************
 * TLS and CLS
 */

typedef struct _tls_heapstat_t {
    char *errbuf; /* buffer for atomic writes */
    size_t errbufsz;
# ifdef UNIX
    int64 filepos; /* f_callstack file position */
# endif
} tls_heapstat_t;

/* XXX: share w/ syscall_os.h */
#ifdef WINDOWS
# define SYSCALL_NUM_ARG_STORE 14
#else
# define SYSCALL_NUM_ARG_STORE 6 /* 6 is max on Linux */
#endif

static int tls_idx_heapstat = -1;

/***************************************************************************
 * OPTIONS
 */

static void
reset_intervals(void)
{
    if (options.dump) {
        options.snapshots = 1;
    } else {
        options.dump_freq = 1;
    }

    /* Instr threshold is per 1k, so a max of 2 trillion instrs.
     * We could support more and still do 32-bit inlined arith by
     * having the callout do a mod.
     */
    if (options.time_instrs) {
        if (options.dump_freq > UINT_MAX/1000)
            usage_error("-dump_freq: value too large", "");
        options.dump_freq *= 1000;
        /* We count backward */
        instr_count = options.dump_freq;
    } else if (options.time_bytes) {
        if (!options.dump) {
            /* only *8 if doing const # snapshots.  this is invisible
             * to user so no need to talk about in docs: just makes
             * initial snapshots more reasonable than starting at 1.
             */
            ASSERT(options.dump_freq == 1, "invalid assumption");
            options.dump_freq = 8;
        }
        /* We count backward */
        byte_count = options.dump_freq;
    } else if (options.time_allocs) {
        /* We count backward */
        allocfree_count = options.dump_freq;
    }
}

static void
drheap_options_init(const char *opstr)
{
    options_init(opstr);

    reset_intervals();

    /* set globals */
    op_print_stderr = options.use_stderr;
    op_verbose_level = options.verbose;
    op_pause_at_assert = options.pause_at_assert;
    op_pause_via_loop = options.pause_via_loop;
    op_ignore_asserts = options.ignore_asserts;
    op_use_symcache = options.use_symcache;
}

/***************************************************************************
 * EVENTS FOR COMMON/ALLOC.C
 */

/* Snapshot arrays: of size options.snapshots.  For !options.dump,
 * when the arrays fill, we double the options.dump_freq frequency and
 * then replace snapshots that would not have existed if the
 * frequency had been the double one from the beginning.
 */
static uint snap_idx;
static uint snap_fills;

/* We keep a linked list of these structs per snapshot.
 * One struct per callstack that has non-zero usage in that snapshot.
 * This can save a lot of memory versus arrays when there are
 * many callstacks and few are present in all snapshots.
 * Xref PR 493134.
 */
typedef struct _heap_used_t {
    /* FIXME: 64-bit? */
    uint instances;
    uint bytes_asked_for;
    ushort extra_usable;   /* beyond bytes_asked_for */
    ushort extra_occupied; /* beyond bytes_asked_for + extra_usable */
    struct _heap_used_t *next;
    per_callstack_t *callstack;
} heap_used_t;

/* Arrays of snapshots.  Not using a heap_used_t b/c we need larger counters. */
typedef struct _per_snapshot_t {
    uint64 stamp;
    uint64 tot_mallocs;
    uint64 tot_bytes_asked_for;
    uint64 tot_bytes_usable;
    uint64 tot_bytes_occupied;
    /* Linked list of non-zero usage per callstack */
    heap_used_t *used;
    /* Staleness data: array with one entry per live malloc */
    stale_snap_allocs_t *stale;
} per_snapshot_t;

static uint64 stamp;
/* Used for starting time 0 in middle of run (post-nudge usually) */
static uint64 stamp_offs;
static per_snapshot_t *snaps;
/* peak snapshot (PR 476018) */
static per_snapshot_t snap_peak;
/* track changes in # allocs+frees for PR 566116 */
static uint64 allocfree_cur, allocfree_last_peak;
#define SNAPSHOT_LOG_BUF_SIZE   (32*1024)
static char snaps_log_buf[SNAPSHOT_LOG_BUF_SIZE];   /* PR 551841 */

struct _per_callstack_t {
    uint id;
#if defined(USE_MD5) || defined(CHECK_WITH_MD5)
    /* PR 496304: we keep just the md5 to save memory.  We either do so
     * instead of crc32, or in addition as a debug check on collisions.
     */
    byte md5[MD5_RAW_BYTES];
#endif
#ifndef USE_MD5
    /* PR 496304: we keep just a checksum to save memory.  Since crc32 could
     * collide we use crc32 of the whole callstack plus a separate crc32
     * of the first half of the callstack.
     */
    uint crc[2];
#endif
    /* for the current snapshot */
    heap_used_t *used;
    /* for node removal w/o keeping a prev per heap_used_t per snapshot */
    heap_used_t *prev_used;
};

static uint num_callstacks;
static uint snapshot_count;
static uint nudge_count;

uint
get_cstack_id(per_callstack_t *per)
{
    return per->id;
}

static inline per_callstack_t *
get_cstack_from_alloc_data(void *client_data)
{
    /* We store either per_callstack_t or stale_per_alloc_t in the
     * client_data slot in each malloc
     */
    if (options.staleness)
        return ((stale_per_alloc_t *)client_data)->cstack;
    else
        return (per_callstack_t *) client_data;
}

void
alloc_callstack_free(void *p)
{
    per_callstack_t *per = (per_callstack_t *) p;
    global_free(per, sizeof(*per), HEAPSTAT_CALLSTACK);
}

void
client_malloc_data_free(void *data)
{
    /* nothing to do since we persist our callstacks in alloc_stack_table */
}

void *
client_malloc_data_to_free_list(void *cur_data, dr_mcontext_t *mc, app_pc post_call)
{
    /* nothing to do since we persist our callstacks in alloc_stack_table */
    return cur_data;
}

void *
client_malloc_data_free_split(void *cur_data)
{
    /* Just keep the same data.  There's no use-after-free b/c we don't free
     * it in client_malloc_data_free().
     */
    return cur_data;
}

static void
get_buffer(void *drcontext, char **buf/*OUT*/, size_t *bufsz/*OUT*/)
{
    tls_heapstat_t *pt = (tls_heapstat_t *)
        drmgr_get_tls_field(drcontext, tls_idx_heapstat);
    ASSERT(buf != NULL && bufsz != NULL, "invalid args");
    if (pt == NULL) {
        /* at init time no pt yet */
        *bufsz = MAX_ERROR_INITIAL_LINES + max_callstack_size();
        *buf = (char *) global_alloc(*bufsz, HEAPSTAT_CALLSTACK);
    } else {
        *buf = pt->errbuf;
        *bufsz = pt->errbufsz;
    }
}

static void
release_buffer(void *drcontext, char *buf, size_t bufsz)
{
    tls_heapstat_t *pt = (tls_heapstat_t *)
        drmgr_get_tls_field(drcontext, tls_idx_heapstat);
    if (pt == NULL) {
        global_free(buf, bufsz, HEAPSTAT_CALLSTACK);
    }
}

static const char *
unit_name(void)
{
    if (options.time_instrs)
        return "instrs";
    if (options.time_allocs)
        return "mallocs";
    if (options.time_bytes)
        return "bytes";
    if (options.time_clock)
        return "ticks (10ms each)";
    return "<error>";
}

/* Up to caller to synchronize */
static void
dump_snapshot(per_snapshot_t *snap, int idx/*-1 means peak*/)
{
    heap_used_t *u;
    size_t sofar = 0;
    ssize_t len = 0;

    LOG(2, "dumping snapshot idx=%d count=%"INT64_FORMAT"u\n",
        idx, snap->stamp);
    dr_fprintf(f_snapshot, "SNAPSHOT #%4d @ %16"INT64_FORMAT"u %s\n",
               snapshot_count, snap->stamp + stamp_offs, unit_name());
    dr_fprintf(f_snapshot, "idx=%d, stamp_offs=%16"INT64_FORMAT"u\n",
               idx, stamp_offs);
    dr_fprintf(f_snapshot, "total: %"INT64_FORMAT"u,%"INT64_FORMAT"u,%"
               INT64_FORMAT"u,%"INT64_FORMAT"u\n",
               snap->tot_mallocs, snap->tot_bytes_asked_for,
               snap->tot_bytes_usable, snap->tot_bytes_occupied);

    for (u = snap->used; u != NULL; u = u->next) {
        if (u->bytes_asked_for + u->extra_usable > 0) {
            /* PR 551841: buffer snapshot output else performance is bad. */
            BUFFERED_WRITE(f_snapshot, snaps_log_buf, SNAPSHOT_LOG_BUF_SIZE,
                           sofar, len, "%u,%u,%u,%u,%u\n",
                           u->callstack->id, u->instances, u->bytes_asked_for,
                           u->extra_usable, u->extra_occupied);
        }
    }
    FLUSH_BUFFER(f_snapshot, snaps_log_buf, sofar);

    if (options.staleness) {
        uint i;
        dr_fprintf(f_staleness, "SNAPSHOT #%4d @ %16"INT64_FORMAT"u %s\n",
                   snapshot_count, snap->stamp + stamp_offs, unit_name());
        /* FIXME: optimize by listing cstack id only once; or binary format.
         * If still too big then collapse similar timestamps and give up
         * some runtime flexibility in granularity
         */
        sofar = 0;
        for (i = 0; snap->stale != NULL && i < snap->stale->num_entries; i++) {
            /* PR 551841: improve perf by printing to buffer to reduce # file writes */
            BUFFERED_WRITE(f_staleness, snaps_log_buf, SNAPSHOT_LOG_BUF_SIZE,
                           sofar, len, "%u,%u,%"INT64_FORMAT"u\n",
                           staleness_get_snap_cstack_id(snap->stale, i),
                           staleness_get_snap_bytes(snap->stale, i),
                           staleness_get_snap_last_access(snap->stale, i));
        }
        FLUSH_BUFFER(f_staleness, snaps_log_buf, sofar);
    }

    snapshot_count++;
}

/* Caller must hold snapshot_lock */
static void
free_snapshot(per_snapshot_t *snap)
{
    heap_used_t *u, *nxt_u;
    for (u = snap->used; u != NULL; u = nxt_u) {
        nxt_u = u->next;
        global_free(u, sizeof(*u), HEAPSTAT_SNAPSHOT);
    }
    snap->used = NULL;
    if (options.staleness && snap->stale != NULL) {
        staleness_free_snapshot(snap->stale);
        snap->stale = NULL;
    }
}

/* Caller must hold snapshot_lock.
 * Calls free_snapshot on dst first.
 * If new_live is true, dst is the new "live" in-progress snapshot
 * whose list is where callstack table entries point.
 */
static void
copy_snapshot(per_snapshot_t *dst, per_snapshot_t *src, bool new_live)
{
    heap_used_t *u, *nxt_u, *prev_u;
    int i;
    /* Replace the existing list at dst with a clone of
     * src, and update the callstack table pointers.  First
     * we clear the callstack table pointers in case pointing to
     * entries not in the new list.
     */
    ASSERT(src != dst, "cannot copy to self");

    free_snapshot(dst);

    memcpy(dst, src, sizeof(*dst));
    if (options.staleness) {
        /* We fill this in at snapshot time */
        dst->stale = NULL;
    }

    hashtable_lock(&alloc_stack_table);
    if (new_live) {
        for (i = 0; i < HASHTABLE_SIZE(alloc_stack_table.table_bits); i++) {
            hash_entry_t *he;
            for (he = alloc_stack_table.table[i]; he != NULL; he = he->next) {
                per_callstack_t *per = (per_callstack_t *) he->payload;
                per->used = NULL;
                per->prev_used = NULL;
            }
        }
    }

    prev_u = NULL;
    for (u = src->used; u != NULL; u = u->next) {
        nxt_u = (heap_used_t *) global_alloc(sizeof(*nxt_u), HEAPSTAT_SNAPSHOT);
        memcpy(nxt_u, u, sizeof(*nxt_u));
        if (prev_u == NULL)
            dst->used = nxt_u;
        else
            prev_u->next = nxt_u;
        if (new_live) {
            nxt_u->callstack->used = nxt_u;
            nxt_u->callstack->prev_used = prev_u;
        }
        nxt_u->next = NULL;
        prev_u = nxt_u;
    }
    hashtable_unlock(&alloc_stack_table);
}

static bool
difference_exceeds_percent(uint64 new_val, uint64 old_val, uint percent)
{
    /* Avoid floating-point via 100*.  Assuming no overflow b/c uint64. */
    uint64 diff = (new_val > old_val) ? (new_val - old_val) : (old_val - new_val);
    return (100 * diff > percent * old_val);
}

/* If the current snap_idx snapshot is larger than the current peak,
 * makes a new peak snapshot (PR 476018).
 * Assumes snapshot lock and malloc_lock are held.
 */
static void
check_for_peak(void)
{
    if (snaps[snap_idx].tot_bytes_occupied > snap_peak.tot_bytes_occupied) {
        /* PR 566116: avoid too-frequent peak snapshots by ignoring if the new
         * peak is similar to the existing one, both in size and in malloc
         * makeup.  May need to split -peak_threshold into 3 if we need
         * separate control of each variable.
         */
        if (difference_exceeds_percent(snaps[snap_idx].tot_bytes_occupied,
                                       snap_peak.tot_bytes_occupied,
                                       options.peak_threshold) ||
            difference_exceeds_percent(allocfree_cur, allocfree_last_peak,
                                       snap_peak.tot_bytes_occupied) ||
            /* even if not much different, if it's been a long time, use it */
            difference_exceeds_percent(snaps[snap_idx].stamp,
                                       snap_peak.stamp,
                                       options.peak_threshold)) {
            STATS_INC(peaks_detected);
            allocfree_last_peak = allocfree_cur;
            copy_snapshot(&snap_peak, &snaps[snap_idx], false/*isolated copy*/);
            if (options.staleness) {
                /* copy_snapshot called free_snapshot which freed this */
                ASSERT(snap_peak.stale == NULL, "invalid staleness data");
                snap_peak.stale = staleness_take_snapshot(stamp);
            }
            LOG(2, "new peak snapshot, tot occupied=%"INT64_FORMAT"u\n",
                snap_peak.tot_bytes_occupied);
        } else {
            STATS_INC(peaks_skipped);
            LOG(2, "NOT taking new peak snapshot, tot occupied=%"INT64_FORMAT"u\n",
                snap_peak.tot_bytes_occupied);
        }
    }
}

/* Caller must hold malloc_lock() */
static void
take_snapshot(void)
{
    uint prev_idx;
    /* We serialize snapshots since rare so not costly perf-wise, and this avoids
     * needing potentially very large buffers to try and get atomic writes
     */
    dr_mutex_lock(snapshot_lock);
    if (options.staleness) {
        /* Unlike the mem usage data which is maintained as the app
         * executes, we have to go collect this at snapshot time from
         * the malloc table.
         */
        if (options.dump && snaps[snap_idx].stale != NULL) {
            staleness_free_snapshot(snaps[snap_idx].stale);
            snaps[snap_idx].stale = NULL;
        }
        ASSERT(snaps[snap_idx].stale == NULL, "invalid staleness data");
        snaps[snap_idx].stale = staleness_take_snapshot(stamp);
    }
    if (options.dump) {
        snaps[snap_idx].stamp += options.dump_freq;
        dump_snapshot(&snaps[snap_idx], snap_idx);
    } else {
        stamp += options.dump_freq;
        snaps[snap_idx].stamp = stamp;
        prev_idx = snap_idx;
        LOG(2, "take_snapshot @idx=%u stamp=%"INT64_FORMAT"u\n", prev_idx, stamp);
        /* Check for peak on every snapshot (PR 476018) */
        check_for_peak();
        /* Find the next one we should overwrite.  Keep those aligned
         * w/ current dump_freq.
         */
        do {
            snap_idx++;
            if (snap_idx >= options.snapshots) {
                snap_fills++;
                snap_idx = 0;
                options.dump_freq *= 2;
                LOG(1, "adjusting snapshots: new freq=%u\n", options.dump_freq);
                if (options.time_clock)
                    reset_clock_timer();
            }
        } while (snaps[snap_idx].stamp > 0 &&
                 (snaps[snap_idx].stamp % options.dump_freq) == 0);

        /* Replace the existing list at snap_idx with a clone of prev_idx */
        copy_snapshot(&snaps[snap_idx], &snaps[prev_idx], true/*live copy*/);
    }
    dr_mutex_unlock(snapshot_lock);
}

/* Called from pre-alloc-hashtable-change events.
 * Updates the current snapshot and callstack usage.
 */
static void
account_for_bytes_pre(per_callstack_t *per, int asked_for,
                      int extra_usable, int extra_occupied, bool realloc)
{
    /* must be synched w/ take_snapshot().  the malloc lock is always acquired
     * before the snapshot lock.
     */
    dr_mutex_lock(snapshot_lock);
    if (asked_for+extra_usable > 0) {
        if (per->used == NULL) {
            per->used = (heap_used_t *)
                global_alloc(sizeof(*per->used), HEAPSTAT_SNAPSHOT);
            memset(per->used, 0, sizeof(*per->used));
            per->used->callstack = per;
            per->used->next = snaps[snap_idx].used;
            if (snaps[snap_idx].used != NULL) {
                ASSERT(snaps[snap_idx].used->callstack->prev_used == NULL,
                       "prev_used should already be null");
                snaps[snap_idx].used->callstack->prev_used = per->used;
            }
            ASSERT(per->prev_used == NULL, "prev_used should already be null");
            snaps[snap_idx].used = per->used;
        }
        if (!realloc)
            per->used->instances++;
        snaps[snap_idx].tot_mallocs++;
    } else {
        ASSERT(asked_for+extra_usable < 0, "cannot have 0-sized usable space");
        ASSERT(per->used != NULL, "alloc must exist");
        ASSERT(per->used->instances >= 0, "alloc count must be >= 0");
        ASSERT(snaps[snap_idx].tot_mallocs >= 0, "alloc count must be >= 0");
        if (!realloc)
            per->used->instances--;
        snaps[snap_idx].tot_mallocs--;
    }
    per->used->bytes_asked_for += asked_for;
    per->used->extra_usable += extra_usable;
    per->used->extra_occupied += extra_occupied;
    LOG(2, "callstack id %u => %ux, %uB, +%uB, +%uB\n", per->id,
        per->used->instances, per->used->bytes_asked_for,
        per->used->extra_usable, per->used->extra_occupied);
    if (per->used->instances == 0) {
        /* remove the node to save memory since may not re-alloc */
        ASSERT(per->used->bytes_asked_for == 0, "no malloc => no bytes!");
        if (per->used->next != NULL)
            per->used->next->callstack->prev_used = per->prev_used;
        if (per->prev_used == NULL) {
            ASSERT(per->used == snaps[snap_idx].used, "prev node error");
            snaps[snap_idx].used = per->used->next;
        } else {
            per->prev_used->next = per->used->next;
        }
        global_free(per->used, sizeof(*per->used), HEAPSTAT_SNAPSHOT);
        per->used = NULL;
        per->prev_used = NULL;
    }
    snaps[snap_idx].tot_bytes_asked_for += asked_for;
    snaps[snap_idx].tot_bytes_usable += asked_for + extra_usable;
    snaps[snap_idx].tot_bytes_occupied += asked_for + extra_usable + extra_occupied;
    dr_mutex_unlock(snapshot_lock);
}

/* Called from post-alloc-hashtable-change events which is important to
 * have a consistent view in the staleness hashtable walk (PR 567117).
 * Updates the -time_allocs and -time_bytes counters and potentially
 * takes snapshots.
 */
static void
account_for_bytes_post(int asked_for, int extra_usable, int extra_occupied)
{
    if (options.time_bytes) {
        /* PR 545288: consider dealloc as well as alloc */
        int diff = asked_for + extra_usable + extra_occupied;
        if (diff < 0)
            diff = -diff;
        if (diff > byte_count) {
            /* allocs larger than cur freq occupy multiple snapshots */
            while (diff > byte_count) {
                take_snapshot();
                diff -= options.dump_freq;
            }
            byte_count = options.dump_freq;
        } else {
            byte_count -= diff;
        }
    } else if (options.time_allocs) {
        /* PR 545288: consider free as well as alloc */
        /* We rely on malloc lock being held by caller */
        allocfree_count--;
        if (allocfree_count <= 0) {
            take_snapshot();
            allocfree_count = options.dump_freq;
        }
    }
    allocfree_cur++;
}

static void
dump_callstack(packed_callstack_t *pcs, per_callstack_t *per,
               char *buf, size_t bufsz, size_t *sofar)
{
    ssize_t len = 0;
    /* we use a buffer for atomic prints even though malloc lock does
     * currently synchronize
     */
    BUFPRINT(buf, bufsz, *sofar, len, "CALLSTACK %u\n", per->id);
    packed_callstack_print(pcs, 0, buf, bufsz, sofar, NULL);
    BUFPRINT(buf, bufsz, *sofar, len, "%s", END_MARKER);
    print_buffer(f_callstack, buf);
}

/* A lock is held around the call to this routine */
void *
client_add_malloc_pre(malloc_info_t *info, dr_mcontext_t *mc, app_pc post_call)
{
    void *drcontext = dr_get_current_drcontext();
    per_callstack_t *per;
    char *buf;
    size_t bufsz;
    size_t sofar = 0;
#ifdef STATISTICS
    static uint malloc_count;
#endif
    get_buffer(drcontext, &buf, &bufsz);
    if (info->client_data != NULL) {
        per = get_cstack_from_alloc_data(info->client_data);
        IF_DEBUG({
            hashtable_lock(&alloc_stack_table);
            ASSERT(hashtable_lookup(&alloc_stack_table,
                                    (void *)per->IF_MD5_ELSE(md5, crc)) == (void*)per,
                   "malloc re-add should still be in table");
            hashtable_unlock(&alloc_stack_table);
        });
    } else {
#if defined(USE_MD5) || defined(CHECK_WITH_MD5)
        byte md5[MD5_RAW_BYTES];
#endif
#ifndef USE_MD5
        uint crc[2];
#endif
        /* Printing to a buffer is slow (quite noticeable: 2x on cfrac) so it's
         * faster to create a packed callstack for computing the checksum to
         * decide uniqueness, limiting printing to new callstacks only.
         */
        packed_callstack_t *pcs;
        app_loc_t loc;
        pc_to_loc(&loc, post_call);
        packed_callstack_record(&pcs, mc, &loc, options.callstack_max_frames);

#if defined(USE_MD5) || defined(CHECK_WITH_MD5)
        packed_callstack_md5(pcs, md5);
#endif
#ifndef USE_MD5
        packed_callstack_crc32(pcs, crc);
#endif

        hashtable_lock(&alloc_stack_table);
        per = (per_callstack_t *)
            hashtable_lookup(&alloc_stack_table, (void *)IF_MD5_ELSE(md5, crc));
#ifdef CHECK_WITH_MD5
        /* Check for collisions with crc32 */
        ASSERT(per == hashtable_lookup(&alloc_md5_table, (void *)md5),
               "crc and md5 do not agree");
#endif
        if (per == NULL) {
            per = (per_callstack_t *) global_alloc(sizeof(*per), HEAPSTAT_CALLSTACK);
            memset(per, 0, sizeof(*per));
            /* we could do ++ since there's an outer lock */
            per->id = atomic_add32_return_sum((volatile int *)&num_callstacks, 1);
#if defined(USE_MD5) || defined(CHECK_WITH_MD5)
            memcpy(per->md5, md5, BUFFER_SIZE_BYTES(md5));
            hashtable_add(IF_MD5_ELSE(&alloc_stack_table, &alloc_md5_table),
                          (void *)per->md5, (void *)per);
#endif
#ifndef USE_MD5
            per->crc[0] = crc[0];
            per->crc[1] = crc[1];
            hashtable_add(&alloc_stack_table, (void *)per->crc, (void *)per);
#endif
            STATS_INC(alloc_stack_count);

            dump_callstack(pcs, per, buf, bufsz, &sofar);
        }
        hashtable_unlock(&alloc_stack_table);
        sofar = packed_callstack_free(pcs);
        ASSERT(sofar == 0, "pcs should have 0 ref count");
    }

#ifdef X64
    /* FIXME: assert not truncating */
#endif
    account_for_bytes_pre(per, info->request_size, info->pad_size, HEADER_SIZE, false);

#ifdef STATISTICS
    if (((malloc_count++) % STATS_DUMP_FREQ) == 0)
        dump_statistics();
#endif
    release_buffer(drcontext, buf, bufsz);

    if (options.staleness)
        return (void *) staleness_create_per_alloc(per, stamp);
    else
        return (void *) per;
}

void
client_add_malloc_post(malloc_info_t *info)
{
    /* take potential snapshots here once table is consistent (PR 567117) */
    account_for_bytes_post(info->request_size, info->pad_size, HEADER_SIZE);
}

/* A lock is held around the call to this routine */
void
client_remove_malloc_pre(malloc_info_t *info)
{
    per_callstack_t *per = get_cstack_from_alloc_data(info->client_data);
#ifdef X64
    /* FIXME: assert not truncating */
#endif
    /* To avoid repeatedly redoing the peak snapshot we wait until a drop (PR 476018) */
    dr_mutex_lock(snapshot_lock);
    check_for_peak();
    dr_mutex_unlock(snapshot_lock);
    account_for_bytes_pre(per, -(ssize_t)info->request_size, -(ssize_t)info->pad_size,
                          -(ssize_t)(HEADER_SIZE), false);
    if (options.staleness)
        staleness_free_per_alloc((stale_per_alloc_t *)info->client_data);
}

void
client_remove_malloc_post(malloc_info_t *info)
{
    /* take potential snapshots here once table is consistent (PR 567117) */
    account_for_bytes_post(info->request_size, info->pad_size, HEADER_SIZE);
}

static void
snapshot_init(void)
{
    snapshot_lock = dr_mutex_create();

    snaps = (per_snapshot_t *)
        global_alloc(options.snapshots*sizeof(*snaps), HEAPSTAT_SNAPSHOT);
    memset(snaps, 0, options.snapshots*sizeof(*snaps));
}

/* Caller must hold malloc lock */
static void
snapshot_dump_all(void)
{
    uint i;
    dr_mutex_lock(snapshot_lock);
    /* These should be sorted by stamp, but simpler to have the vis tool
     * sort them.
     */
    /* We do dump the partially-full current snapshot (PR 548013) */
    if (options.time_clock) {
        uint64 diff = ((dr_get_milliseconds() - timestamp_last_snapshot)
                       / TIME_BASE_FREQ) + 1 /* round up */;
        snaps[snap_idx].stamp = stamp + diff;
    } else if (options.time_allocs)
        snaps[snap_idx].stamp = stamp + (options.dump_freq - allocfree_count);
    else if (options.time_bytes)
        snaps[snap_idx].stamp = stamp + (options.dump_freq - byte_count);
    else if (options.time_instrs)
        snaps[snap_idx].stamp = stamp + (options.dump_freq - instr_count);
    /* Check for peak on every snapshot (PR 476018) */
    check_for_peak();
    dump_snapshot(&snap_peak, -1);
    if (snap_fills == 0) {
        for (i = 0; i <= snap_idx; i++) {
            dump_snapshot(&snaps[i], i);
        }
    } else {
        /* FIXME: sort by stamp */
        for (i = 0; i < options.snapshots; i++) {
            dump_snapshot(&snaps[i], i);
        }
    }
    dr_mutex_unlock(snapshot_lock);
}

static void
snapshot_exit(void)
{
    int i;

    snapshot_dump_all();

    for (i = 0; i < options.snapshots; i++)
        free_snapshot(&snaps[i]);
    global_free(snaps, options.snapshots*sizeof(*snaps), HEAPSTAT_SNAPSHOT);
    free_snapshot(&snap_peak);

    dr_mutex_destroy(snapshot_lock);
}

void
client_handle_malloc(void *drcontext, malloc_info_t *info, dr_mcontext_t *mc)
{
    if (options.check_leaks)
        leak_handle_alloc(drcontext, info->base, info->request_size);
}

void
client_handle_realloc(void *drcontext, malloc_info_t *old_info, malloc_info_t *new_info,
                      bool for_reuse, dr_mcontext_t *mc)
{
    /* We only need to act on an in-place realloc, as an out-of-place realloc
     * will have already called client_{remove,add}_malloc_{pre,post}.
     */
    if (new_info->base == old_info->base) {
        per_callstack_t *per = get_cstack_from_alloc_data(new_info->client_data);
        ssize_t delta_req = (ssize_t)new_info->request_size - old_info->request_size;
        ssize_t delta_pad = (ssize_t)new_info->pad_size - old_info->pad_size;
        ssize_t delta_head = 0;
        if (delta_req < 0) {
            /* Just like on a free we check for a drop in the peak */
            dr_mutex_lock(snapshot_lock);
            check_for_peak();
            dr_mutex_unlock(snapshot_lock);
        }
        account_for_bytes_pre(per, delta_req, delta_pad, delta_head, true/*realloc*/);
        account_for_bytes_post(delta_req, delta_pad, 0);
    }

    if (options.check_leaks)
        leak_handle_alloc(drcontext, new_info->base, new_info->request_size);
}

void
client_handle_alloc_failure(size_t request_size, app_pc pc, dr_mcontext_t *mc)
{
}

void
client_handle_realloc_null(app_pc pc, dr_mcontext_t *mc)
{
}

/* Returns the value to pass to free().  Return "real_base" for no change.
 * The Windows heap param is INOUT so it can be changed as well.
 */
app_pc
client_handle_free(malloc_info_t *info, byte *tofree, dr_mcontext_t *mc,
                   app_pc free_routine, void *routine_set_data, bool for_reuse
                   _IF_WINDOWS(ptr_int_t *auxarg INOUT))
{
    return tofree;
}

void
client_handle_free_reuse(void *drcontext, malloc_info_t *info, dr_mcontext_t *mc)
{
    /* nothing */
}

void
client_new_redzone(app_pc start, size_t size)
{
    /* nothing */
}

void
client_invalid_heap_arg(app_pc pc, app_pc target, dr_mcontext_t *mc, const char *routine,
                        bool is_free)
{
    /* not reporting today */
    LOG(1, "invalid heap arg\n");
}

void
client_mismatched_heap(app_pc pc, app_pc target, dr_mcontext_t *mc,
                       const char *alloc_routine, const char *free_routine,
                       const char *action, void *client_data, bool C_vs_CPP)
{
    /* not reporting today */
    LOG(1, "mismatched heap routines\n");
}

void
client_handle_mmap(void *drcontext, app_pc base, size_t size, bool anon)
{
}

void
client_handle_munmap(app_pc base, size_t size, bool anon)
{
}

void
client_handle_munmap_fail(app_pc base, size_t size, bool anon)
{
}

#ifdef UNIX
void
client_handle_mremap(app_pc old_base, size_t old_size, app_pc new_base, size_t new_size,
                     bool image)
{
}
#endif

void *
client_add_malloc_routine(app_pc pc)
{
    return NULL;
}

void
client_remove_malloc_routine(void *client_data)
{
}

#ifdef WINDOWS
void
client_handle_heap_destroy(void *drcontext, HANDLE heap,
                           void *client_data)
{
}

void
client_remove_malloc_on_destroy(HANDLE heap, byte *start, byte *end)
{
    if (options.check_leaks)
        leak_remove_malloc_on_destroy(heap, start, end);
}
#endif /* WINDOWS */

void
client_stack_alloc(byte *start, byte *end, bool defined)
{
}

void
client_stack_dealloc(byte *start, byte *end)
{
}

bool
client_write_memory(byte *start, size_t size, dr_mcontext_t *mc)
{
    return true;
}

bool
client_read_memory(byte *start, size_t size, dr_mcontext_t *mc)
{
    return true;
}

#ifdef DEBUG
void
client_print_callstack(void *drcontext, dr_mcontext_t *mc, app_pc pc)
{
    print_callstack_to_file(drcontext, mc, pc, f_global, options.callstack_max_frames);
}
#endif

void
client_pre_syscall(void *drcontext, int sysnum)
{
}

void
client_post_syscall(void *drcontext, int sysnum)
{
}

void
client_found_leak(app_pc start, app_pc end, size_t indirect_bytes,
                  bool pre_us, bool reachable,
                  bool maybe_reachable, void *client_data,
                  bool count_reachable, bool show_reachable)
{
    /* XXX i#926: we now have online symbolization of leak callstacks, but
     * we're re-symbolizing in postleaks.pl until we can produce a proper
     * error report here including suppression checking.  We should refactor
     * Dr. Memory leak reporting (and checking) into a library for sharing.
     */
    per_callstack_t *per = get_cstack_from_alloc_data(client_data);
    ssize_t len = 0;
    size_t sofar = 0;
    char *buf;
    size_t bufsz;
    void *drcontext = dr_get_current_drcontext();
    int num;

    ASSERT(options.check_leaks, "leak checking error");
    if (pre_us && options.ignore_early_leaks)
        return;
    if (reachable) {
        if (count_reachable)
            ATOMIC_INC32(reachable_leak_count);
        if (!show_reachable)
            return;
    }
    if (maybe_reachable && !options.possible_leaks)
        return;

    num = atomic_add32_return_sum((volatile int *)&leak_count, 1);
    get_buffer(drcontext, &buf, &bufsz);
    BUFPRINT(buf, bufsz, sofar, len, "Error #%d: ", num);
    if (reachable)
        BUFPRINT(buf, bufsz, sofar, len, "REACHABLE ");
    else if (maybe_reachable)
        BUFPRINT(buf, bufsz, sofar, len, "POSSIBLE ");
    BUFPRINT(buf, bufsz, sofar, len,
             "LEAK %d direct bytes "PFX"-"PFX" + %d indirect bytes"
             "\n\tcallstack=%d\n\terror end\n",
             (end - start), start, end, indirect_bytes, per->id);
    print_buffer(f_global, buf);
    release_buffer(drcontext, buf, bufsz);
}

/***************************************************************************
 * INSTRUMENTATION
 */

/* N.B.: mcontext is not in consistent app state, for efficiency.
 */
static void
shared_instrcnt_callee(void)
{
    bool do_snapshot = false;
    ASSERT(options.time_instrs, "option mismatch");
    /* We racily subtract and check, so serialize now for a single snapshot */
    dr_mutex_lock(snapshot_lock);
    /* We can still have a double-snapshot if threshold is low enough that
     * other threads bump the instr_count over it before 2nd guy to get lock
     * can do this check, but that's ok
     */
    if (instr_count < 0) {
        do_snapshot = true;
        instr_count = options.dump_freq;
    } else {
        /* We assume can't take so long that it wraps around */
        ASSERT(instr_count <= options.dump_freq, "callee incorrectly invoked");
    }
    /* Release lock so take_snapshot can grab it */
    dr_mutex_unlock(snapshot_lock);
    if (do_snapshot)
        take_snapshot();
}

/* To avoid the code expansion from a clean call in every bb we use
 * a shared clean call sequence, entering it with a direct jump
 * and exiting with an indirect jump to a stored return point.
 */
static app_pc
generate_shared_callout(void *drcontext, instrlist_t *ilist, app_pc pc)
{
    /* On entry:
     *   - SPILL_SLOT_2 holds the return address
     * The spill slots are persistent storage across clean calls.
     */
    dr_insert_clean_call(drcontext, ilist, NULL,
                         (void *) shared_instrcnt_callee, false, 0);
    PRE(ilist, NULL,
        INSTR_CREATE_jmp_ind(drcontext,
                             dr_reg_spill_slot_opnd(drcontext, SPILL_SLOT_2)));

    shared_instrcnt_callout = pc;
    pc = instrlist_encode(drcontext, ilist, pc, false);
    instrlist_clear(drcontext, ilist);
    return pc;
}

static void
create_shared_code(void)
{
    void *drcontext = dr_get_current_drcontext();
    byte *pc;
    IF_DEBUG(bool ok;)
    instrlist_t *ilist = instrlist_create(drcontext);

    shared_code_region = (byte *)
        nonheap_alloc(SHARED_CODE_SIZE,
                      DR_MEMPROT_READ|DR_MEMPROT_WRITE|DR_MEMPROT_EXEC,
                      HEAPSTAT_GENCODE);

    pc = shared_code_region;
    pc = generate_shared_callout(drcontext, ilist, pc);
    ASSERT(pc - shared_code_region <= SHARED_CODE_SIZE, "shared code region too small");

    if (options.staleness) {
        pc = generate_shared_slowpath(drcontext, ilist, pc);
        ASSERT(pc - shared_code_region <= SHARED_CODE_SIZE,
               "shared code region too small");
    }

    if (options.check_leaks) {
        pc = generate_shared_esp_slowpath(drcontext, ilist, pc);
        ASSERT(pc - shared_code_region <= SHARED_CODE_SIZE,
               "shared code region too small");
    }

    instrlist_clear_and_destroy(drcontext, ilist);

    /* now mark as +rx (non-writable) */
    IF_DEBUG(ok = )
        dr_memory_protect(shared_code_region, SHARED_CODE_SIZE,
                          DR_MEMPROT_READ|DR_MEMPROT_EXEC);
    ASSERT(ok, "-w failed on shared routines gencode");

    DOLOG(2, {
        byte *end_pc = pc;
        pc = shared_code_region;
        LOG(2, "shared_code region:\n");
        while (pc < end_pc) {
            pc = disassemble_with_info(drcontext, pc, f_global,
                                       true/*show pc*/, true/*show bytes*/);
        }
    });

}

static void
free_shared_code(void)
{
    nonheap_free(shared_code_region, SHARED_CODE_SIZE, HEAPSTAT_GENCODE);
}

static void
insert_instr_counter(void *drcontext, instrlist_t *bb,
                     instr_t *first, bool flags_dead, instr_t *where_dead,
                     uint instrs_in_bb)
{
    instr_t *where = (where_dead == NULL) ? first : where_dead;
    instr_t *done = INSTR_CREATE_label(drcontext);
    if (!flags_dead)
        dr_save_arith_flags(drcontext, bb, first, SPILL_SLOT_1);
    /* Rather than an ongoing count that would need a 64-bit
     * counter, we do a racy subtract of a 32-bit counter and if
     * negative (so we don't need a cmp) then we go to a callout
     * that synchs for a counter reset and single snapshot.
     * We assume that racy mods during that synch won't overflow
     * the counter.  We also ignore the detail of how many instrs
     * in this bb we've executed yet.
     */
    instrlist_meta_preinsert
        (bb, where, INSTR_CREATE_sub(drcontext, OPND_CREATE_ABSMEM
                                     ((byte *)&instr_count, OPSZ_4),
                                     (instrs_in_bb <= CHAR_MAX) ?
                                     OPND_CREATE_INT8(instrs_in_bb) :
                                     OPND_CREATE_INT32(instrs_in_bb)));
    /* TODO: for better perf could not bother to check threshold
     * in every bb: but don't want to skip for single-bb-loop-body
     */
    instrlist_meta_preinsert
        (bb, where, INSTR_CREATE_jcc(drcontext, OP_jns_short,
                                     opnd_create_instr(done)));
    /* To avoid the code expansion from a clean call in every bb we use
     * a shared clean call sequence, entering it with a direct jump
     * and exiting with an indirect jump to a stored return point.
     */
    /* Get return point into SPILL_SLOT_2.  Spill reg, mov imm to reg, and then
     * xchg reg and slot isn't any faster, right?
     */
    instrlist_meta_preinsert
        (bb, where, INSTR_CREATE_mov_st
         (drcontext, dr_reg_spill_slot_opnd(drcontext, SPILL_SLOT_2),
          opnd_create_instr(done)));
    instrlist_meta_preinsert
        (bb, where, INSTR_CREATE_jmp(drcontext,
                                     opnd_create_pc(shared_instrcnt_callout)));
    /* Will return here */
    instrlist_meta_preinsert(bb, where, done);
    if (!flags_dead)
        dr_restore_arith_flags(drcontext, bb, first, SPILL_SLOT_1);
}

static dr_emit_flags_t
event_bb_app2app(void *drcontext, void *tag, instrlist_t *bb,
                         bool for_trace, bool translating, void **user_data OUT)
{
    /* we pass bi among all 4 phases */
    instru_info_t *ii = thread_alloc(drcontext, sizeof(*ii), HEAPSTAT_PERBB);
    memset(ii, 0, sizeof(*ii));
    *user_data = (void *) ii;
    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb,
                         bool for_trace, bool translating, void *user_data)
{
    instru_info_t *ii = (instru_info_t *) user_data;
    DOLOG(3, instrlist_disassemble(drcontext, tag, bb, LOGFILE_GET(drcontext)););
#ifdef USE_DRSYMS
    DOLOG(3, {
        char buf[128];
        size_t sofar = 0;
        ssize_t len;
        if (!translating) {
            BUFPRINT(buf, BUFFER_SIZE_ELEMENTS(buf), sofar, len,
                     "new basic block @"PFX" ==", tag);
            print_symbol(tag, buf, BUFFER_SIZE_ELEMENTS(buf), &sofar, false, 0);
            LOG(1, "%s\n", buf);
        }
    });
#endif
    if (options.staleness)
        fastpath_top_of_bb(drcontext, tag, bb, &ii->bi);
    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                       bool for_trace, bool translating, void *user_data)
{
    instru_info_t *ii = (instru_info_t *) user_data;
    uint flags;
    fastpath_info_t mi;

    if (instr_is_meta(inst))
        return DR_EMIT_DEFAULT;

    /* i#2402: Temporarily disable auto predication globally due to poor
     * interaction with internal control flow we emit.
     */
    drmgr_disable_auto_predication(drcontext, bb);

    ii->instrs_in_bb++;

    if (options.time_instrs) {
        /* See if flags are dead anywhere.
         * FIXME: for fault handling we should either consider a faultable
         * instr as having live flags or recover somehow: ignoring for now
         * as pathological.
         */
        flags = instr_get_arith_flags(inst, DR_QUERY_DEFAULT);
        /* We insert after the prev instr to avoid messing up
         * -check_leaks instrumentation (PR 560871)
         */
        if (TESTALL(EFLAGS_WRITE_6, flags) && !TESTANY(EFLAGS_READ_6, flags)) {
            ii->where_dead = instr_get_prev(inst);
            ii->flags_dead = true;
        }
    }

    if (options.staleness) {
        /* We want to spill AFTER any clean call in case it changes mcontext */
        ii->bi.spill_after = instr_get_prev(inst);

        /* update liveness of whole-bb spilled regs */
        fastpath_pre_instrument(drcontext, bb, inst, &ii->bi);

        if (instr_uses_memory_we_track(inst)) {
            if (instr_ok_for_instrument_fastpath(inst, &mi, &ii->bi)) {
                instrument_fastpath(drcontext, bb, inst, &mi, false);
                ii->bi.added_instru = true;
            } else {
                LOG(3, "fastpath unavailable "PFX": ", instr_get_app_pc(inst));
                DOLOG(3, { instr_disassemble(drcontext, inst,
                                             LOGFILE_GET(drcontext)); });
                LOG(3, "\n");
                ii->bi.shared_memop = opnd_create_null();
                /* Restore whole-bb spilled regs (PR 489221)
                 * FIXME: optimize via liveness analysis
                 */
                mi.reg1 = ii->bi.reg1;
                mi.reg2 = ii->bi.reg2;
                memset(&mi.reg3, 0, sizeof(mi.reg3));
                instrument_slowpath(drcontext, bb, inst,
                                    whole_bb_spills_enabled() ? &mi : NULL);
                /* for whole-bb slowpath does interact w/ global regs */
                ii->bi.added_instru = whole_bb_spills_enabled();
            }
        }
    }

    if (ZERO_STACK() && instr_writes_esp(inst)) {
        /* any new spill must be after the alloc instru */
        ii->bi.spill_after = instr_get_prev(inst);
        /* we zero for leaks, and staleness does not care about xsp */
        instrument_esp_adjust(drcontext, bb, inst, &ii->bi,
                              SP_ADJUST_ACTION_ZERO);
        ii->bi.added_instru = true;
    }

    if (options.staleness)
        fastpath_pre_app_instr(drcontext, bb, inst, &ii->bi, &mi);

    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
event_bb_instru2instru(void *drcontext, void *tag, instrlist_t *bb,
                       bool for_trace, bool translating, void *user_data)
{
    instru_info_t *ii = (instru_info_t *) user_data;
    if (options.staleness) {
        fastpath_bottom_of_bb(drcontext, tag, bb, &ii->bi, ii->bi.added_instru,
                              translating, false);
    }
    if (options.time_instrs) {
        insert_instr_counter(drcontext, bb, instrlist_first(bb), ii->flags_dead,
                             /* insert after the prev instr to avoid messing up
                              * -check_leaks instrumentation (PR 560871)
                              */
                             (ii->where_dead == NULL) ?
                             instrlist_first(bb) : instr_get_next(ii->where_dead),
                             ii->instrs_in_bb);
    }

    LOG(3, "final instrumentation:\n");
    DOLOG(3, instrlist_disassemble(drcontext, tag, bb, LOGFILE_GET(drcontext)););

    thread_free(drcontext, ii, sizeof(*ii), HEAPSTAT_PERBB);
    return DR_EMIT_DEFAULT; /* deterministic */
}

/***************************************************************************
 * DYNAMORIO EVENTS & TOP-LEVEL CODE
 */

#ifdef STATISTICS
/* statistics
 * FIXME: make per-thread to avoid races (or use locked inc)
 * may want some of these to be 64-bit
 */
static void
dump_statistics(void)
{
    int i;
    dr_fprintf(f_global, "Statistics:\n");
    dr_fprintf(f_global, "app mallocs: %8u, frees: %8u, large mallocs; %6u\n",
               num_mallocs, num_frees, num_large_mallocs);
    dr_fprintf(f_global, "unique malloc stacks: %8u\n", alloc_stack_count);
    dr_fprintf(f_global, "app heap regions: %8u\n", heap_regions);
    dr_fprintf(f_global, "peaks detected: %8u, skipped: %8u\n",
               peaks_detected, peaks_skipped);
    if (options.staleness) {
        dr_fprintf(f_global, "staleness: needs large: %7u, needs ext: %7u\n",
                   stale_needs_large, stale_small_needs_ext);
    }

    /* FIXME: share w/ drmemory.c */
    dr_fprintf(f_global, "\nPer-opcode slow path executions:\n");
    for (i = 0; i <= OP_LAST; i++) {
        if (slowpath_count[i] > 0) {
            dr_fprintf(f_global, "\t%3u %10s: %12"UINT64_FORMAT_CODE"\n",
                       i, decode_opcode_name(i), slowpath_count[i]);
        }
    }

    heap_dump_stats(f_global);
}
#endif /* STATISTICS */

#if DEBUG
/* drsyscall debug build uses this */
void
report_callstack(void *drcontext, dr_mcontext_t *mc)
{
}
#endif /* DEBUG */

static void
client_heap_add(app_pc start, app_pc end, dr_mcontext_t *mc)
{
    LOG(2, "%s "PFX"-"PFX"\n", __FUNCTION__, start, end);
    if (options.staleness)
        shadow_create_shadow_memory(start, end, 0);
}

static void
client_heap_remove(app_pc start, app_pc end, dr_mcontext_t *mc)
{
    /* save memory and improve performance by putting back the specials --
     * except w/ our sideline thread doing sweeps we could have races
     * (unlikely since this is a heap region remove) so it's not safe.
     * we just live w/ the extra mem and writes.
     */
    LOG(2, "%s "PFX"-"PFX"\n", __FUNCTION__, start, end);
#if 0 /* disabled: see comment above */
    if (options.staleness)
        shadow_reinstate_specials_in_range(start, end);
#endif
}

static void
heap_iter_region(app_pc start, app_pc end _IF_WINDOWS(HANDLE heap))
{
    client_heap_add(start, end, NULL);
    heap_region_add(start, end, HEAP_PRE_US | HEAP_ARENA, NULL);
}

static void
heap_iter_chunk(app_pc start, app_pc end)
{
    /* We don't have the asked-for size so we use real end for both */
    malloc_add(start, end, end, true/*pre_us*/, 0, NULL, NULL);
}

/* Walk the heap blocks that are already allocated at client init time */
static void
heap_walk(void)
{
    heap_iterator(heap_iter_region, heap_iter_chunk _IF_WINDOWS(NULL));
}

/* if which_thread is >= 0, creates a file name with which_thread and
 * the cur thread's tid
 */
static file_t
open_logfile(const char *name, bool pid_log, int which_thread)
{
    file_t f;
    char logname[MAXIMUM_PATH];
    IF_DEBUG(int len;)
    uint extra_flags = IF_UNIX_ELSE(DR_FILE_ALLOW_LARGE, 0);
    ASSERT(logsubdir[0] != '\0', "logsubdir not set up");
    if (pid_log) {
        IF_DEBUG(len = )
            dr_snprintf(logname, BUFFER_SIZE_ELEMENTS(logname),
                        "%s%c%s.%d.log", logsubdir, DIRSEP, name, dr_get_process_id());
    } else if (which_thread >= 0) {
        IF_DEBUG(len = )
            dr_snprintf(logname, BUFFER_SIZE_ELEMENTS(logname),
                        "%s%c%s.%d.%d.log", logsubdir, DIRSEP, name,
                          which_thread, dr_get_thread_id(dr_get_current_drcontext()));
        /* have DR close on fork so we don't have to track and iterate */
        extra_flags |= DR_FILE_CLOSE_ON_FORK;
    } else {
        IF_DEBUG(len = )
            dr_snprintf(logname, BUFFER_SIZE_ELEMENTS(logname),
                        "%s%c%s", logsubdir, DIRSEP, name);
    }
    ASSERT(len > 0, "logfile name buffer max reached");
    NULL_TERMINATE_BUFFER(logname);
    f = dr_open_file(logname, DR_FILE_WRITE_OVERWRITE | extra_flags);
    ASSERT(f != INVALID_FILE, "unable to open log file");
    if (which_thread > 0) {
        void *drcontext = dr_get_current_drcontext();
        dr_log(drcontext, LOG_ALL, 1,
               "DrMemory: log for thread "TIDFMT" is %s\n",
               dr_get_thread_id(drcontext), logname);
        NOTIFY("thread logfile is %s"NL, logname);
    }
    return f;
}

/* also initializes logsubdir */
static void
create_global_logfile(void)
{
    uint count = 0;
    const char *appnm = dr_get_application_name();
    const uint LOGDIR_TRY_MAX = 1000;
    /* PR 408644: pick a new subdir inside base logdir */
    /* PR 453867: logdir must have pid in its name */
    do {
        dr_snprintf(logsubdir, BUFFER_SIZE_ELEMENTS(logsubdir),
                    "%s%cDrHeapstat-%s.%d.%03d",
                    options.logdir, DIRSEP, appnm == NULL ? "null" : appnm,
                    dr_get_process_id(), count);
        NULL_TERMINATE_BUFFER(logsubdir);
        /* FIXME PR 514092: if the base logdir is unwritable, we shouldn't loop
         * UINT_MAX times: it looks like we've hung.
         * Unfortuantely dr_directory_exists() is Windows-only and
         * dr_create_dir returns only a bool, so for now we just
         * fail if we hit 1000 dirs w/ same pid.
         */
    } while (!dr_create_dir(logsubdir) && ++count < LOGDIR_TRY_MAX);
    if (count >= LOGDIR_TRY_MAX) {
        NOTIFY_ERROR("Unable to create subdir in log base dir %s"NL, options.logdir);
        ASSERT(false, "unable to create unique logsubdir");
        dr_abort();
    }

    f_global = open_logfile("global", true/*pid suffix*/, -1);
#ifdef UNIX
    /* make it easier for wrapper script to find this logfile */
    dr_fprintf(f_global, "process=%d, parent=%d\n",
               dr_get_process_id(), dr_get_parent_id());
#endif
    /* make sure "Dr. Heapstat" is 1st (or 2nd on linux) in file (for PR 453867) */
    dr_fprintf(f_global, "Dr. Heapstat version %s\n", VERSION_STRING);
    NOTIFY("log dir is %s"NL, logsubdir);
    LOGF(1, f_global, "running %s\n",
         (dr_get_application_name() == NULL) ? "<null>" : dr_get_application_name());
    LOGF(1, f_global, "global logfile fd=%d\n", f_global);

    f_callstack = open_logfile("callstack.log", false, -1);
    f_snapshot = open_logfile("snapshot.log", false, -1);
    if (options.staleness)
        f_staleness = open_logfile("staleness.log", false, -1);

    /* For long running multi-process apps like sfcbd, this can mean a lot of
     * index files.  With each file being 1 MB minimum on esxi, space can be
     * used up fast.  On ther other hand computing nudge index in postprocess
     * each time can be time consuming with large number of snapshots, thereby
     * affecting the vistool startup time.  No simple solution.  If the file
     * problem gets out of hand, we might use the global log, but then that
     * requires parsing the global log, which can get large.
     */
    f_nudge = open_logfile("nudge.idx", false, -1);
    dr_fprintf(f_nudge, "%s snapshots\n", options.dump ? "variable" : "constant");
}

static void
close_file(file_t f)
{
    /* with DRi#357, DR now isolates log files so little to do here */
    dr_close_file(f);
}

#define dr_close_file DO_NOT_USE_dr_close_file

static void
reset_to_time_zero(bool keep_offs)
{
    int i;
    dr_mutex_lock(snapshot_lock);

    /* take current data and make it the cur val of to-be-snapshot 0 */
    if (snap_idx != 0)
        copy_snapshot(&snaps[0], &snaps[snap_idx], true/*live copy*/);
    for (i = 1; i < options.snapshots; i++)
        free_snapshot(&snaps[i]);
    memset(&snaps[1], 0, (options.snapshots-1)*sizeof(*snaps));

    if (keep_offs)
        stamp_offs = stamp;
    else
        reset_intervals();
    stamp = 0;
    snap_idx = 0;
    /* malloc_count we do not reset */

    dr_mutex_unlock(snapshot_lock);
}

static void
event_timer(void *drcontext, dr_mcontext_t *mcontext)
{
    bool alarm_clock = false, alarm_stale = false;
    if (sideline_exit) {
#ifdef UNIX
        dr_set_itimer(ITIMER_REAL, 0, event_timer);
#endif
       return;
    }
    if (options.time_clock) {
        ASSERT(timer_real <= timer_clock, "timer internal error");
        timer_clock -= timer_real;
        if (timer_clock == 0) {
            alarm_clock = true;
            timer_clock = options.dump_freq*TIME_BASE_FREQ;
        }
    }
    if (options.staleness) {
        ASSERT(timer_real <= timer_stale, "timer internal error");
        timer_stale -= timer_real;
        if (timer_stale == 0) {
            alarm_stale = true;
            /* FIXME PR 553724: should -stale_granularity be increased as
             * -dump_freq increases?  For a long-running app it seems fine to
             * make the staleness data coarser and coarser, which also improves
             * performance.
            */
            timer_stale = options.stale_granularity;
        }
    }
    /* reset now before potentially taking a while in code below, to avoid
     * clock drift
     */
    reset_real_timer();

    if (alarm_clock) {
        timestamp_last_snapshot = dr_get_milliseconds();
        /* Must hold malloc lock first.  We set alloc_ops.global_lock, so this
         * will synchronize w/ all allocations and frees.
         */
        malloc_lock();
        take_snapshot();
        malloc_unlock();
    }
    if (alarm_stale) {
        staleness_sweep(stamp);
    }
}

static void
reset_real_timer(void)
{
    /* set real timer to the smaller and when it fires we'll adjust both */
    if (options.staleness) {
        if (options.time_clock) {
            timer_real = (timer_clock > 0 && timer_clock < timer_stale) ?
                timer_clock : timer_stale;
        } else
            timer_real = timer_stale;
    } else {
        ASSERT(options.time_clock, "timer should not be active");
        timer_real = timer_clock;
    }
    ASSERT(timer_real >= 0, "timer internal error");
#ifdef UNIX
    if (!dr_set_itimer(ITIMER_REAL, timer_real, event_timer))
        ASSERT(false, "unable to set up timer callback\n");
#endif
}

static void
reset_clock_timer(void)
{
    if (options.time_clock)
        timer_clock = options.dump_freq*TIME_BASE_FREQ;
    reset_real_timer();
}

/* For -time_clock we need a timer (PR 476008): simplest to use a separate thread */
static void
sideline_run(void *arg)
{
    void *drcontext = dr_get_current_drcontext();

    /* PR 609569: we spend a lot of time holding locks, so keep running
     * during synchall.  Our locks keep us safe wrt leak scan, and we
     * do not mutate any app state or non-persistent DR state.
     */
    dr_client_thread_set_suspendable(false);

    if (options.thread_logs) {
        /* easier to debug w/ all staleness and clock snaps in sep file */
        /* FIXME i#297: have to use global heap for sideline thread */
        sideline_pt = global_alloc(sizeof(*sideline_pt), HEAPSTAT_MISC);
        memset(sideline_pt, 0, sizeof(*sideline_pt));
        /* store it in the slot provided in the drcontext */
        drmgr_set_tls_field(drcontext, tls_idx_util, (void *)sideline_pt);
        utils_thread_set_file(drcontext, open_logfile("sideline.log", false, -1));
    }
    if (options.staleness)
        timer_stale = options.stale_granularity;
    reset_clock_timer();
    ASSERT(options.time_clock || options.staleness, "thread should not be running");
    LOG(1, "sideline thread "TIDFMT" running\n", dr_get_thread_id(drcontext));
    while (!sideline_exit) {
#ifdef WINDOWS
        dr_sleep(timer_real);
        /* FIXME: check wall-clock time and normalize to get closer to real time */
        event_timer(drcontext, NULL);
#else
        dr_sleep(500);
#endif
    }
#ifdef UNIX
    dr_set_itimer(ITIMER_REAL, 0, event_timer);
#endif
    /* i#297: we can't clean up sideline_pt so event_exit does it */
}

#ifdef UNIX
static void
event_fork(void *drcontext)
{
    /* we want a whole new log dir to avoid clobbering the parent's */
    tls_heapstat_t *pt = (tls_heapstat_t *)
        drmgr_get_tls_field(drcontext, tls_idx_heapstat);
    /* fds are shared across fork so we must duplicate */
    file_t f_parent_callstack = dr_dup_file_handle(f_callstack);
    /* we assume no lock is needed since only one thread post-fork */
    static char buf[4096];

    close_file(f_global);
    close_file(f_callstack);
    close_file(f_snapshot);
    if (options.staleness)
        close_file(f_staleness);
    close_file(f_nudge);
    /* now create new files for all 5 */
    create_global_logfile();
    utils_thread_set_file(drcontext, f_global);
    LOG(0, "new logfile after fork fd=%d\n", f_global);

    /* we don't expect the user to go find the parent's data,
     * so we need to duplicate the callstack file and start
     * the snapshots over.  we no longer keep full callstacks
     * in memory (PR 496304) so we copy the file.
     * so we don't have to parse and find id# num_callstacks we
     * store the file position.
     */
    if (dr_file_seek(f_parent_callstack, 0, DR_SEEK_SET)) {
        int64 curpos = 0;
        IF_DEBUG(ssize_t sz;)
        LOG(1, "copying parent callstacks "INT64_FORMAT_STRING" bytes\n", pt->filepos);
        while (curpos + sizeof(buf) <= pt->filepos) {
            IF_DEBUG(sz = )
                dr_read_file(f_parent_callstack, buf, sizeof(buf));
            ASSERT(sz == sizeof(buf), "error reading parent callstack data");
            IF_DEBUG(sz = )
                dr_write_file(f_callstack, buf, sizeof(buf));
            ASSERT(sz == sizeof(buf), "error writing parent callstack data");
            curpos += sizeof(buf);
        }
        ASSERT(pt->filepos - curpos < sizeof(buf), "buf calc error");
        IF_DEBUG(sz = )
            dr_read_file(f_parent_callstack, buf, pt->filepos - curpos);
        ASSERT(sz == pt->filepos - curpos, "error reading parent callstack data");
        IF_DEBUG(sz = )
            dr_write_file(f_callstack, buf, pt->filepos - curpos);
        ASSERT(sz == pt->filepos - curpos, "error writing parent callstack data");
    } else
        LOG(0, "ERROR: unable to copy parent callstack file\n");
    close_file(f_parent_callstack);

    reset_to_time_zero(false/*start time over*/);
}
#endif

#ifdef UNIX
dr_signal_action_t
event_signal(void *drcontext, dr_siginfo_t *info)
{
    if (info->sig == SIGSEGV && ZERO_STACK() &&
        handle_zeroing_fault(drcontext, info->access_address, info->raw_mcontext,
                             info->mcontext)) {
        return DR_SIGNAL_SUPPRESS;
    }
    return DR_SIGNAL_DELIVER;
}
#else
bool
event_exception(void *drcontext, dr_exception_t *excpt)
{
    if (excpt->record->ExceptionCode == STATUS_ACCESS_VIOLATION) {
        app_pc target = (app_pc) excpt->record->ExceptionInformation[1];
        if (ZERO_STACK() &&
            excpt->record->ExceptionInformation[0] == 1 /* write */ &&
            handle_zeroing_fault(drcontext, target, excpt->raw_mcontext,
                                 excpt->mcontext)) {
            return false;
        }
    }
    return true;
}
#endif

bool
event_restore_state_nop(void *drcontext, bool restore_memory,
                        dr_restore_state_info_t *info)
{
    /* nothing: just here to avoid DR warning on zeroing loop faulting instrs */
    return true;
}

static bool
event_filter_syscall(void *drcontext, int sysnum)
{
    switch (sysnum) {
#ifdef UNIX
    case SYS_close:
    case SYS_fork:
    case SYS_clone:
    IF_VMX86(case 1025:)
        return true;
#endif
    default:
        return alloc_syscall_filter(drcontext, sysnum);
    }
}

static bool
event_pre_syscall(void *drcontext, int sysnum)
{
    tls_heapstat_t *pt = (tls_heapstat_t *)
        drmgr_get_tls_field(drcontext, tls_idx_heapstat);
    dr_mcontext_t *mc;
    if (drsys_get_mcontext(drcontext, &mc) != DRMF_SUCCESS)
        ASSERT(false, "drsys_get_mcontext failed");

    DOLOG(2, {
        drsys_sysnum_t sysnum_full;
        drsys_syscall_t *syscall;
        const char *name;
        if (drsys_cur_syscall(drcontext, &syscall) != DRMF_SUCCESS)
            ASSERT(false, "shouldn't fail");
        if (drsys_syscall_number(syscall, &sysnum_full) != DRMF_SUCCESS)
            ASSERT(false, "drsys_get_sysnum failed");
        if (drsys_syscall_name(syscall, &name) != DRMF_SUCCESS)
            ASSERT(false, "drsys_syscall_name failed");
        LOG(2, "system call #%d==%d.%d %s\n", sysnum,
            sysnum_full.number, sysnum_full.secondary, name);
    });

    handle_pre_alloc_syscall(drcontext, sysnum, mc);

#ifdef UNIX
    if (sysnum == SYS_fork ||
        (sysnum == SYS_clone &&
         !TEST(CLONE_VM, (uint) dr_syscall_get_param(drcontext, 0)))
        /* FIXME: if open-sourced we should split this.
         * Presumably we'll have the bora shlib split before then.
         */
        IF_VMX86(|| sysnum == 1025)) {
        /* Store the file offset in the client_data field, shared across callbacks */
        pt->filepos = dr_file_tell(f_callstack);
        LOG(1, "SYS_fork: callstack file @ "INT64_FORMAT_STRING"\n", pt->filepos);
    }
#endif
    return true; /* execute syscall */
}

static void
event_post_syscall(void *drcontext, int sysnum)
{
    dr_mcontext_t *mc;
    if (drsys_get_mcontext(drcontext, &mc) != DRMF_SUCCESS)
        ASSERT(false, "drsys_get_mcontext failed");
    handle_post_alloc_syscall(drcontext, sysnum, mc);
}

void
check_reachability(bool at_exit)
{
    if (options.check_leaks) {
        void *drcontext = dr_get_current_drcontext();
        ssize_t len = 0;
        size_t sofar = 0;
        char *buf;
        size_t bufsz;
        leak_scan_for_leaks(at_exit);
        get_buffer(drcontext, &buf, &bufsz);
        BUFPRINT(buf, bufsz, sofar, len,
                 "ERRORS IGNORED:\n  %5d still-reachable allocation(s)\n",
                 reachable_leak_count);
        if (!options.show_reachable) {
            BUFPRINT(buf, bufsz, sofar, len,
                     "         (re-run with \"-check_leaks -show_reachable\""
                     " for details)\n");
        }
        print_buffer(f_global, buf);
        release_buffer(drcontext, buf, bufsz);
    }
}

static void
print_nudge_header(file_t f)
{
    dr_fprintf(f, "NUDGE @ %16"INT64_FORMAT"u %s\n\n",
               snaps[snap_idx].stamp, unit_name());
}

static void
event_nudge(void *drcontext, uint64 argument)
{
    uint64 snapshot_fpos = 0;
    uint64 staleness_fpos = 0;

    /* PR 476043: use nudge to output snapshots for daemon app.  For
     * now we have only one use, so we don't need the argument, but we
     * may want an option to reset the start point for whole-run
     * vs since-last-nudge snapshots: though that would require
     * changing all usage types to be signed (PR 553707) so we
     * keep everything absolute w/ no reset on nudge.
     */
    /* We hold the malloc lock across the snapshot + reset to prevent
     * new allocs being added in between
     */
    malloc_lock(); /* must be acquired before snapshot_lock */
    nudge_count++;
    snapshot_dump_all();
    print_nudge_header(f_snapshot);
    print_nudge_header(f_callstack);
    if (options.dump) {
        /* For const # snapshots, we want the peak to be the global peak for the
         * whole run, regardless of how many nudges were done.
         * For dump-as-you-go, we want a local peak since the last nudge.
         */
        free_snapshot(&snap_peak);
        memset(&snap_peak, 0, sizeof(snap_peak));
    }
    if (options.staleness)
        print_nudge_header(f_staleness);

    /* Print the nudge index information, i.e., for each nudge, print the file
     * position in snapshot.log that marks the begining of new data after nudge
     * data was dumped.  This makes nudge handling efficient as opposed to
     * building the index during the post process stage which would require a
     * full pass of the snapshot.log file which can be large.  The same applies
     * to staleness.log.  Also specify whether snapshots are fixed in number or
     * variable (-dump).  PR 502468.
     */
    snapshot_fpos = dr_file_tell(f_snapshot);
    if (options.staleness)
        staleness_fpos = dr_file_tell(f_staleness);
    ASSERT(snapshot_fpos >= 0 && staleness_fpos >= 0, "bad log file location");
    dr_fprintf(f_nudge, "%d,%"INT64_FORMAT"u,%"INT64_FORMAT"u\n",
               nudge_count, snapshot_fpos, staleness_fpos);
    malloc_unlock();
    check_reachability(false/*!at_exit*/);
    print_nudge_header(f_global);
    NOTIFY("Received nudge"NL, logsubdir);
}

static void
event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    callstack_module_load(drcontext, info, loaded);
    alloc_module_load(drcontext, info, loaded);
}

static void
event_module_unload(void *drcontext, const module_data_t *info)
{
    callstack_module_unload(drcontext, info);
    alloc_module_unload(drcontext, info);
}

static void
event_fragment_delete(void *drcontext, void *tag)
{
    instrument_fragment_delete(drcontext, tag);
    alloc_fragment_delete(drcontext, tag);
}

static void
event_thread_init(void *drcontext)
{
    uint which_thread = atomic_add32_return_sum((volatile int *)&num_threads, 1) - 1;
    file_t f;
    tls_heapstat_t *pt = (tls_heapstat_t *)
        thread_alloc(drcontext, sizeof(*pt), HEAPSTAT_MISC);
    memset(pt, 0, sizeof(*pt));
    drmgr_set_tls_field(drcontext, tls_idx_heapstat, (void *)pt);

    utils_thread_init(drcontext);
    ELOGF(0, f_global, "new thread #%d id=%d\n",
          which_thread, dr_get_thread_id(drcontext));
    if (!options.thread_logs) {
        f = f_global;
    } else {
        /* we're going to dump our data to a per-thread file */
        f = open_logfile("thread", false, which_thread/*tid suffix*/);
        LOGPT(1, PT_GET(drcontext), "thread logfile fd=%d\n", f);
    }
    utils_thread_set_file(drcontext, f);

    pt->errbufsz = MAX_ERROR_INITIAL_LINES + max_callstack_size();
    pt->errbuf = (char *) thread_alloc(drcontext, pt->errbufsz, HEAPSTAT_MISC);

    LOGPT(2, PT_GET(drcontext), "in event_thread_init()\n");
    callstack_thread_init(drcontext);
    if (options.check_leaks || options.staleness)
        shadow_thread_init(drcontext);
    if (options.staleness)
        instrument_thread_init(drcontext);
}

static void
event_thread_exit(void *drcontext)
{
    tls_heapstat_t *pt = (tls_heapstat_t *)
        drmgr_get_tls_field(drcontext, tls_idx_heapstat);
    LOGPT(2, PT_GET(drcontext), "in event_thread_exit()\n");
    if (options.staleness)
        instrument_thread_init(drcontext);
    callstack_thread_exit(drcontext);
    utils_thread_exit(drcontext);
    thread_free(drcontext, (void *) pt->errbuf, pt->errbufsz, HEAPSTAT_MISC);
    /* with PR 536058 we do have dcontext in exit event so indicate explicitly
     * that we've cleaned up the per-thread data
     */
    drmgr_set_tls_field(drcontext, tls_idx_heapstat, NULL);
    thread_free(drcontext, pt, sizeof(*pt), HEAPSTAT_MISC);
}

static bool
alloc_itercb_exit(malloc_info_t *info, void *iter_data)
{
    if (options.staleness)
        staleness_free_per_alloc((stale_per_alloc_t *)info->client_data);
    return true;
}

static void
event_exit(void)
{
    LOGF(2, f_global, "in event_exit\n");

    if (options.time_clock || options.staleness) {
        sideline_exit = true;
        if (options.thread_logs) {
            /* i#297: sideline_run never gets a chance to clean up so we do it */
            ASSERT(sideline_pt != NULL, "sideline per-thread error");
            global_free(sideline_pt, sizeof(*sideline_pt), HEAPSTAT_MISC);
        }
    }
    snapshot_exit();
    if (options.check_leaks) {
        check_reachability(true/*at_exit*/);
        leak_exit();
    }

    if (options.staleness)
        malloc_iterate(alloc_itercb_exit, NULL);

    alloc_exit(); /* must be before deleting alloc_stack_table */
    heap_region_exit(); /* must be after alloc_exit */
    LOG(1, "final alloc stack table size: %u bits, %u entries\n",
        alloc_stack_table.table_bits, alloc_stack_table.entries);
    hashtable_delete(&alloc_stack_table);
#ifdef CHECK_WITH_MD5
    hashtable_delete(&alloc_md5_table);
#endif
    callstack_exit();
    if (options.check_leaks || options.staleness) {
        instrument_exit();
        shadow_exit();
    }
    free_shared_code();
    utils_exit();

#ifdef USE_DRSYMS
    if (options.use_symcache)
        drsymcache_exit();
#endif

#ifdef STATISTICS
    dump_statistics();
#endif

    if (umbra_exit() != DRMF_SUCCESS)
        ASSERT(false, "fail to finalize umbra");
    if (drsys_exit() != DRMF_SUCCESS)
        ASSERT(false, "drsys failed to exit");
    drmgr_unregister_tls_field(tls_idx_heapstat);
    drwrap_exit();
    drmgr_exit();

    dr_fprintf(f_global, "LOG END\n");
    close_file(f_global);
    dr_fprintf(f_callstack, "LOG END\n");
    close_file(f_callstack);
    dr_fprintf(f_snapshot, "LOG END\n");
    close_file(f_snapshot);
    if (options.staleness) {
        dr_fprintf(f_staleness, "LOG END\n");
        close_file(f_staleness);
    }
    close_file(f_nudge);
}

DR_EXPORT void
dr_init(client_id_t client_id)
{
    const char *opstr = dr_get_options(client_id);
    alloc_options_t alloc_ops;
    drsys_options_t ops = { sizeof(ops), 0, };
    callstack_options_t callstack_ops = { sizeof(callstack_ops), 0 };
    drmgr_priority_t priority = {sizeof(priority), "drheapstat", NULL, NULL, 1000};

    dr_set_client_name("Dr. Heapstat", "http://drmemory.org/issues");

    ASSERT(opstr != NULL, "error obtaining option string");
    drheap_options_init(opstr);

    drmgr_init(); /* must be before utils_init and any other tls/cls uses */
    tls_idx_heapstat = drmgr_register_tls_field();
    ASSERT(tls_idx_heapstat > -1, "unable to reserve TLS slot");

    drwrap_init();
    utils_init();
    if (drsys_init(client_id, &ops) != DRMF_SUCCESS)
        ASSERT(false, "drsys failed to init");
    if (umbra_init(client_id) != DRMF_SUCCESS)
        ASSERT(false, "Umbra failed to init");

    /* now that we know whether -quiet, print basic info */
    NOTIFY("Dr. Heapstat version %s"NL, VERSION_STRING);
    NOTIFY("options are \"%s\""NL, opstr);

    create_global_logfile();
    LOG(0, "options are \"%s\"\n", opstr);

    dr_register_exit_event(event_exit);
    drmgr_register_thread_init_event(event_thread_init);
    drmgr_register_thread_exit_event(event_thread_exit);

    if (!drmgr_register_bb_instrumentation_ex_event
        (event_bb_app2app, event_bb_analysis, event_bb_insert,
         event_bb_instru2instru, &priority))
        ASSERT(false, "drmgr registration failed");
    drmgr_register_module_load_event(event_module_load);
    drmgr_register_module_unload_event(event_module_unload);
#ifdef UNIX
    dr_register_fork_init_event(event_fork);
#endif
    if (ZERO_STACK()) {
#ifdef UNIX
        drmgr_register_signal_event(event_signal);
#else
        drmgr_register_exception_event(event_exception);
#endif
    }

    dr_register_filter_syscall_event(event_filter_syscall);
    drmgr_register_pre_syscall_event(event_pre_syscall);
    drmgr_register_post_syscall_event(event_post_syscall);
    /* simplest to filter all for pre-syscall-arg access: else we'd
     * need to ask alloc for all that it cares about.
     */
    if (drsys_filter_all_syscalls() != DRMF_SUCCESS)
        ASSERT(false, "drsys_filter_all_syscalls should never fail");

    dr_register_nudge_event(event_nudge, client_id);
    if (options.staleness)
        drmgr_register_restore_state_ex_event(event_restore_state);
    /* DR complains if we have xl8 fields and faults w/o restore-state events */
    else if (ZERO_STACK())
        drmgr_register_restore_state_ex_event(event_restore_state_nop);
    if (options.staleness)
        dr_register_delete_event(event_fragment_delete);

    /* make it easy to tell, by looking at log file, which client executed */
    dr_log(NULL, LOG_ALL, 1, "client = Dr. Heapstat version %s\n", VERSION_STRING);

#ifdef USE_DRSYMS
    if (options.use_symcache) {
        if (!option_specified.symcache_dir) {
            dr_snprintf(options.symcache_dir, BUFFER_SIZE_ELEMENTS(options.symcache_dir),
                        "%s/symcache", options.logdir);
            NULL_TERMINATE_BUFFER(options.symcache_dir);
        }
        drsymcache_init(client_id, options.symcache_dir, 0);
    }
#endif

    snapshot_init();

    callstack_ops.global_max_frames = options.callstack_max_frames;
    callstack_ops.stack_swap_threshold = 0x10000;
    /* default flags: but if we have apps w/ DGC we may
     * want to expose some flags as options
     */
    callstack_ops.fp_flags = 0;
    /* scan forward 1 page: good compromise bet perf (scanning
     * can be the bottleneck) and good callstacks
     */
    callstack_ops.fp_scan_sz = PAGE_SIZE;
    /* XXX i#926: symbolize and suppress leaks online (and then
     * use options.callstack_style here)
     */
    callstack_ops.print_flags = PRINT_FOR_POSTPROCESS;
    callstack_ops.ignore_xbp = IF_WINDOWS_ELSE(is_in_seh_unwind, NULL);
    /* XXX: may need better callstack heuristics w/o shadow info
     * if user turns off stack zeroing from -leaks_only
     */
    callstack_ops.old_retaddrs_zeroed = options.zero_retaddr;
    callstack_ops.tool_lib_ignore = IF_WINDOWS_ELSE("drheapstatlib.dll",
                                                    "libdrheapstatlib.so*");
    callstack_ops.bad_fp_list = options.callstack_bad_fp_list;
    callstack_init(&callstack_ops);

    heap_region_init(client_heap_add, client_heap_remove);
    /* We keep callstacks around forever and only free when we delete
     * the alloc_stack_table, so no refcounts
     */

    /* must be before heap_walk() and alloc_init() */
    if (options.check_leaks || options.staleness)
        shadow_init();

    hashtable_init_ex(&alloc_stack_table, ASTACK_TABLE_HASH_BITS, HASH_CUSTOM,
                      false/*!str_dup*/, false/* !synch; + higher-level synch covered
                                               * by malloc_table's lock */,
                      alloc_callstack_free,
#ifdef USE_MD5
                      (uint (*)(void*)) md5_hash,
                      (bool (*)(void*, void*)) md5_digests_equal
#else
                      (uint (*)(void*)) crc32_whole_and_half_hash,
                      (bool (*)(void*, void*)) crc32_whole_and_half_equal
#endif
                      );
#ifdef CHECK_WITH_MD5
    hashtable_init_ex(&alloc_md5_table, ASTACK_TABLE_HASH_BITS, HASH_CUSTOM,
                      false/*!str_dup*/, false/* !synch; + higher-level synch covered
                                               * by malloc_table's lock */,
                      NULL/*points at md5 data stored in alloc_stack_table*/,
                      (uint (*)(void*)) md5_hash,
                      (bool (*)(void*, void*)) md5_digests_equal);
#endif

    memset(&alloc_ops, 0, sizeof(alloc_ops));
    alloc_ops.track_allocs = true;
    alloc_ops.track_heap = true;
    alloc_ops.redzone_size = 0; /* no redzone */
    alloc_ops.size_in_redzone = false;
    alloc_ops.record_allocs = true;
    alloc_ops.get_padded_size = true;
    alloc_ops.cache_postcall = false;
    alloc_ops.intercept_operators = false;
    alloc_ops.conservative = options.conservative;
    alloc_ops.global_lock = true; /* we want to serialize w/ our snapshots */
    alloc_ops.replace_malloc = true;
    alloc_ops.use_symcache = options.use_symcache;
    alloc_init(&alloc_ops, sizeof(alloc_ops));

    /* must be after heap_region_init and snapshot_init */
    heap_walk();

    if (options.check_leaks || options.staleness)
        instrument_init();

    create_shared_code();

    if (options.time_clock)
        timestamp_last_snapshot = dr_get_milliseconds();
    if (options.time_clock || options.staleness) {
        if (!dr_create_client_thread(sideline_run, NULL)) {
            ASSERT(false, "unable to create thread");
        }
    }

    if (options.check_leaks) {
        leak_init(false/*no defined info*/,
                  options.check_leaks_on_destroy,
                  options.midchunk_new_ok,
                  options.midchunk_inheritance_ok,
                  options.midchunk_string_ok,
                  options.midchunk_size_ok,
                  options.show_reachable,
                  IF_WINDOWS_(options.check_encoded_pointers)
                  NULL, NULL, NULL);
    }
}
