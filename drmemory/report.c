/* **********************************************************
 * Copyright (c) 2010-2016 Google, Inc.  All rights reserved.
 * Copyright (c) 2008-2010 VMware, Inc.  All rights reserved.
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
 * report.c: Dr. Memory error reporting
 */

#include "dr_api.h"
#ifdef USE_DRSYMS
# include "drsyms.h"
#endif
#include "drmemory.h"
#include "shadow.h"
#include "slowpath.h"
#include "syscall.h"
#include "alloc.h"
#include "report.h"
#include "callstack.h"
#include "heap.h"
#include "alloc_drmem.h"
#include "fuzzer.h"
#ifdef UNIX
# include <errno.h>
#endif
#include <limits.h>

#define FUZZER_MSG_SZ 0x100

static uint error_id; /* errors + leaks */
static uint error_id_potential; /* potential errors + leaks */

/* Global singletons.  Xref arrays over ERROR_SET_NUM below. */
static uint num_leaks_ignored;
static uint num_suppressions;
static uint num_suppressions_matched_user;
static uint num_suppressed_leaks_user;
static uint num_suppressions_matched_default;
static uint num_suppressed_leaks_default;
static uint num_throttled_errors;
static uint num_throttled_leaks;

static uint saved_leaks_ignored;
static uint saved_suppressed_leaks_user;
static uint saved_suppressed_leaks_default;
static uint saved_throttled_leaks;

static uint64 timestamp_start;

static bool report_exited;

typedef struct _tls_report_t {
    char *errbuf; /* buffer for atomic writes to global logfile */
    size_t errbufsz;
    /* for callstack shadow xl8 cache */
    umbra_shadow_memory_info_t xl8_info;
    /* cached values for module_is_on_check_uninit_blacklist() for i#1529 */
    app_pc last_query_mod_start;
    size_t last_query_mod_size;
    bool last_query_res;
} tls_report_t;

static int tls_idx_report = -1;

/***************************************************************************/
/* Store all errors so we can eliminate duplicates (PR 484167) */

enum {
    ERROR_NORMAL,
    /* i#1310: we separate probable false positives */
    ERROR_POTENTIAL,
    ERROR_SET_NUM,
};

#define ERROR_SET(potential) ((potential) ? ERROR_POTENTIAL : ERROR_NORMAL)

enum {
    ERROR_UNADDRESSABLE,
    ERROR_UNDEFINED,
    ERROR_INVALID_HEAP_ARG,
#ifdef WINDOWS
    ERROR_GDI_USAGE,
    ERROR_HANDLE_LEAK,
#endif
    ERROR_WARNING,
    ERROR_LEAK,
    ERROR_POSSIBLE_LEAK,
    ERROR_REACHABLE_LEAK,
    ERROR_MAX_LEAK = ERROR_REACHABLE_LEAK,
    ERROR_MAX_VAL,
};

static inline bool
type_is_leak(uint type)
{
    return (type >= ERROR_LEAK && type <= ERROR_MAX_LEAK);
}

static const char *const error_name[] = {
    "unaddressable access(es)",
    "uninitialized access(es)",
    "invalid heap argument(s)",
#ifdef WINDOWS
    "GDI usage error(s)",
    "handle leak(s)",
#endif
    "warning(s)",
    "leak(s)",
    "possible leak(s)",
    "still-reachable allocation(s)",
};

static const char *const suppress_name[] = {
    "UNADDRESSABLE ACCESS",
    "UNINITIALIZED READ",
    "INVALID HEAP ARGUMENT",
#ifdef WINDOWS
    "GDI USAGE ERROR",
    "HANDLE LEAK",
#endif
    "WARNING",
    "LEAK",
    "POSSIBLE LEAK",
    "REACHABLE LEAK",
};

#ifdef WINDOWS
/* When updating, change the -dump_at_error_mask docs as well */
static const uint error_mask[] = {
    0x0001, /* unaddressable access */
    0x0002, /* uninitialized access */
    0x0004, /* invalid heap argument */
    0x0008, /* GDI usage error */
    0x0010, /* handle leak */
    0x0020, /* warning */
    0x0040, /* leak */
    0x0080, /* possible leak */
    0x0100, /* still-reachable allocation */
};
#endif

#define DRMEM_VALGRIND_TOOLNAME "Dr.Memory"

/* The error_lock protects these as well as error_table */
static uint num_unique[ERROR_SET_NUM][ERROR_MAX_VAL];
static uint num_total[ERROR_SET_NUM][ERROR_MAX_VAL];

/* Leak-only stats.  For code simplicity we waste slots on non-leak types. */
static uint num_bytes_leaked[ERROR_SET_NUM][ERROR_MAX_VAL];
static uint saved_bytes_leaked[ERROR_SET_NUM][ERROR_MAX_VAL];
static uint saved_unique[ERROR_SET_NUM][ERROR_MAX_VAL];
static uint saved_total[ERROR_SET_NUM][ERROR_MAX_VAL];

/* Split only by normal vs potential */
static uint num_reported_errors[ERROR_SET_NUM];
static uint num_total_leaks[ERROR_SET_NUM];
static uint saved_total_leaks[ERROR_SET_NUM];

struct _suppress_spec_t;
typedef struct _suppress_spec_t suppress_spec_t;

/* Error report information.  These are not saved like stored_error_t, and are
 * only alive long enough to print an error report.
 */
typedef struct _error_toprint_t {
    /* Fields common to all errors. */
    uint errtype;               /* ERROR_* type: unaddr, uninit, etc. */
    app_loc_t *loc;             /* App location. */
    app_pc addr;                /* Access or alloc addr. */
    size_t sz;                  /* Access size or alloc size. */

    /* For unaddrs: */
    uint access_type;           /* DR_MEMPROT_* flag describing the access. */

    /* For unaddrs, uninits, and warnings: */
    bool report_instruction;    /* Whether to report instr. */

    /* For unaddrs, warnings, and invalid heap args: */
    bool report_neighbors;      /* Whether to report neighboring heap allocs. */
    byte *xsp;                  /* App xsp, if we have it. */
    /* Computed by gather_heap_info() and stored for report_heap_info(),
     * as well as for use by print_error_to_buffer():
     */
    bool on_heap, on_stack, use_after_free;
    byte *free_start, *next_start, *prev_end, *stack_base;
    size_t free_size, next_size, prev_size, stack_size;
    packed_callstack_t *neighbor_pcs;
    packed_callstack_t *free_pcs;

    /* For unaddrs and uninits: */
    app_pc container_start;     /* Container start. */
    app_pc container_end;       /* Container end. */

    /* For warnings and invalid heap args: */
    const char *msg;            /* Free-form message. */

    /* Auxiliary callstack and a prefix message describing it, with
     * INFO_PFX starting each msg line and aux_cstack_pfx starting each
     * callstack newline:
     */
    const char *aux_msg;
    packed_callstack_t *aux_pcs;

    /* For the state of any threads executing a fuzz target: */
    const char *fuzzer_msg;

    /* For leaks: */
    size_t indirect_size;       /* Size of indirect allocs. */
    const char *label;          /* Extra label (e.g., IGNORED). */

    /* For handle leaks */
    bool potential;             /* Whether a potential leak. */
} error_toprint_t;

/* Though any one instance of an address can have only one error
 * type, the same address could have multiple via different
 * executions.  Thus we must use a key combining the callstack and
 * the error type.
 */
typedef struct _stored_error_t {
    /* We can shrink some of these fields if memory is tight but we shouldn't
     * have more than a few thousand of these
     */
    uint id;
    uint errtype; /* from ERROR_ enum */
    uint count;
    bool suppressed;
    bool suppressed_by_default;
    bool potential;
    suppress_spec_t *suppress_spec;
    packed_callstack_t *pcs;
    /* We also keep a linked list so we can iterate in id order */
    struct _stored_error_t *next;
} stored_error_t;

/* We want to store extra data with each error callstack */
#define MAX_INSTR_DISASM 96
typedef struct _error_callstack_t {
    symbolized_callstack_t scs;
    char instruction[MAX_INSTR_DISASM];
    size_t bytes_leaked;
} error_callstack_t;

#define ERROR_HASH_BITS 8
hashtable_t error_table;
/* We need an outer lock to synchronize stored_error_t data access.
 * Since we never remove from error_table we could instead have
 * a lock per stored_error_t but we save space, assuming errors
 * are rare enough to not be a bottleneck.
 */
static void *error_lock;
/* We also keep a linked list so we can iterate in id order, but composed
 * of hashtable payloads so no separate free is necessary.
 * Protected by error_lock.
 */
static stored_error_t *error_head;
static stored_error_t *error_tail;

/* Only initializes the errtype field */
stored_error_t *
stored_error_create(uint type)
{
    stored_error_t *err = global_alloc(sizeof(*err), HEAPSTAT_REPORT);
    memset(err, 0, sizeof(*err));
    ASSERT(type < ERROR_MAX_VAL, "invalid error type");
    err->errtype = type;
    return err;
}

void
stored_error_free(stored_error_t *err)
{
    ASSERT(err != NULL, "invalid arg");
    if (err->pcs != NULL) {
        IF_DEBUG(uint ref = )
            packed_callstack_free(err->pcs);
        ASSERT(ref == 0, "invalid ref count");
    }
    global_free(err, sizeof(*err), HEAPSTAT_REPORT);
}

uint
stored_error_hash(stored_error_t *err)
{
    /* do NOT use id or count as they won't be filled out at lookup time */
    uint hash;
    ASSERT(err != NULL, "invalid arg");
    hash = packed_callstack_hash(err->pcs);
    hash ^= err->errtype;
    return hash;
}

bool
stored_error_cmp(stored_error_t *err1, stored_error_t *err2)
{
    /* do NOT use id or count as they won't be filled out at lookup time */
    ASSERT(err1 != NULL && err2 != NULL, "invalid arg");
    if (err1->errtype != err2->errtype)
        return false;
    return (packed_callstack_cmp(err1->pcs, err2->pcs));
}

/* We use a different prefix for the callstack, for Visual Studio (i#800) */
static const char *info_cstack_pfx;
static const char *aux_cstack_pfx;

/* To provide thread callstacks (i#312), we don't want to symbolize and
 * print at thread creation time b/c the symbolization is a noticeable
 * perf hit on runs with no errors (i#714).  Thus we store a callstack
 * and only symbolize when an error is reported for that thread.
 */
#define THREAD_HASH_BITS 6
/* Key is thread id, payload is packed_callstack_t * */
static hashtable_t thread_table;
static void *thread_table_lock;
static thread_id_t main_thread;
static bool main_thread_printed;

static void
report_delayed_thread(thread_id_t tid);

static void
report_main_thread(void);

static void
print_error_to_buffer(char *buf, size_t bufsz, error_toprint_t *etp,
                      stored_error_t *err, error_callstack_t *ecs,
                      bool for_log);
#ifdef DEBUG
static void
print_double_null_term_string(const char *s, const char *sep);
#endif

/***************************************************************************
 * suppression list
 */

/* For each error type, we have a list of callstacks, with each
 * callstack a list of frames
 */
typedef struct _suppress_frame_t {
    bool is_ellipsis; /* "..." wildcard, can be combined with modname (i#738) */
    bool is_star;     /* "*" wildcard (i#527) */
    bool is_module;
    char *modname;
    char *modoffs; /* string b/c we allow wildcards in it */
    char *func;
    struct _suppress_frame_t *next;
} suppress_frame_t;

struct _suppress_spec_t {
    int type;
    /* these 3 fields are for reporting which suppressions were used (i#50) */
    uint num;
    char *name;
    uint count_used;
    char *instruction; /* i#498 */
    uint num_frames;
    suppress_frame_t *frames;
    suppress_frame_t *last_frame;
    bool is_default; /* from default file, or user-specified? */
    bool is_memcheck_syscall;
    size_t bytes_leaked;
    /* During initial reading it's easier to build a linked list.
     * We could convert to an array after reading both suppress files,
     * but we have pointers scattered all over anyway so we leave it a
     * list.
     */
    struct _suppress_spec_t *next;
};

/* We suppress error type separately (PR 507837) */
static suppress_spec_t *supp_list[ERROR_MAX_VAL];
static uint supp_num[ERROR_MAX_VAL];
static bool have_module_wildcard;

#ifdef USE_DRSYMS
static void *suppress_file_lock;
#endif

static void
error_callstack_init(error_callstack_t *ecs)
{
    ecs->scs.num_frames = 0;
    ecs->scs.frames = NULL;
    ecs->instruction[0] = '\0';
    ecs->bytes_leaked = 0;
}

static int
get_suppress_type(const char *line)
{
    int i;
    ASSERT(line != NULL, "invalid param");
    if (line[0] == '\0')
        return -1;
    /* Perf: we could stick the 6 names in a hashtable */
    for (i = 0; i < ERROR_MAX_VAL; i++) {
        const char *start =  strstr(line, suppress_name[i]);
        if (start == line ||
            /* Support "Dr.Memory:<type>" for legacy format */
            (start == line + strlen(DRMEM_VALGRIND_TOOLNAME) + 1/*":"*/ &&
             strstr(line, DRMEM_VALGRIND_TOOLNAME) == line))
            return i;
    }
    return -1;
}

#define INCORRECT_FRAME_MSG \
    "The last frame is incorrect!"NL NL\
    "Frames should be one of the following:"NL\
    " module!function"NL\
    " module!..."NL\
    " <module+0xhexoffset>"NL\
    " <not in a module>"NL\
    " system call Name"NL\
    " *"NL\
    " ..."

static void
report_malformed_suppression(const char *orig_start,
                             const char *orig_end,
                             const char *message)
{
    NOTIFY("Malformed suppression:"NL"%.*s"NL"%s"NL,
           orig_end - orig_start, orig_start, message);
    usage_error("Malformed suppression. See the log file for the details", "");
}

static suppress_spec_t *
suppress_spec_create(int type, bool is_default)
{
    suppress_spec_t *spec;
    spec = (suppress_spec_t *) global_alloc(sizeof(*spec), HEAPSTAT_REPORT);
    LOG(2, "parsing suppression %d of type %s\n", num_suppressions,
        suppress_name[type]);
    spec->type = type; /* may be -1 initially for Valgrind format */
    spec->count_used = 0;
    spec->is_default = is_default;
    spec->bytes_leaked = 0;
    spec->name = NULL; /* for i#50 NYI */
    spec->num = num_suppressions;
    spec->instruction = NULL;
    spec->num_frames = 0;
    spec->frames = NULL;
    spec->last_frame = NULL;
    spec->next = NULL;
    return spec;
}

#ifdef DEBUG
static void
suppress_frame_print(file_t f, const suppress_frame_t *frame, const char *prefix)
{
    ASSERT(frame != NULL, "invalid arg");
    ELOGF(0, f, "%s: ", prefix);
    if (frame->is_ellipsis && frame->modname == NULL)
        ELOGF(0, f, "...\n");
    else if (frame->is_star)
        ELOGF(0, f, "*\n");
    else if (!frame->is_module)
        ELOGF(0, f, "%s\n", frame->func);
    else {
        if (frame->func == NULL && !frame->is_ellipsis)
            ELOGF(0, f, "<");
        if (frame->modname != NULL)
            ELOGF(0, f, "%s", frame->modname);
        if (frame->func != NULL)
            ELOGF(0, f, "!%s\n", frame->func);
        else if (frame->is_ellipsis)
            ELOGF(0, f, "!...\n");
        else
            ELOGF(0, f, "+%s>\n", frame->modoffs);
    }
}
#endif

static void
suppress_frame_free(suppress_frame_t *frame)
{
    if (frame->modname != NULL)
        global_free(frame->modname, strlen(frame->modname)+1, HEAPSTAT_REPORT);
    if (frame->modoffs != NULL)
        global_free(frame->modoffs, strlen(frame->modoffs)+1, HEAPSTAT_REPORT);
    if (frame->func != NULL)
        global_free(frame->func, strlen(frame->func)+1, HEAPSTAT_REPORT);
    global_free(frame, sizeof(*frame), HEAPSTAT_REPORT);
}

static void
suppress_spec_free(suppress_spec_t *spec)
{
    suppress_frame_t *frame, *next;
    for (frame = spec->frames; frame != NULL; frame = next) {
        next = frame->next;
        suppress_frame_free(frame);
    }
    if (spec->name != NULL)
        global_free(spec->name, strlen(spec->name)+1, HEAPSTAT_REPORT);
    if (spec->instruction != NULL)
        global_free(spec->instruction, strlen(spec->instruction)+1, HEAPSTAT_REPORT);
    global_free(spec, sizeof(*spec), HEAPSTAT_REPORT);
}

/* Return true if the suppression has a single frame covering an entire module.
 * We can handle single frame expressions that match the current instruction.
 */
static bool
is_module_wildcard(suppress_spec_t *spec)
{
    return (spec->num_frames == 1 &&
            spec->instruction == NULL &&
            spec->frames[0].is_module &&
            spec->frames[0].func != NULL &&
            spec->frames[0].func[0] == '*' &&
            spec->frames[0].func[1] == '\0');
}

static suppress_spec_t *
suppress_spec_finish(suppress_spec_t *spec,
                     const char *orig_start,
                     const char *orig_end)
{
    ASSERT(spec->type >= 0 && spec->type < ERROR_MAX_VAL, "internal error type error");
    if (spec->frames == NULL) {
        report_malformed_suppression(orig_start, orig_end,
                                     "The given suppression ends with '...'");
        ASSERT(false, "should not reach here");
    }
    if (spec->last_frame->is_ellipsis) {
        report_malformed_suppression(orig_start, orig_end,
                                     "The given suppression ends with '...'");
        ASSERT(false, "should not reach here");
    }
    LOG(3, "added suppression #%d of type %s\n", spec->num, suppress_name[spec->type]);
    /* insert into list */
    spec->next = supp_list[spec->type];
    supp_list[spec->type] = spec;
    supp_num[spec->type]++;
    num_suppressions++;
    if (is_module_wildcard(spec)) {
        have_module_wildcard = true;
        if (spec->type == ERROR_UNDEFINED && options.check_uninitialized) {
            /* i#1529: auto-add to the check_uninit_blacklist, which has already
             * been converted from commas to null-separated, double-null-terminated.
             * We assume no synch is needed as this is init time.
             */
            size_t len;
            char *c = options.check_uninit_blacklist;
            while (*c != '\0')
                c += strlen(c) + 1/*skip 1st null*/;
            len = c - options.check_uninit_blacklist;
            dr_snprintf(c, BUFFER_SIZE_ELEMENTS(options.check_uninit_blacklist) - len,
                        "%s", spec->frames[0].modname);
            len = strlen(c);
            if (c + len + 1 - options.check_uninit_blacklist <
                BUFFER_SIZE_ELEMENTS(options.check_uninit_blacklist))
                *(c + len + 1) = '\0';
            NULL_TERMINATE_BUFFER(options.check_uninit_blacklist); /* paranoid */
            LOG(1, "Found whole-module supp: added %s to -check_uninit_blacklist\n",
                spec->frames[0].modname);
            DOLOG(2, {
                LOG(2, "Blacklist is now: ");
                print_double_null_term_string(options.check_uninit_blacklist, ", ");
                LOG(2, "\n");
            });
        }
    }
    return spec;
}

/* Returns whether this line is a prefix line before the callstack frames */
static bool
suppress_spec_prefix_line(suppress_spec_t *spec, const char *cstack_start,
                          const char *line_in, size_t line_len, int brace_line,
                          const char *line, bool *skip OUT)
{
    const char *c;
    if (skip != NULL)
        *skip = false;

    /* look for top-level spec lines.  we could disallow once callstack starts
     * but I'm not bothering.
     */
    if (brace_line == 1) {
        /* Valgrind format: this is the name */
        spec->name = drmem_strdup(line, HEAPSTAT_REPORT);
        LOG(3, "  suppression name=\"%s\"\n", spec->name);
        return true;
    } else if (brace_line == 2) {
        /* Valgrind format: this is the error type.
         * We don't have a perfect mapping here.
         */
        ASSERT(spec->type == -1, "duplicate error types");
        /* Support "Dr.Memory:<type>" mixed format */
        spec->type = get_suppress_type(line);
        if (spec->type > -1) {
            return true;
        } else if (strstr(line, "Memcheck:") != line) {
            /* Not a Memcheck type */
            if (skip != NULL)
                *skip = true;
            return true;
        } else if (strstr(line, "Memcheck:Addr") == line ||
                   strcmp(line, "Memcheck:Jump") == 0) {
            /* We ignore the {1,2,4,8,16} after Addr */
            spec->type = ERROR_UNADDRESSABLE;
            return true;
        } else if (strstr(line, "Memcheck:Value") == line ||
                   strcmp(line, "Memcheck:Cond") == 0) {
            /* We ignore the {1,2,4,8,16} after Value */
            spec->type = ERROR_UNDEFINED;
            return true;
        } else if (strcmp(line, "Memcheck:Param") == 0) {
            /* XXX: is Param used for unaddr syscall params too? */
            spec->type = ERROR_UNDEFINED;
            spec->is_memcheck_syscall = true;
            return true;
        } else if (strcmp(line, "Memcheck:Leak") == 0) {
            spec->type = ERROR_LEAK;
            return true;
        } else if (strcmp(line, "Memcheck:Free") == 0) {
            spec->type = ERROR_INVALID_HEAP_ARG;
            return true;
        } else if (strcmp(line, "Memcheck:Overlap") == 0) {
            /* XXX i#156: NYI: stick in warning list for now */
            spec->type = ERROR_WARNING;
            return true;
        } else {
            report_malformed_suppression(cstack_start, line_in + line_len,
                                         "Unknown Valgrind/Memcheck error type");
            ASSERT(false, "should not reach here");
        }
    }

    /* Dr. Memory format, or instruction= added to Valgrind format */
    c = strchr(line, '=');
    if (c != NULL) {
        if (strstr(line, "name=") == line) { /* we allow in Valgrind format */
            spec->name = drmem_strndup(c + 1, line_len - (c + 1 - line), HEAPSTAT_REPORT);
            LOG(3, "  suppression name=\"%s\"\n", spec->name);
            return true;
        } else if (strstr(line, "instruction=") == line) {
            if (spec->type == ERROR_UNADDRESSABLE || spec->type == ERROR_UNDEFINED ||
                spec->type == ERROR_WARNING/*prefetch warning*/) {
                spec->instruction = drmem_strndup(c + 1, line_len - (c + 1 - line),
                                                  HEAPSTAT_REPORT);
                LOG(3, "  instruction=\"%s\"\n", spec->instruction);
                return true;
            } else {
                report_malformed_suppression(cstack_start, line_in + line_len,
                                             "Only unaddressable accesses and "
                                             "uninitialized reads can specify an "
                                             "instruction= field");
                ASSERT(false, "should not reach here");
            }
        }
    }
    return false;
}

/* Returns whether to keep the suppression, based on this frame */
static bool
suppress_spec_add_frame(suppress_spec_t *spec, const char *cstack_start,
                        const char *line_in, size_t line_len, int brace_line)
{
    suppress_frame_t *frame;
    IF_NOT_DRSYMS(bool has_symbols = false;)
    const char *line;
    bool skip_supp = false;

    /* make a local copy that ends in \0 so we can use strchr, etc. */
    line = drmem_strndup(line_in, line_len, HEAPSTAT_REPORT);

    if (suppress_spec_prefix_line(spec, cstack_start, line_in, line_len,
                                  brace_line, line, &skip_supp))
        goto add_frame_done;

    spec->num_frames++;
    if (spec->num_frames >= options.callstack_max_frames) {
        /* we truncate suppression callstacks to match requested max */
        DO_ONCE({
            WARN("WARNING: requested max frames truncates suppression callstacks\n");
        });
        goto add_frame_done;
    }

    frame = global_alloc(sizeof(*frame), HEAPSTAT_REPORT);
    memset(frame, 0, sizeof(*frame));

    if (brace_line > -1) { /* Valgrind format */
        if (strstr(line, "fun:") == line) {
            /* Valgrind format fun:sym => *!sym */
            /* FIXME i#282: Valgrind C++ symbols are mangled.  We need to note
             * whether any suppression of a particular type has Valgrind
             * suppressions, and if so, make both a mangled and unmangled version
             * of the callstack.  We do not support mixed Valgrind and DrMem
             * frames within one callstack.  If there are no wildcards in the
             * frames, we could unmangle here (requires DRi#545).
             */
            IF_NOT_DRSYMS(has_symbols = true;)
            frame->is_module = true;
            frame->modname = drmem_strdup("*", HEAPSTAT_REPORT);
            frame->func = drmem_strdup(line + strlen("fun:"), HEAPSTAT_REPORT);
        } else if (strstr(line, "obj:") == line) {
            /* Valgrind format obj:mod => mod!* */
            IF_NOT_DRSYMS(has_symbols = true;)
            frame->is_module = true;
            frame->modname = drmem_strdup(line + strlen("obj:"), HEAPSTAT_REPORT);
            frame->func = drmem_strdup("*", HEAPSTAT_REPORT);
        } else if (strstr(line, "...") == line) {
            frame->is_ellipsis = true;
        } else if (strstr(line, "*") == line) {
            frame->is_star = true;
        } else if (spec->is_memcheck_syscall && spec->num_frames == 1) {
            /* 1st frame of Memcheck:Param can be syscall name + args.
             * Often has params which we don't want: "epoll_ctl(epfd)"
             */
            const char *stop = strchr(line, '(');
            ASSERT(!frame->is_module, "incorrect initialization");
            frame->func = drmem_strndup(line_in,
                                        (stop != NULL) ? stop - line: line_len,
                                        HEAPSTAT_REPORT);
        } else {
            report_malformed_suppression(cstack_start, line_in + line_len,
                                         "Unknown frame in Valgrind-style callstack");
            ASSERT(false, "should not reach here");
        }
    } else if (line[0] == '<' && strchr(line, '+') != NULL &&
               /* we assume module doesn't have ! in its name */
               strchr(line, '>') != NULL && strchr(line, '!') == NULL) {
        const char *plus = strchr(line, '+');
        frame->is_module = true;
        frame->modname = drmem_strndup(line + 1/*skip '<'*/, plus - (line + 1),
                                       HEAPSTAT_REPORT);
        frame->modoffs = drmem_strndup(plus + 1, strchr(line, '>') - (plus + 1),
                                       HEAPSTAT_REPORT);
        if (strlen(frame->modoffs) < 3 ||
            frame->modoffs[0] != '0' ||
            frame->modoffs[1] != 'x') {
            report_malformed_suppression(cstack_start, line_in + line_len,
                                         INCORRECT_FRAME_MSG);
            ASSERT(false, "should not reach here");
        }
    } else if (strchr(line, '!') != NULL && line[0] != '<') {
        /* note that we can't exclude any + ("operator+") or < (templates) */
        const char *bang = strchr(line, '!');
        IF_NOT_DRSYMS(has_symbols = true;)
        frame->is_module = true;
        frame->modname = drmem_strndup(line, bang - line, HEAPSTAT_REPORT);
        if (strstr(bang + 1, "...") == bang + 1) {
            frame->is_ellipsis = true;
        } else {
            frame->func = drmem_strndup(bang + 1, line_len - (bang + 1 - line),
                                        HEAPSTAT_REPORT);
        }
    } else if (strcmp(line, "<not in a module>") == 0) {
        ASSERT(!frame->is_module, "incorrect initialization");
        frame->func = drmem_strndup(line_in, line_len, HEAPSTAT_REPORT);
    } else if (strcmp(line, "...") == 0) {
        frame->is_ellipsis = true;
    } else if (strcmp(line, "*") == 0) {
        frame->is_star = true;
    } else if (strstr(line, "system call ") != NULL) {
        ASSERT(!frame->is_module, "incorrect initialization");
        frame->func = drmem_strndup(line_in, line_len, HEAPSTAT_REPORT);
    } else {
        report_malformed_suppression(cstack_start, line_in + line_len,
                                     INCORRECT_FRAME_MSG);
        ASSERT(false, "should not reach here");
    }

     DOLOG(3, {
         suppress_frame_print(LOGFILE_LOOKUP(), frame, "  added suppression frame");
     });

    /* insert */
    if (spec->last_frame != NULL)
        spec->last_frame->next = frame;
    spec->last_frame = frame;
    if (spec->frames == NULL)
        spec->frames = frame;

 add_frame_done:
    global_free((byte *)line, strlen(line) + 1, HEAPSTAT_REPORT);
    return !skip_supp && IF_DRSYMS_ELSE(true, !has_symbols);
}

static void
read_suppression_file(file_t f, bool is_default)
{
    const char *line, *newline, *next_line, *eof;
    suppress_spec_t *spec = NULL;
    const char *cstack_start;
    int type;
    bool skip_suppression = false;
    int brace_line = -1;
    bool new_error = false;

    /* we avoid having to do our own buffering by just mapping the whole file */
    uint64 map_size;
    size_t actual_size;
    bool ok = dr_file_size(f, &map_size);
    void *map = NULL;
    if (ok) {
        actual_size = (size_t) map_size;
        ASSERT(actual_size == map_size, "file size too large");
        map = dr_map_file(f, &actual_size, 0, NULL, DR_MEMPROT_READ, 0);
    }
    if (!ok || map == NULL || actual_size < map_size) {
        const char *label = (is_default) ? "default" : "user";
        if (map != NULL)
            dr_unmap_file(map, actual_size);
        NOTIFY_ERROR("Error mapping %s suppression file"NL, label);
        return;
    }

    cstack_start = (char *) map;
    eof = ((char *) map) + map_size;
    for (line = (char *) map; line < eof; line = next_line) {
        /* We trim trailing whitespace (i#381) and skip leading whitespace (mainly to
         * support Valgrind format)
         */
        next_line = find_next_line(line, eof, &line, &newline, true);
        /* Skip blank and comment lines */
        if (line == newline || line[0] == '#')
            continue;
        LOG(4, "suppression file line: \"%.*s\"\n", newline - line, line);
        /* Support both Dr. Memory-style (starts w/ error type name) and
         * brace-delimited Valgrind-style
         */
        new_error = false;
        if (brace_line == -1) {
            type = get_suppress_type(line); /* error type is start of drmem supp */
            if (type > -1)
                new_error = true;
            else if (line[0] == '{') {
                new_error = true;
                brace_line = 0;
                DO_ONCE({
                    /* There is no script for Windows (nobody has Valgrind
                     * suppressions on Windows except WINE users) so we can't say
                     * "use script": for Linux we rely on postprocess saying that
                     */
                    NOTIFY("WARNING: Deprecated legacy limited Valgrind suppression format detected.  Please convert to the more-powerful supported Dr. Memory format."NL);
                });
            }
        } else if (line[0] == '}') {
            brace_line = -1;
            continue;
        } else
            brace_line++;
        if (new_error) {
            if (spec != NULL) {
                if (!skip_suppression)
                    suppress_spec_finish(spec, cstack_start, line - 1);
                else
                    suppress_spec_free(spec);
            }
            /* A new callstack */
            cstack_start = line;
            spec = suppress_spec_create(type, is_default);
            skip_suppression = false;
        } else if (spec != NULL) {
            if (!suppress_spec_add_frame(spec, cstack_start, line, newline - line,
                                        brace_line))
                skip_suppression = true;
        } else {
            report_malformed_suppression(cstack_start, newline, INCORRECT_FRAME_MSG);
            ASSERT(false, "should not reach here");
        }
    }
    if (spec != NULL) {
        if (!skip_suppression)
            suppress_spec_finish(spec, cstack_start, line - 1);
        else
            suppress_spec_free(spec);
    }
    dr_unmap_file(map, actual_size);
}

static void
open_and_read_suppression_file(const char *fname, bool is_default)
{
#ifdef USE_DRSYMS
    uint prev_suppressions = num_suppressions;
#endif
    const char *label = (is_default) ? "default" : "user";
    if (fname == NULL || fname[0] == '\0') {
        dr_fprintf(f_global, "No %s suppression file specified\n", label);
    } else {
        file_t f = dr_open_file(fname, DR_FILE_READ);
        if (f == INVALID_FILE) {
            NOTIFY_ERROR("Error opening %s suppression file %s"NL, label, fname);
            dr_abort();
            return;
        }
        read_suppression_file(f, is_default);
#ifdef USE_DRSYMS
        /* Don't print to stderr about default suppression file, and don't print
         * at all when postprocess is handling all the symbolic stacks.  Also
         * don't print if the user passed -no_summary, or we'll get this for
         * every subprocess.
         */
        NOTIFY_COND(options.summary && !is_default, f_global,
                    "Recorded %d suppression(s) from %s %s"NL,
                    num_suppressions - prev_suppressions, label, fname);
        ELOGF(0, f_results, "Recorded %d suppression(s) from %s %s"NL,
              num_suppressions - prev_suppressions, label, fname);
#endif
        dr_close_file(f);
    }
}

#ifdef USE_DRSYMS
/* up to caller to lock f_results file */
static void
write_suppress_pattern(uint type, symbolized_callstack_t *scs, bool symbolic, uint id)
{
    int i;
    ASSERT(type >= 0 && type < ERROR_MAX_VAL, "invalid error type");
    ASSERT(scs != NULL, "invalid param");

    dr_fprintf(f_suppress, "%s"NL, suppress_name[type]);
    dr_fprintf(f_suppress, "name=Error #%d (update to meaningful name)"NL, id);

    for (i = 0; i < scs->num_frames; i++) {
        if (symbolized_callstack_frame_is_module(scs, i)) {
            if (symbolic) {
                char *func = symbolized_callstack_frame_func(scs, i);
                /* i#285: replace ? with * */
                if (strcmp(func, "?") == 0)
                    func = "*";
                dr_fprintf(f_suppress, "%s!%s"NL,
                           symbolized_callstack_frame_modname(scs, i), func);
            } else {
                dr_fprintf(f_suppress, "<%s+%s>"NL,
                           symbolized_callstack_frame_modname(scs, i),
                           symbolized_callstack_frame_modoffs(scs, i));
            }
        } else {
            dr_fprintf(f_suppress, "%s"NL,
                       symbolized_callstack_frame_func(scs, i));
        }
    }
}
#endif

static void
report_error_suppression(uint type, error_callstack_t *ecs, uint id)
{
#ifdef USE_DRSYMS /* else reported in postprocessing */
    if (!options.gen_suppress_syms && !options.gen_suppress_offs)
        return;
    /* write supp patterns to f_suppress */
    dr_mutex_lock(suppress_file_lock);
    /* XXX: if both -no_gen_suppress_offs and -no_gen_suppress_syms we
     * could not create any file at all: for now we create an empty
     * file for simplicity
     */
    dr_fprintf(f_suppress, "# Suppression for Error #%d"NL, id);
    if (options.gen_suppress_syms)
        write_suppress_pattern(type, &ecs->scs, true/*mod!func*/, id);
    if (options.gen_suppress_offs) {
        if (options.gen_suppress_syms)
            dr_fprintf(f_suppress, "\n## Mod+offs-style suppression for Error #%d:"NL, id);
        write_suppress_pattern(type, &ecs->scs, false/*mod+offs*/, id);
    }
    dr_fprintf(f_suppress, ""NL);
    dr_mutex_unlock(suppress_file_lock);
#endif
}

/* Match a frame's module name against a suppression frame's module name.
 */
static bool
frame_matches_modname(const error_callstack_t *ecs, uint idx,
                      const suppress_frame_t *supp)
{
    ASSERT(supp != NULL && supp->is_module && supp->modname != NULL,
           "Must have a suppression with a modname!");
    return text_matches_pattern(symbolized_callstack_frame_modname(&ecs->scs, idx),
                                supp->modname, FILESYS_CASELESS);
}

static bool
top_frame_matches_suppression_frame(const error_callstack_t *ecs,
                                    uint idx,
                                    const suppress_frame_t *supp)
{
    DOLOG(4, {
        LOG(4, "  comparing error frame %d ", idx);
        suppress_frame_print(LOGFILE_LOOKUP(), supp, "to suppression frame");
    });
    if (idx >= ecs->scs.num_frames)
        return false;

    if (supp->is_ellipsis) {
        if (supp->is_module) {
            /* i#738: mod!... only matches if the modules match. */
            return frame_matches_modname(ecs, idx, supp);
        } else {
            return true;  /* Plain ellipsis matches every frame. */
        }
    }

    /* "*" matches everything ("*!*" only matches module frames) (i#527) */
    if (supp->is_star)
        return true;

    if (!supp->is_module) {
        return (!symbolized_callstack_frame_is_module(&ecs->scs, idx) &&
                text_matches_pattern(symbolized_callstack_frame_func(&ecs->scs, idx),
                                     supp->func, false/*consider case*/));
    }

    if (supp->func == NULL) {
        /* "<mod+offs>" suppression frame */
        if (!symbolized_callstack_frame_is_module(&ecs->scs, idx))
            return false;
        return (frame_matches_modname(ecs, idx, supp) &&
                text_matches_pattern(symbolized_callstack_frame_modoffs(&ecs->scs, idx),
                                     supp->modoffs, true/*ignore case*/));
    } else {
        /* "mod!fun" suppression frame */
        const char *func = symbolized_callstack_frame_func(&ecs->scs, idx);
        if (!symbolized_callstack_frame_is_module(&ecs->scs, idx) || func == NULL)
            return false;
#ifndef USE_DRSYMS
        if ((func[0] == '?' && func[1] == '\0')) {
            /* in-client frames don't have mod!fun */
            return false;
        }
#endif
        LOG(4, "  error frame for cmp: %s!%s\n",
            symbolized_callstack_frame_modname(&ecs->scs, idx),
            symbolized_callstack_frame_func(&ecs->scs, idx));
        return (frame_matches_modname(ecs, idx, supp) &&
                text_matches_pattern(func, supp->func, false/*consider case*/));
    }
}

static bool
stack_matches_suppression(const error_callstack_t *ecs, const suppress_spec_t *spec)
{
    uint i;
    int scs_last_ellipsis = -1;
    suppress_frame_t *cur_ellipsis_supp = NULL;
    suppress_frame_t *supp = spec->frames;

    /* i#498: allow restricting by instruction */
    if (spec->instruction != NULL) {
        if (!text_matches_pattern(ecs->instruction, spec->instruction,
                                  false/*consider case*/)) {
            LOG(4, "  supp: instruction \"%s\" != \"%s\"\n",
                ecs->instruction, spec->instruction);
            return false;
        }
    }

    for (i = 0; i < ecs->scs.num_frames; i++) {
        if (supp == NULL) {
            /* PR 460923: pattern is considered a prefix.
             * suppression has matched the top of the stack.
             */
            return true;
        } else if (top_frame_matches_suppression_frame(ecs, i, supp)) {
            if (supp->is_ellipsis) {
                cur_ellipsis_supp = supp;
                supp = supp->next;
                /* we should have aborted when parsing */
                ASSERT(supp != NULL, "Suppression ends with '...'");
                scs_last_ellipsis = i;
                i--; /* counteract for's ++ */
            } else {
                supp = supp->next;
            }
        } else if (scs_last_ellipsis > -1 &&
                   (!cur_ellipsis_supp->is_module ||
                    frame_matches_modname(ecs, i, cur_ellipsis_supp))) {
            /* We didn't match the next suppression frame, but we did match to
             * the current open ellipsis.
             */
            scs_last_ellipsis++;
            i = scs_last_ellipsis - 1; /* counteract for's ++ */
        } else if (i == 0 && options.replace_malloc &&
                   text_matches_pattern(symbolized_callstack_frame_func(&ecs->scs, i),
                                        "replace_*", false/*consider case*/) &&
                   text_matches_pattern(symbolized_callstack_frame_modname(&ecs->scs, i),
                                        DRMEMORY_LIBNAME, FILESYS_CASELESS)) {
            /* To support swapping between wrapping and replacing, we ignore
             * mismatches of replacing's top replace_ frame (i#1189).
             */
            LOG(4, "  skipping top replace_ frame\n");
        } else if (i == 0 && !options.replace_malloc && supp->func != NULL &&
                   text_matches_pattern(supp->func,
                                        "replace_*", false/*consider case*/) &&
                   text_matches_pattern(supp->modname,
                                        DRMEMORY_LIBNAME, FILESYS_CASELESS)) {
            /* The other direction: a suppression frame for replace_*
             * yet we're running with wrapping (in case we have to
             * turn off -replace_malloc) (i#1189).
             */
            LOG(4, "  skipping top replace_ suppress frame\n");
            supp = supp->next;
            i--; /* counteract for's ++ */
        } else {
            return false;
        }
    }
    LOG(3, "supp: callstack ended => prefix %smatch\n", supp == NULL ? "" : "mis");
    return (supp == NULL);
}

static bool
on_suppression_list_helper(uint type, error_callstack_t *ecs,
                           suppress_spec_t **matched OUT)
{
    suppress_spec_t *spec;
    ASSERT(type >= 0 && type < ERROR_MAX_VAL, "invalid error type");
    for (spec = supp_list[type]; spec != NULL; spec = spec->next) {
        DOLOG(3, {
            suppress_frame_print(LOGFILE_LOOKUP(), spec->frames,
                                 "supp: comparing error to suppression pattern");
        });
        if (stack_matches_suppression(ecs, spec)) {
            LOG(3, "matched suppression %s\n",
                (spec->name == NULL) ? "<no name>" : spec->name);
            if (matched != NULL)
                *matched = spec;
            spec->count_used++;
            if (type_is_leak(type))
                spec->bytes_leaked += ecs->bytes_leaked;
            return true;
        }
    }
    return false;
}

static bool
on_suppression_list(uint type, error_callstack_t *ecs, suppress_spec_t **matched OUT)
{
    ASSERT(type >= 0 && type < ERROR_MAX_VAL, "invalid error type");
    if (on_suppression_list_helper(type, ecs, matched))
        return true;
    /* qualified leak reports should be checked against LEAK suppressions */
    if (type_is_leak(type) && type != ERROR_LEAK) {
        if (on_suppression_list_helper(ERROR_LEAK, ecs, matched))
            return true;
    }
    LOG(3, "supp: no match\n");
    return false;
}

/* Returns true if we have a whole-module suppression of the same type covering
 * the app pc.  Updates the suppression usage counts if it does.
 */
static bool
report_in_suppressed_module(uint type, app_loc_t *loc, const char *instruction)
{
    suppress_spec_t *spec;
    bool suppressed = false;
    const char *preferred_name;

    /* We don't handle leaks because they're not usually suppressed with a
     * single module wildcard and we need to update the suppression with the
     * number of bytes leaked.
     */
    if (type >= ERROR_LEAK)
        return false;
    if (loc->type != APP_LOC_PC || !loc->u.addr.valid)
        return false;
    /* Not worth checking for it if we don't have one of these suppressions. */
    if (!have_module_wildcard)
        return false;
    preferred_name = module_lookup_preferred_name(loc->u.addr.pc);
    if (preferred_name == NULL)
        return false;

    /* We could hook module load and maintain an rb interval tree of which
     * regions were suppressed to avoid this extra supp_list iteration.
     */
    for (spec = supp_list[type]; spec != NULL; spec = spec->next) {
        if (is_module_wildcard(spec) &&
            text_matches_pattern(preferred_name, spec->frames[0].modname,
                                 FILESYS_CASELESS) &&
            (spec->instruction == NULL ||
             text_matches_pattern(instruction, spec->instruction,
                                  /*ignore_case=*/false))) {
            suppressed = true;
            dr_mutex_lock(error_lock);
            if (spec->is_default)
                num_suppressions_matched_default++;
            else
                num_suppressions_matched_user++;
            /* spec->count_used is now a total and not unique (i#1527) which is good
             * b/c we don't have the callstack here to check unique.
             */
            spec->count_used++;
            dr_mutex_unlock(error_lock);
            LOG(3, "matched whole module suppression %s\n", spec->name);
       }
    }
    return suppressed;
}

/***************************************************************************
 * Callstack per-module data
 */

typedef struct _per_callstack_module_t {
    bool on_blacklist;
    bool on_whitelist;
    bool in_tool;
    bool on_check_uninit_blacklist;
} per_callstack_module_t;

static void *
callstack_module_load_cb(const char *path, const char *modname, byte *base)
{
    per_callstack_module_t *mod = (per_callstack_module_t *)
        global_alloc(sizeof(*mod), HEAPSTAT_CALLSTACK);
    /* We cache in the callstack module to avoid re-matching on every frame */
    /* XXX: what about '\' vs '/' ? */
    mod->on_blacklist = (path != NULL && options.lib_blacklist[0] != '\0' &&
                         text_matches_any_pattern(path, options.lib_blacklist,
                                                  FILESYS_CASELESS));
    mod->on_whitelist = (path != NULL && options.lib_whitelist[0] != '\0' &&
                         text_matches_any_pattern(path, options.lib_whitelist,
                                                  FILESYS_CASELESS));
    mod->in_tool = (path != NULL &&
                    text_matches_pattern(modname, DRMEMORY_LIBNAME, FILESYS_CASELESS));
    mod->on_check_uninit_blacklist =
        (modname != NULL && options.check_uninit_blacklist[0] != '\0' &&
         text_matches_any_pattern(modname, options.check_uninit_blacklist,
                                  FILESYS_CASELESS));
    LOG(1, "%s: %s => black=%d white=%d uninit=%d\n", __FUNCTION__, path,
        mod->on_blacklist, mod->on_whitelist, mod->on_check_uninit_blacklist);
    return (void *) mod;
}

static void
callstack_module_unload_cb(const char *path, void *data)
{
    per_callstack_module_t *mod = (per_callstack_module_t *) data;
    global_free(mod, sizeof(*mod), HEAPSTAT_CALLSTACK);

    if (!report_exited) {
        /* Clear the cache */
        tls_report_t *pt = (tls_report_t *)
            drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx_report);
        pt->last_query_mod_size = 0;
    }
}

/* Returns whether the error should be treated as a false positive */
static bool
check_src_whitelist(error_callstack_t *ecs, uint start)
{
    uint i;
    if (options.src_whitelist_frames > 0 && options.src_whitelist[0] != '\0') {
        for (i = 0; i < ecs->scs.num_frames && i < options.src_whitelist_frames; i++) {
            char *file = symbolized_callstack_frame_file(&ecs->scs, start + i);
            if (file != NULL && text_matches_any_pattern(file, options.src_whitelist,
                                                         FILESYS_CASELESS))
                return false; /* report as true positive */
        }
        /* if no frame matches whitelist, treat as false positive! */
        return true;
    }
    return false;
}

/* Returns whether the error should be treated as a false positive */
/* XXX: i#1454: add per-error blacklist callstack frame depth support */
static bool
check_blacklist_and_whitelist(error_callstack_t *ecs, uint start)
{
    uint i;
    /* We don't support combining black + white: for us, if white is set,
     * we only report what's on white and ignore black.
     * XXX: I'd report a usage error if user sets both, except
     * currently the blacklist default is passed in from frontend
     * (for ease of getting $SYSTEMROOT env var).
     */
    if (options.lib_whitelist_frames > 0 && options.lib_whitelist[0] != '\0') {
        for (i = 0; i < ecs->scs.num_frames && i < options.lib_whitelist_frames; i++) {
            per_callstack_module_t *mod = (per_callstack_module_t *)
                symbolized_callstack_frame_data(&ecs->scs, start + i);
            if (mod != NULL && mod->on_whitelist)
                /* report as true positive, unless not on -src_whitelist */
                return check_src_whitelist(ecs, start);
        }
        /* if no frame matches whitelist, treat as false positive! */
        return true;
    }
    if (options.src_whitelist_frames > 0 && options.src_whitelist[0] != '\0')
        return check_src_whitelist(ecs, start);
    if (options.lib_blacklist_frames > 0 && options.lib_blacklist[0] != '\0') {
        for (i = 0; i < ecs->scs.num_frames && i < options.lib_blacklist_frames; i++) {
            per_callstack_module_t *mod = (per_callstack_module_t *)
                symbolized_callstack_frame_data(&ecs->scs, start + i);
            if (mod == NULL || !mod->on_blacklist)
                break;
        }
        /* if all frames match blacklist, treat as false positive! */
        return (i > 0 && i >= options.lib_blacklist_frames);
    }
    return false;
}

bool
module_is_on_check_uninit_blacklist(app_pc pc)
{
    /* We use TLS to cache the last lookup.  For -no_fastpath, or a series of
     * fastpath entrances, we expect a whole bunch of queries for the same module.
     * Querying TLS should be faster than doing a full module lookup.
     */
    tls_report_t *pt = (tls_report_t *)
        drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx_report);
    if (pc < pt->last_query_mod_start ||
        pc - pt->last_query_mod_start >= pt->last_query_mod_size) {
        per_callstack_module_t *mod = (per_callstack_module_t *)
            module_lookup_user_data(pc, &pt->last_query_mod_start,
                                    &pt->last_query_mod_size);
        if (mod != NULL)
            pt->last_query_res = mod->on_check_uninit_blacklist;
        else
            pt->last_query_res = false;
    }
    return pt->last_query_res;
}

static bool
error_is_likely_false_positive(error_callstack_t *ecs, error_toprint_t *etp)
{
    /* i#1310: separate callstacks that are likely false positives.
     * We look for the top N frames being on the blacklist or whitelist.
     * We skip the top frame if a system call.
     */
    uint start = 0;
    if (etp->potential) /* tool specific potential error */
        return true;
    if (!symbolized_callstack_frame_is_module(&ecs->scs, 0)) /* syscall, we assume */
        start = 1;
    else {
        /* Skip replace_ string/mem routines in our tool library */
        per_callstack_module_t *mod = (per_callstack_module_t *)
            symbolized_callstack_frame_data(&ecs->scs, 0);
        if (mod != NULL && mod->in_tool)
            start = 1;
    }
    return check_blacklist_and_whitelist(ecs, start);
}

static bool
leak_is_likely_false_positive(error_callstack_t *ecs)
{
    /* i#1310: separate callstacks that are likely false positives.
     * We look for the top N frames being on the blacklist or whitelist.
     * We skip the top frame for -replace_malloc.
     */
    uint start = (options.replace_malloc ? 1 : 0);
    return check_blacklist_and_whitelist(ecs, start);
}

/***************************************************************************/

/* converts a ,-separated string to null-separated w/ double null at end */
static void
convert_commas_to_nulls(char *buf, size_t bufsz)
{
    /* ensure double-null-terminated */
    char *c = buf + strlen(buf) + 1;
    if (c - buf >= bufsz - 1) {
        ASSERT(false, ",-separated option string is too big");
        c -= 2; /* put 2nd null before orig null */
    }
    *c = '\0';
    /* convert from ,-separated to separate strings */
    c = strchr(buf, ',');
    while (c != NULL) {
        *c = '\0';
        c = strchr(c + 1, ',');
    }
}

#ifdef DEBUG
static void
print_double_null_term_string(const char *s, const char *sep)
{
    const char *c = s;
    while (*c != '\0') {
        LOG(1, "%s%s", c, sep);
        c += strlen(c) + 1;
    }
}
#endif

static void
print_timestamp(file_t f, uint64 timestamp, const char *prefix)
{
    dr_time_t time;
    uint64 abssec = timestamp / 1000;
    uint msec = (uint) (timestamp % 1000);
    uint sec = (uint) (abssec % 60);
    uint min = (uint) (abssec / 60);
    uint hour = min / 60;
    min %= 60;
    ELOGF(0, f, "%s: %u:%02d:%02d.%03d", prefix, hour, min, sec, msec);
    dr_get_time(&time);
    /* US-style month/day/year */
    ELOGF(0, f, " == %02d:%02d:%02d.%03d %02d/%02d/%04d\n",
          time.hour, time.minute, time.second, time.milliseconds,
          time.month, time.day, time.year);
}

static bool
is_stack_dword_defined(void *drcontext, byte *addr)
{
    umbra_shadow_memory_info_t  info;
    umbra_shadow_memory_info_t *info_ptr;
    uint res;
    tls_report_t *pt = (tls_report_t *) drmgr_get_tls_field(drcontext, tls_idx_report);
    if (pt != NULL)
        info_ptr = &pt->xl8_info;
    else {
        umbra_shadow_memory_info_init(&info);
        info_ptr = &info;
    }
    res = shadow_get_dword(info_ptr, addr);
    if (!TEST(UMBRA_SHADOW_MEMORY_TYPE_NORMAL, info_ptr->shadow_type)) {
        shadow_replace_special(addr);
        /* The replace_special makes umbra_shadow_memory_info stale,
         * so we need clear the cache to get the updated info again.
         */
        umbra_shadow_memory_info_init(info_ptr);
        res = shadow_get_dword(info_ptr, addr);
    }
    return (res == SHADOW_DWORD_DEFINED);
}

static bool
callstack_ignore_initial_xbp(void *drcontext, dr_mcontext_t *mc)
{
    /* i#783: we expose option for whether to always scan at start */
    if (!options.callstack_use_top_fp
        IF_WINDOWS(|| is_in_seh_unwind(drcontext, mc)))
        return true;
    else
        return false;
}

static void
missing_syms_cb(const char *modpath)
{
#ifdef USE_DRSYMS
    dr_fprintf(f_missing_symbols, "%s\n", modpath);
#endif
}

void
report_init(void)
{
    char *c;
    callstack_options_t callstack_ops = { sizeof(callstack_ops), 0 };

    timestamp_start = dr_get_milliseconds();
    print_timestamp(f_global, timestamp_start, "start time");

    tls_idx_report = drmgr_register_tls_field();
    ASSERT(tls_idx_report > -1, "unable to reserve TLS slot");

#ifdef WINDOWS
    if (options.dump_at_unaddressable)
        options.dump_at_error_mask |= error_mask[ERROR_UNADDRESSABLE];
#endif

    error_lock = dr_mutex_create();

    hashtable_init_ex(&error_table, ERROR_HASH_BITS, HASH_CUSTOM,
                      false/*!str_dup*/, false/*using error_lock*/,
                      (void (*)(void*)) stored_error_free,
                      (uint (*)(void*)) stored_error_hash,
                      (bool (*)(void*, void*)) stored_error_cmp);

#ifdef USE_DRSYMS
    /* callstack.c wants these as null-separated, double-null-terminated */
    convert_commas_to_nulls(options.callstack_truncate_below,
                            BUFFER_SIZE_ELEMENTS(options.callstack_truncate_below));
    if (options.callstack_exe_hide && dr_get_application_name() != NULL) {
        size_t len = strlen(options.callstack_modname_hide);
        dr_snprintf(options.callstack_modname_hide + len,
                    BUFFER_SIZE_ELEMENTS(options.callstack_modname_hide) - len,
                    ",%s",  dr_get_application_name());
        NULL_TERMINATE_BUFFER(options.callstack_modname_hide);
    }
    convert_commas_to_nulls(options.callstack_modname_hide,
                            BUFFER_SIZE_ELEMENTS(options.callstack_modname_hide));
    convert_commas_to_nulls(options.callstack_srcfile_hide,
                            BUFFER_SIZE_ELEMENTS(options.callstack_srcfile_hide));
    convert_commas_to_nulls(options.callstack_srcfile_prefix,
                            BUFFER_SIZE_ELEMENTS(options.callstack_srcfile_prefix));
    /* text_matches_any_pattern also wants these w/ nulls, not commas */
    convert_commas_to_nulls(options.lib_blacklist,
                            BUFFER_SIZE_ELEMENTS(options.lib_blacklist));
    convert_commas_to_nulls(options.lib_whitelist,
                            BUFFER_SIZE_ELEMENTS(options.lib_whitelist));
    convert_commas_to_nulls(options.src_whitelist,
                            BUFFER_SIZE_ELEMENTS(options.src_whitelist));
#endif
    convert_commas_to_nulls(options.check_uninit_blacklist,
                            BUFFER_SIZE_ELEMENTS(options.check_uninit_blacklist));

#ifdef WINDOWS
    {
        /* i#805: auto-detect mingw app and enable -no_callstack_use_top_fp */
        drsym_debug_kind_t kind;
        /* XXX: if for early injection we don't want to use drsyms this early,
         * we can delay this b/c it's used in a callback and not passed to
         * callstack_init()
         */
        /* XXX: now that we split leaks off it may be fine to remove all this
         * but we'll go ahead and pay the overhead to get nicer leak callstacks
         */
        if (drsym_get_module_debug_kind(app_path, &kind) == DRSYM_SUCCESS &&
            TEST(DRSYM_PECOFF_SYMTAB, kind) &&
            !option_specified.callstack_use_top_fp)
            options.callstack_use_top_fp = false;
    }
#endif

    /* must be BEFORE read_suppression_file (PR 474542) */
    callstack_ops.global_max_frames = options.callstack_max_frames;
    /* I used to use options.stack_swap_threshold but that
     * was decreased for PR 525807 and anything smaller than
     * ~0x20000 leads to bad callstacks on gcc b/c of a huge
     * initial frame
     */
    callstack_ops.stack_swap_threshold = 0x20000;
    /* Default callstack flags */
    callstack_ops.fp_flags = 0;
    if (!options.callstack_use_fp)
        callstack_ops.fp_flags |= FP_DO_NOT_WALK_FP;
    if (options.callstack_conservative) {
        /* We don't expose FP_VERIFY_CROSS_MODULE_TARGET, although it can be a big
         * perf win over FP_VERIFY_CALL_TARGET (see i#703 numbers) -- so should we
         * have -callstack_mostly_conservative?.
         */
        callstack_ops.fp_flags |= FP_VERIFY_CALL_TARGET;
    }
    callstack_ops.fp_scan_sz = options.callstack_max_scan;
    callstack_ops.print_flags = IF_DRSYMS_ELSE(options.callstack_style,
                                               PRINT_FOR_POSTPROCESS);
    callstack_ops.get_syscall_name = get_syscall_name;
    callstack_ops.is_dword_defined =
        options.shadowing ? is_stack_dword_defined : NULL;
    callstack_ops.ignore_xbp = callstack_ignore_initial_xbp;
#ifdef USE_DRSYMS
    /* pass NULL since callstack.c uses that as quick check */
    callstack_ops.truncate_below =
        (options.callstack_truncate_below[0] == '\0') ? NULL :
        options.callstack_truncate_below;
    callstack_ops.modname_hide =
        (options.callstack_modname_hide[0] == '\0') ? NULL :
        options.callstack_modname_hide;
    callstack_ops.srcfile_hide =
        (options.callstack_srcfile_hide[0] == '\0') ? NULL :
        options.callstack_srcfile_hide;
    callstack_ops.srcfile_prefix =
        (options.callstack_srcfile_prefix[0] == '\0') ? NULL :
        options.callstack_srcfile_prefix;
#endif
    callstack_ops.missing_syms_cb = missing_syms_cb;
    /* i#1231: we don't zero for full mode but we want the cache */
    callstack_ops.old_retaddrs_zeroed = options.zero_retaddr;
    callstack_ops.tool_lib_ignore = DRMEMORY_LIBNAME;
    callstack_ops.bad_fp_list = options.callstack_bad_fp_list;
    callstack_ops.dump_app_stack = options.callstack_dump_stack;
    callstack_ops.module_load = callstack_module_load_cb;
    callstack_ops.module_unload = callstack_module_unload_cb;
    callstack_init(&callstack_ops);

#ifdef USE_DRSYMS
    suppress_file_lock = dr_mutex_create();
    ELOGF(0, f_results, "Dr. Memory results for pid %d: \"%s\""NL,
          dr_get_process_id(), dr_get_application_name());
# ifdef WINDOWS
    ELOGF(0, f_results, "Application cmdline: \"%S\""NL, get_app_commandline());
# endif
    ELOGF(0, f_suppress, "# File for suppressing errors found in pid %d: \"%s\""NL NL,
          dr_get_process_id(), dr_get_application_name());
    ELOGF(0, f_potential, "Dr. Memory errors that are likely to be false positives, "
          "for pid %d: \"%s\""NL, dr_get_process_id(), dr_get_application_name());
    if ((options.lib_whitelist_frames > 0 && options.lib_whitelist[0] != '\0') ||
        (options.src_whitelist_frames > 0 && options.src_whitelist[0] != '\0')) {
        if (options.lib_whitelist_frames > 0 && options.lib_whitelist[0] != '\0') {
            ELOGF(0, f_potential,
                  "These errors did not match the lib whitelist '%s' for %d frames."NL,
                  options.lib_whitelist, options.lib_whitelist_frames);
        }
        if (options.src_whitelist_frames > 0 && options.src_whitelist[0] != '\0') {
            ELOGF(0, f_potential,
                  "These errors did not match the src whitelist '%s' for %d frames."NL,
                  options.src_whitelist, options.src_whitelist_frames);
        }
    } else if (options.lib_blacklist_frames > 0 && options.lib_blacklist[0] != '\0') {
        ELOGF(0, f_potential, "These errors matched the blacklist '%s' for %d frames."NL,
              options.lib_blacklist, options.lib_blacklist_frames);
        ELOGF(0, f_potential, "Run with -lib_blacklist_frames 0 to treat these as "
              "regular errors."NL);
    }
    ELOGF(0, f_potential, "If these are all false positives and your focus is "
          "unaddressable errors, consider running with -light to skip all "
          "uninitialized reads and leaks for higher performance."NL);
#endif

    if (options.default_suppress) {
        /* the default suppression file must be located at
         *   dr_get_client_path()/../suppress-default.txt
         */
        const char *const DEFAULT_SUPPRESS_NAME = "suppress-default.txt";
        char dname[MAXIMUM_PATH];
        if (obtain_configfile_path(dname, BUFFER_SIZE_ELEMENTS(dname),
                                    DEFAULT_SUPPRESS_NAME))
            open_and_read_suppression_file(dname, true);
        else
            ASSERT(false, "default-suppress snprintf error");
    }

    /* we support multiple suppress file (i#574) */
    c = options.suppress;
    while (*c != '\0') {
        open_and_read_suppression_file(c, false);
        c += strlen(c) + 1;
    }

    if (options.show_threads || options.show_all_threads) {
        main_thread = dr_get_thread_id(dr_get_current_drcontext());
        if (options.show_all_threads)
            report_main_thread();
    }
    if (options.show_threads && !options.show_all_threads) {
        thread_table_lock = dr_mutex_create();
        hashtable_init_ex(&thread_table, THREAD_HASH_BITS, HASH_INTPTR,
                          false/*!str_dup*/, false/*!synch*/,
                          (void (*)(void*)) packed_callstack_free, NULL, NULL);
    }

    if (options.prefix_style == PREFIX_STYLE_BLANK) {
        info_cstack_pfx = "      ";
        /* Extra indent the width of "Note: " */
        aux_cstack_pfx  = "           ";
    } else {
        info_cstack_pfx = INFO_PFX;
        aux_cstack_pfx  = INFO_PFX;
    }

#ifndef DEBUG
    /* We need our instruction= line to match old DR disasm style for compatibility.
     * For debug, we only do this around each report, so our logs have full info.
     */
    disassemble_set_syntax(DR_DISASM_NO_OPND_SIZE);
#endif
}

#ifdef UNIX
void
report_fork_init(void)
{
    uint i, set;
    /* We reset so the child's timestamps will be relative to its start.
     * The global timestamp printed in the log can be used to find
     * time relative to the grandparent.
     */
    timestamp_start = dr_get_milliseconds();
    print_timestamp(f_global, timestamp_start, "start time");

    /* PR 513984: fork child should not inherit errors from parent */
    dr_mutex_lock(error_lock);
    error_id = 0;
    error_id_potential = 0;
    for (set = 0; set < ERROR_SET_NUM; set++) {
        for (i = 0; i < ERROR_MAX_VAL; i++) {
            num_unique[set][i] = 0;
            num_total[set][i] = 0;
        }
        for (i = ERROR_LEAK; i < ERROR_MAX_LEAK; i++) {
            saved_unique[set][i] = 0;
            saved_total[set][i] = 0;
            num_bytes_leaked[set][i] = 0;
            saved_bytes_leaked[set][i] = 0;
        }
        num_reported_errors[set] = 0;
        num_total_leaks[set] = 0;
    }
    num_leaks_ignored = 0;
    num_suppressions = 0;
    num_suppressions_matched_user = 0;
    num_suppressed_leaks_user = 0;
    num_suppressions_matched_default = 0;
    num_suppressed_leaks_default = 0;
    num_throttled_errors = 0;
    num_throttled_leaks = 0;
    hashtable_clear(&error_table);
    /* Be sure to reset the error list (xref PR 519222)
     * The error list points at hashtable payloads so nothing to free
     */
    error_head = NULL;
    error_tail = NULL;
    dr_mutex_unlock(error_lock);

    if (options.show_threads && !options.show_all_threads) {
        dr_mutex_lock(thread_table_lock);
        hashtable_clear(&thread_table);
        dr_mutex_unlock(thread_table_lock);
    }
}
#endif

static void
report_leak_stats(file_t f, bool notify, bool potential, uint type)
{
    uint set = ERROR_SET(potential);
    size_t bytes = num_bytes_leaked[set][type];
    if (options.check_leaks) {
        NOTIFY_COND(notify, f,
                    "  %5d unique, %5d total, %6d byte(s) of %s%s"NL,
                    num_unique[set][type], num_total[set][type], bytes,
                    potential ? POTENTIAL_PREFIX " " : "", error_name[type]);
    } else {
        /* We don't have dup checking */
        NOTIFY_COND(notify, f,
                    "  %5d total, %6d byte(s) of %s%s"NL,
                    num_unique[set][type], bytes,
                    potential ? POTENTIAL_PREFIX " " : "", error_name[type]);
    }
}

static bool
report_errors_found(void)
{
    uint set = ERROR_SET(false/*!potential*/);
    return (num_reported_errors[set] > 0 ||
            num_bytes_leaked[set][ERROR_LEAK] > 0 ||
            num_bytes_leaked[set][ERROR_POSSIBLE_LEAK] > 0 ||
            (options.show_reachable &&
             num_bytes_leaked[set][ERROR_REACHABLE_LEAK] > 0));
}

/* N.B.: for PR 477013, postprocess.pl duplicates some of this syntax
 * exactly: try to keep the two in sync
 */
static void
report_summary_to_file(file_t f, bool stderr_too, bool print_full_stats, bool potential)
{
    uint i;
    stored_error_t *err;
    bool notify = (options.summary && stderr_too);
    uint set = ERROR_SET(potential);
    bool found_errors = report_errors_found();

    /* Too much info to put on stderr, so just in logfile */
    dr_fprintf(f, ""NL);
    dr_fprintf(f, "DUPLICATE %sERROR COUNTS:"NL,
               potential ? POTENTIAL_PREFIX_ALLCAP " " : "");
    for (err = error_head; err != NULL; err = err->next) {
        if (err->count > 1 && !err->suppressed &&
            ((potential && err->potential) || (!potential && !err->potential)) &&
            /* possible leaks are left with id==0 and should be ignored
             * except in summary, unless -possible_leaks
             */
            (err->errtype != ERROR_POSSIBLE_LEAK || options.possible_leaks) &&
            /* similarly with reachable leaks */
            (err->errtype != ERROR_REACHABLE_LEAK || options.show_reachable)) {
            ASSERT(err->id > 0, "error id wrong");
            dr_fprintf(f, "\t%sError #%4d: %6d"NL,
                       potential ? POTENTIAL_PREFIX_CAP " " : "", err->id, err->count);
        }
    }

    if (!potential) {
        dr_fprintf(f, NL"SUPPRESSIONS USED:"NL);
        for (i = 0; i < ERROR_MAX_VAL; i++) {
            suppress_spec_t *spec;
            for (spec = supp_list[i]; spec != NULL; spec = spec->next) {
                if (!print_full_stats && spec->is_default)
                    continue;
                if (spec->count_used > 0) {
                    dr_fprintf(f, "\t%6dx", spec->count_used);
                    if (type_is_leak(i))
                        dr_fprintf(f, " (leaked %7d bytes): ", spec->bytes_leaked);
                    else
                        dr_fprintf(f, ": ");
                    if (spec->name == NULL)
                        dr_fprintf(f, "<no name %d>"NL, spec->num);
                    else
                        dr_fprintf(f, "%s"NL, spec->name);
                } else if (options.check_uninitialized && is_module_wildcard(spec) &&
                           spec->type == ERROR_UNDEFINED) {
                    dr_fprintf(f, "\t%6sx", "?");
                    dr_fprintf(f, " (count unavail. for whole-lib): ");
                    if (spec->name == NULL)
                        dr_fprintf(f, "<no name %d>"NL, spec->num);
                    else
                        dr_fprintf(f, "%s"NL, spec->name);
                }
            }
        }
    }

    NOTIFY_COND(notify IF_DRSYMS(&& options.results_to_stderr), f, NL);
    NOTIFY_COND(notify, f, found_errors ? "%sERRORS FOUND:"NL : "NO %sERRORS FOUND:"NL,
                potential ? POTENTIAL_PREFIX_ALLCAP " " : "",
                potential ? POTENTIAL_PREFIX_ALLCAP " " : "");
    for (i = 0; i < ERROR_MAX_VAL; i++) {
        if (type_is_leak(i)) {
            if (options.count_leaks &&
                (options.show_reachable || i != ERROR_REACHABLE_LEAK)) {
                report_leak_stats(f, notify, potential, i);
                if (i == ERROR_LEAK && !options.check_leaks) {
                    NOTIFY_COND(notify, f,
                                "         (re-run with \"-check_leaks\" for details)"NL);
                }
                if (i == ERROR_POSSIBLE_LEAK && !options.possible_leaks) {
                    NOTIFY_COND(notify, f,
                                "         (re-run with \"-possible_leaks\""
                                " for details)"NL);
                }
            }
        } else if (((i != ERROR_UNADDRESSABLE && i != ERROR_UNDEFINED) ||
                    INSTRUMENT_MEMREFS()) &&
                   (i != ERROR_INVALID_HEAP_ARG ||
                    (options.check_invalid_frees && options.track_allocs)) &&
#ifdef WINDOWS
                   (i != ERROR_GDI_USAGE || options.check_gdi) &&
                   (i != ERROR_HANDLE_LEAK || options.check_handle_leaks) &&
#endif
                   (i != ERROR_UNDEFINED || CHECK_UNINITS())) {
            NOTIFY_COND(notify, f, "  %5d unique, %5d total %s%s"NL,
                        num_unique[set][i], num_total[set][i],
                        potential ? POTENTIAL_PREFIX " " : "", error_name[i]);
        }
    }
    if (!potential) {
        /* -brief doesn't list the count of potential errors */
        if (!options.brief) {
            if (num_throttled_errors > 0 || num_throttled_leaks > 0 ||
                (!options.show_reachable && num_reported_errors > 0) ||
                num_reported_errors[ERROR_POTENTIAL] > 0 ||
                num_total_leaks[ERROR_POTENTIAL] > 0)
                NOTIFY_COND(notify, f, "ERRORS IGNORED:"NL);
            else
                NOTIFY_COND(notify, f, "NO ERRORS IGNORED"NL);
        }
        if (!options.brief && num_reported_errors[ERROR_POTENTIAL] > 0) {
            NOTIFY_COND(notify, f,
                        "  %5d potential error(s) (suspected false positives)"NL,
                        num_reported_errors[ERROR_POTENTIAL]);
            NOTIFY_COND(notify, f, "         (details: %s%c%s)"NL,
                        logsubdir, DIRSEP, RESULTS_POTENTIAL_FNAME);
        }
        if (!options.brief && num_total_leaks[ERROR_POTENTIAL] > 0) {
            NOTIFY_COND(notify, f,
                        "  %5d potential leak(s) (suspected false positives)"NL,
                        num_total_leaks[ERROR_POTENTIAL]);
            NOTIFY_COND(notify, f, "         (details: %s%c%s)"NL,
                        logsubdir, DIRSEP, RESULTS_POTENTIAL_FNAME);
        }
        if (!options.brief) {
            if (options.suppress[0] != '\0') {
                NOTIFY_COND(notify, f,
                            "  %5d user-suppressed, %5d default-suppressed error(s)"NL,
                            num_suppressions_matched_user,
                            num_suppressions_matched_default);
                if (options.count_leaks) {
                    NOTIFY_COND(notify, f,
                                "  %5d user-suppressed, %5d default-suppressed leak(s)"NL,
                                num_suppressed_leaks_user, num_suppressed_leaks_default);
                }
            }
            if (options.count_leaks) {
                /* We simplify the results.txt and stderr view by omitting some details */
                if (print_full_stats) {
                    /* Not sending to stderr */
                    dr_fprintf(f, "  %5d ignored assumed-innocuous system leak(s)"NL,
                               num_leaks_ignored);
                }
                if (!options.show_reachable) {
                    report_leak_stats(f, notify, potential, ERROR_REACHABLE_LEAK);
                    NOTIFY_COND(notify, f,
                                "         (re-run with \"-show_reachable\" for details)"
                                NL);
                }
            }
        }
        if (num_throttled_errors > 0) {
            NOTIFY_COND(notify, f, "  %5d error(s) beyond -report_max"NL,
                        num_throttled_errors);
        }
        if (num_throttled_leaks > 0) {
            NOTIFY_COND(notify, f, "  %5d leak(s) beyond -report_leak_max"NL,
                        num_throttled_leaks);
        }
    }
    NOTIFY_COND(notify, f, "Details: %s%c%s"NL, logsubdir, DIRSEP,
                potential ? RESULTS_POTENTIAL_FNAME : RESULTS_FNAME);
}

void
report_summary(void)
{
    report_summary_to_file(f_global, true, true, false);
    report_summary_to_file(f_global, false, false, true);
#ifdef USE_DRSYMS
    /* we don't show default suppressions used in results.txt file */
    report_summary_to_file(f_results, false, false, false);
    report_summary_to_file(f_potential, false, false, true);
#endif
}

void
report_exit(void)
{
    uint i;
    report_exited = true;
#ifdef USE_DRSYMS
    ELOGF(0, f_results, NL"==========================================================================="NL"FINAL SUMMARY:"NL);
    dr_mutex_destroy(suppress_file_lock);
#endif
    report_summary();

    hashtable_delete(&error_table);
    dr_mutex_destroy(error_lock);

    callstack_exit();

    for (i = 0; i < ERROR_MAX_VAL; i++) {
        suppress_spec_t *spec, *next;
        for (spec = supp_list[i]; spec != NULL; spec = next) {
            next = spec->next;
            suppress_spec_free(spec);
        }
    }

    if (options.show_threads && !options.show_all_threads) {
        hashtable_delete(&thread_table);
        dr_mutex_destroy(thread_table_lock);
    }

    drmgr_unregister_tls_field(tls_idx_report);
}

void
report_exit_if_errors(void)
{
    /* Xref DRi#1400 on downsides of just exiting and perhaps adding a
     * feature to set the exit code in another way.
     */
    if (options.exit_code_if_errors != 0 && report_errors_found())
        dr_exit_process(options.exit_code_if_errors);
}

void
report_thread_init(void *drcontext)
{
    tls_report_t *pt = (tls_report_t *)
        thread_alloc(drcontext, sizeof(*pt), HEAPSTAT_MISC);
    drmgr_set_tls_field(drcontext, tls_idx_report, pt);
    pt->errbufsz = MAX_ERROR_INITIAL_LINES + max_callstack_size()*2;
    pt->errbuf = (char *) thread_alloc(drcontext, pt->errbufsz, HEAPSTAT_REPORT);
    umbra_shadow_memory_info_init(&pt->xl8_info);
    callstack_thread_init(drcontext);
}

void
report_thread_exit(void *drcontext)
{
    tls_report_t *pt = (tls_report_t *) drmgr_get_tls_field(drcontext, tls_idx_report);

    callstack_thread_exit(drcontext);

    if (options.show_threads && !options.show_all_threads) {
        /* this thread can't be involved in any error reports, and thread ids
         * can be re-used, so we must remove
         */
        dr_mutex_lock(thread_table_lock);
        /* we don't assert that it existed b/c we may have removed earlier
         * if this thread hit an error
         */
        hashtable_remove(&thread_table,
                         (void *)(ptr_int_t)dr_get_thread_id(drcontext));
        dr_mutex_unlock(thread_table_lock);
    }

    thread_free(drcontext, (void *) pt->errbuf, pt->errbufsz, HEAPSTAT_REPORT);
    drmgr_set_tls_field(drcontext, tls_idx_report, NULL);
    thread_free(drcontext, pt, sizeof(*pt), HEAPSTAT_MISC);
}

/***************************************************************************/

void
print_timestamp_elapsed(char *buf, size_t bufsz, size_t *sofar)
{
    ssize_t len = 0;
    uint64 timestamp = dr_get_milliseconds() - timestamp_start;
    uint64 abssec = timestamp / 1000;
    uint msec = (uint) (timestamp % 1000);
    uint sec = (uint) (abssec % 60);
    uint min = (uint) (abssec / 60);
    uint hour = min / 60;
    min %= 60;
    BUFPRINT(buf, bufsz, *sofar, len, "%u:%02d:%02d.%03d", hour, min, sec, msec);
}

static void
print_timestamp_and_thread(char *buf, size_t bufsz, size_t *sofar, bool error)
{
    /* PR 465163: include timestamp and thread id in callstacks */
    ssize_t len = 0;
    thread_id_t tid = dr_get_thread_id(dr_get_current_drcontext());
    BUFPRINT(buf, bufsz, *sofar, len, "@");
    print_timestamp_elapsed(buf, bufsz, sofar);
    BUFPRINT(buf, bufsz, *sofar, len, " in thread "TIDFMT""NL, tid);
    if (error && options.show_threads && !options.show_all_threads)
        report_delayed_thread(tid);
}

void
print_timestamp_elapsed_to_file(file_t f, const char *prefix)
{
    char buf[128];
    size_t sofar = 0;
    ssize_t len = 0;
    BUFPRINT(buf, BUFFER_SIZE_ELEMENTS(buf), sofar, len, "%s", prefix);
    print_timestamp_and_thread(buf, BUFFER_SIZE_ELEMENTS(buf), &sofar, false);
    print_buffer(f, buf);
}

static void
report_error_from_buffer(file_t f, char *buf, bool add_prefix)
{
    if (add_prefix) {
        /* we want atomic prints to stderr and for now we pay the cost of
         * allocations on each one since we assume -results_to_stderr will
         * be rare.  opt: have a second pt->buf.
         */
        size_t nlsz = strlen(NL);
        size_t max = strlen(buf);
        char *p = buf;
        char *nl;
        char swap;
        size_t newsz = strlen(buf) * 2;
        char *newbuf = (char *) global_alloc(newsz, HEAPSTAT_CALLSTACK);
        size_t sofar= 0;
        int len;
        while (p < buf + max) {
            nl = strstr(p, NL);
            if (nl == NULL) {
                /* shouldn't really happen but fail gracefully */
                break;
            } else {
                swap = *(nl + nlsz);
                *(nl + nlsz) = '\0';
                print_prefix_to_buffer(newbuf, newsz, &sofar);
                BUFPRINT(newbuf, newsz, sofar, len, "%s", p);
                *(nl + nlsz) = swap;
                p = nl + nlsz;
            }
        }
#if defined(USE_DRSYMS) && defined(WINDOWS)
        /* XXX DRi#556: console output not showing up on win7 for 64-bit apps! */
        if (f == STDERR && IN_CMD)
            print_to_cmd(newbuf);
        else
#endif
            print_buffer(f, newbuf);
        global_free(newbuf, newsz, HEAPSTAT_CALLSTACK);
    } else
        print_buffer(f, buf);
}

/* caller should hold error_lock */
static void
acquire_error_number(stored_error_t *err)
{
    if (err->potential)
        err->id = atomic_add32_return_sum((volatile int *)&error_id_potential, 1);
    else
        err->id = atomic_add32_return_sum((volatile int *)&error_id, 1);
    num_unique[ERROR_SET(err->potential)][err->errtype]++;
}

/* Records a callstack for mc (or uses the passed-in pcs) and checks
 * whether this is a new error or a duplicate.  If new, it adds a new
 * entry to the error table.  Either way, it increments the error's
 * count, and increments the num_total count if the error is not
 * marked as suppressed.  If it is marked as suppressed, it's up to
 * caller to increment any other counters.
 * Returns holding error_lock.
 */
static stored_error_t *
record_error(uint type, packed_callstack_t *pcs, app_loc_t *loc, dr_mcontext_t *mc,
             bool have_lock)
{
    stored_error_t *err = stored_error_create(type);
    if (pcs == NULL) {
        reg_t save_xbp = MC_FP_REG(mc);
        bool zeroed_xbp = false;
        const char *modpath = NULL;
        uint max_frames = (type_is_leak(type) ? options.malloc_max_frames :
                           options.callstack_max_frames);
        if (options.callstack_use_top_fp_selectively && HAVE_STALE_RETADDRS()) {
            /* We need the module of the top frame for checks below */
            if (loc->type == APP_LOC_PC) {
                app_pc pc = loc_to_pc(loc);
                /* callstack mod table is faster than DR lookup */
                modpath = module_lookup_path(pc);
            }
        }
        if (options.callstack_use_top_fp_selectively &&
            /* for -replace_malloc invalid args and leaks we have our own
             * malloc routine as the top frame (i#639).  we ensure it has ebp.
             */
            (!options.replace_malloc ||
             (type != ERROR_INVALID_HEAP_ARG && !type_is_leak(type) &&
              /* ditto for warnings reported from malloc routines */
              (type != ERROR_WARNING ||
               (modpath != NULL &&
                !text_matches_pattern(modpath, "*drmemory*", true/*ignore case*/)))))) {
            /* i#844: force a scan in the top frame to handle the all-too-common
             * leaf function with no frame pointer.
             * We assume there is no setting of mcontext on this path:
             * only reading of mcontext.
             * XXX: perhaps callstack should provide per-callstack flags.
             * But this works just as well.
             */
            if (HAVE_STALE_RETADDRS()) {
                /* We don't have definedness info or zeroing so disabling
                 * top fp will result in risk of stale retaddrs.
                 * System libs don't normally have leaf funcs w/o frames so
                 * only do this for the app.
                 * XXX: this is hacky: the system lib identification, the
                 * risk of stale frames.  But it's not clear that there's
                 * a great solution when the app has missing frames and
                 * we don't have definedness or zeroing.
                 * XXX i#624: Probably long-term we should add zeroing to light mode.
                 */
                if (loc->type == APP_LOC_PC) {
                    if (modpath != NULL && !text_matches_pattern
                        (modpath, "*windows?sys*", true/*ignore case*/)) {
                        zeroed_xbp = true;
                        MC_FP_REG(mc) = 0;
                    }
                }
            } else {
                /* we have definedness info so scanning is accurate */
                zeroed_xbp = true;
                MC_FP_REG(mc) = 0;
            }
        }
        packed_callstack_record(&err->pcs, mc, loc, max_frames);
        if (zeroed_xbp) {
            MC_FP_REG(mc) = save_xbp;
            /* i#1049: scan may not have been far enough so re-try w/ ebp */
            if (packed_callstack_num_frames(err->pcs) <= 1) {
                IF_DEBUG(uint ref = )
                    packed_callstack_free(err->pcs);
                ASSERT(ref == 0, "invalid ref count");
                packed_callstack_record(&err->pcs, mc, loc, max_frames);
            }
        }
    } else {
        /* lifetimes differ so we must clone */
        err->pcs = packed_callstack_clone(pcs);
    }
    if (!have_lock)
        dr_mutex_lock(error_lock);
    /* add returns false if already there */
    if (hashtable_add(&error_table, (void *)err, (void *)err)) {
        err->id = 0; /* caller must call acquire_error_number() to set */
        /* add to linked list */
        if (error_tail == NULL) {
            ASSERT(error_head == NULL, "error list inconsistent");
            error_head = err;
            error_tail = err;
        } else {
            ASSERT(error_head != NULL, "error list inconsistent");
            error_tail->next = err;
            error_tail = err;
        }
    } else {
        stored_error_t *existing = hashtable_lookup(&error_table, (void *)err);
        ASSERT(existing != NULL, "entry must exist");
        stored_error_free(err);
        err = existing;
        /* FIXME PR 423750: print out a line for the dup saying
         * "Error #n: reading 0xaddr", perhaps option-controlled if we don't
         * want to fill up logs in common-case
         */
    }
    /* If marked as suppressed, up to caller to increment counters.
     * If later marked as hidden ("potential") up to caller to adjust counters.
     */
    err->count++;
    if (!err->suppressed)
        num_total[ERROR_SET(err->potential)][type]++;
    return err;
}

/* PR 535568: report nearest mallocs and whether freed.
 * Stores results in etp fields which the caller must zero ahead of time.
 * The results are then printed in report_heap_info().
 * This two-part scheme allows putting heap info in the error title (i#1593).
 */
static void
gather_heap_info(INOUT error_toprint_t *etp, app_pc addr, size_t sz)
{
    byte *start, *end;
    ssize_t size;
    bool found = false;

    if (!is_in_heap_region(addr)) {
        etp->on_heap = false;
        if (etp->xsp != NULL) {
            etp->stack_size = allocation_size(etp->xsp, &etp->stack_base);
            if (addr >= etp->stack_base && addr+sz < etp->stack_base+etp->stack_size)
                etp->on_stack = true;
        }
        return;
    }
    etp->on_heap = true;

    /* I measured replacing the malloc hashtable with an interval tree
     * and the cost is noticeable on heap-intensive benchmarks, so we
     * instead use shadow values to find malloc boundaries
     */
    /* We don't walk more than PAGE_SIZE: FIXME: make larger? */
    for (end = addr+sz; end != NULL && end < addr+sz + PAGE_SIZE; ) {
        if (MAP_4B_TO_1B) {
            /* granularity is 4 so don't report tail of dword of bad ref (i#622) */
            end = (byte *)ALIGN_FORWARD(end, 4);
        }
        if (options.shadowing &&
            !shadow_check_range(end, PAGE_SIZE, SHADOW_UNADDRESSABLE,
                                &start, NULL, NULL)) {
            LOG(3, "report_heap_info: next addressable="PFX"\n", start);
            size = malloc_chunk_size((byte*)ALIGN_FORWARD(start, MALLOC_CHUNK_ALIGNMENT));
            if (size <= -1) {
                /* An earlier unaddr adjacent to real malloc could
                 * have marked as addr so try align-8 forward as our
                 * loop will miss that if all addr in between
                 */
                start = (byte*) ALIGN_FORWARD(start+1, MALLOC_CHUNK_ALIGNMENT);
                size = malloc_chunk_size(start);
            }
            if (size > -1) {
                found = true;
                /* we don't have the malloc lock so races could result in
                 * inaccurate adjacent malloc info: only print if accurate
                 */
                if (start >= addr+sz) {
                    etp->next_start = start;
                    etp->next_size = size;
                }
                break;
            } /* else probably an earlier unaddr error, for which we marked
               * the memory as addressable!
               */
            end = shadow_next_dword((byte *)ALIGN_FORWARD(start, 4),
                                    addr+sz + PAGE_SIZE, SHADOW_UNADDRESSABLE);
            /* end will be NULL on failure which we check in loop bounds */
        } else
            break;
    }
    /* If we can't find a higher malloc better to not print anything since we're
     * using heuristics and could be wrong (if we had rbtree I'd print "no higher")
     */
    /* i#1145: we need an explicit check for 0-sized mallocs */
    size = malloc_chunk_size((byte *)ALIGN_BACKWARD(addr, MALLOC_CHUNK_ALIGNMENT));
    if (size > -1) {
        found = true;
        etp->prev_end = (byte *)ALIGN_BACKWARD(addr, MALLOC_CHUNK_ALIGNMENT) + size;
        etp->prev_size = size;
    }
    for (start = addr; etp->prev_end == NULL && start > addr - PAGE_SIZE; ) {
        if (options.shadowing &&
            !shadow_check_range_backward(start, PAGE_SIZE,
                                         SHADOW_UNADDRESSABLE, &end)) {
            LOG(3, "report_heap_info: prev addressable="PFX"\n", end);
            start = (byte *) ALIGN_BACKWARD(end, 4);
            start = shadow_prev_dword(start, start - PAGE_SIZE, SHADOW_UNADDRESSABLE);
            LOG(3, "\tfrom there, prev unaddressable="PFX"\n", start);
            if (start != NULL) {
                start += 4; /* move to start of addressable */
                size = malloc_chunk_size(start);
                if (size <= -1) {
                    /* An earlier unaddr adjacent to real malloc could
                     * have marked as addr so try align-8 back as our
                     * loop will miss that if all addr in between
                     */
                    start = (byte*) ALIGN_BACKWARD(start-1, MALLOC_CHUNK_ALIGNMENT);
                    size = malloc_chunk_size(start);
                }
                if (size > -1) {
                    found = true;
                    /* we don't have the malloc lock so races could result in
                     * inaccurate adjacent malloc info: only print if accurate
                     */
                    if (start + size <= addr) {
                        etp->prev_end = start + size;
                        etp->prev_size = size;
                    }
                    break;
                } /* else probably an earlier unaddr error, for which we marked
                   * the memory as addressable!
                   */
            }
        } else
            break;
    }
    /* in pattern mode, we walk the whole hashtable to find the region */
    if (options.pattern != 0 && options.redzone_size > 0 &&
        region_in_redzone(addr, sz, &etp->neighbor_pcs, &start, &end, NULL, NULL)) {
        if (addr >= end)
            etp->prev_end = end;
        else
            etp->next_start = start;
        etp->prev_size = (end - start);
    }

    /* Look at both delay free list and at malloc entries marked
     * invalid.  The latter will find frees beyond the limit of the
     * delay list as well as free-by-realloc (xref i#69: we now
     * replace realloc so realloc frees will be on the queue).
     */
    found = overlaps_delayed_free(addr, addr+sz, &start, &end, &etp->free_pcs,
                                  /* While it would be nice to include
                                   * free-list chunks, we don't want to report
                                   * on a former redzone in a coalesced chunk,
                                   * so we limit to delayed chunks.
                                   */
                                  true);
    if (!found && etp->next_start != NULL) {
        /* Heuristic: try 8-byte-aligned ptrs between here and valid mallocs */
        for (start = (byte *) ALIGN_FORWARD(addr, MALLOC_CHUNK_ALIGNMENT);
             start < addr+sz && start < etp->next_start;
             start += MALLOC_CHUNK_ALIGNMENT) {
            size = malloc_chunk_size_invalid_only(start);
            if (size > -1) {
                found = true;
                end = start + size;
                break;
            }
        }
    }
    if (!found && etp->prev_end != NULL) {
        /* Heuristic: try 8-byte-aligned ptrs between here and valid mallocs */
        for (start = (byte *) ALIGN_BACKWARD(addr, MALLOC_CHUNK_ALIGNMENT);
             start > etp->prev_end; start -= MALLOC_CHUNK_ALIGNMENT) {
            size = malloc_chunk_size_invalid_only(start);
            if (size > -1) {
                end = start + size;
                if (end > addr)
                    found = true;
                break;
            }
        }
    }
    /* We can't assert anything about end vs addr as there could be a lot of
     * padding on a realloc-shrunk object (i#1232).
     */
    ASSERT(!found || addr+sz >= start - options.redzone_size,
           "bug in delay free overlap calc");
    if (found) {
        /* For the Note labels, we do want to mention overlap with freed redzones,
         * but we try to avoid overlap with memalign pre-padding (i#94).
         */
        if (!options.delay_frees_stack || etp->free_pcs != NULL) {
            etp->free_start = start;
            etp->free_size = end - start;
        }
        /* Don't label an access to a freed redzone as a use-after-free, as
         * it can easily be an underflow from an adjacent live malloc.
         * We'll still list it as "N bytes beyond memory that was freed".
         * We do want to include access to freed padding.
         *
         * Also don't label a free list entry without a callstack as a
         * use-after-free, as it could be an artificial free from something
         * like the pre-alloc padding for memalign (i#94).
         * If !options.delay_frees_stack we label it anyway: better to properly
         * label real use-after-free and have bad labeling for rare memalign
         * underflow.
         */
        if (addr < (byte *) ALIGN_FORWARD(end, MALLOC_CHUNK_ALIGNMENT) &&
            addr+sz >= etp->free_start &&
            (!options.delay_frees_stack || etp->free_pcs != NULL))
            etp->use_after_free = true;
    }
}

/* PR 535568: report nearest mallocs and whether freed.
 * XXX PR 423750: provide this info on dups not just 1st unique.
 */
static void
report_heap_info(IN error_toprint_t *etp, OUT char *buf, size_t bufsz, size_t *sofar,
                 app_pc addr, size_t sz, bool invalid_heap_arg, bool for_log)
{
    void *drcontext = dr_get_current_drcontext();
    ssize_t len = 0;

    if (etp->on_stack) {
        /* If the offset is negative, we've messed up somewhere.  We do not want to
         * report a negative offset (xref crbug.com/594614).  We still report the
         * unaddr so someone will investigate and report an issue.
         */
        if (addr > etp->xsp) {
            DO_ONCE({
                WARN("WARNING: stack addressability messed up: stack-internal unaddr!");
            });
        } else {
            BUFPRINT(buf, bufsz, *sofar, len,
                     "%s"PFX" refers to %d byte(s) beyond the top of the stack "PFX NL,
                     INFO_PFX, addr, etp->xsp - addr, etp->xsp);
        }
    }

    if (etp->next_start != NULL) {
        if (etp->next_start - addr+sz < 8 && etp->next_start >= addr+sz) {
            BUFPRINT(buf, bufsz, *sofar, len,
                     "%srefers to %d byte(s) before next malloc"NL,
                     INFO_PFX, etp->next_start - addr+sz-1);
        }
        if (!options.brief) {
            BUFPRINT(buf, bufsz, *sofar, len,
                     "%snext higher malloc: "PFX"-"PFX""NL,
                     INFO_PFX, etp->next_start, etp->next_start+etp->next_size);
        }
    }
    if (etp->prev_end != NULL) {
        if (addr - etp->prev_end < 8) {
            BUFPRINT(buf, bufsz, *sofar, len,
                     "%srefers to %d byte(s) beyond last valid byte in prior malloc"NL,
                     /* I used to have +1 to avoid "0 bytes" but
                      * I think that's more confusing then it helps
                      */
                     INFO_PFX, addr - etp->prev_end);
        }
        if (!options.brief) {
            BUFPRINT(buf, bufsz, *sofar, len,
                     "%sprev lower malloc:  "PFX"-"PFX""NL, INFO_PFX,
                     etp->prev_end-etp->prev_size, etp->prev_end);
        }
    }
    if (!options.brief && etp->neighbor_pcs != NULL) {
        symbolized_callstack_t scs;
        BUFPRINT(buf, bufsz, *sofar, len, "%sallocated here:"NL, INFO_PFX);
        /* to get var-align we need to convert to symbolized.
         * if we remove var-align feature, should use direct
         * packed_callstack_print and avoid this extra work
         */
        packed_callstack_to_symbolized(etp->neighbor_pcs, &scs);
        symbolized_callstack_print(&scs, buf, bufsz, sofar,
                                   info_cstack_pfx, for_log);
        symbolized_callstack_free(&scs);
    }

    if (etp->free_start != NULL) {
        /* Note that due to the finite size of the delayed
         * free list (and realloc not on it: PR 493888) and
         * new malloc entries replacing invalid we can't
         * guarantee to identify use-after-free
         */
        app_pc end = etp->free_start + etp->free_size;
        if (invalid_heap_arg && addr == etp->free_start) {
            BUFPRINT(buf, bufsz, *sofar, len,
                     "%smemory was previously freed", INFO_PFX);
        } else if (addr < end && addr+sz >= etp->free_start) {
            if (options.brief) {
                BUFPRINT(buf, bufsz, *sofar, len, "%srefers to ", INFO_PFX);
                if (addr > etp->free_start) {
                    BUFPRINT(buf, bufsz, *sofar, len, "%d byte(s) into ",
                             addr - etp->free_start);
                }
                BUFPRINT(buf, bufsz, *sofar, len, "memory that was freed");
            } else {
                BUFPRINT(buf, bufsz, *sofar, len,
                         "%s"PFX"-"PFX" overlaps memory "PFX"-"PFX" that was freed",
                         INFO_PFX, addr, addr+sz, etp->free_start, end);
            }
        } else {
            /* Refers to padding or redzone, so an overflow/underflow and not
             * really a "use-after-freee".
             */
            if (options.brief)
                BUFPRINT(buf, bufsz, *sofar, len, "%srefers to ", INFO_PFX);
            else {
                BUFPRINT(buf, bufsz, *sofar, len, "%s"PFX"-"PFX" is ", INFO_PFX,
                         addr, addr+sz);
            }
            if (addr < etp->free_start) {
                BUFPRINT(buf, bufsz, *sofar, len, "%d byte(s) before ",
                         etp->free_start - addr);
            } else {
                ASSERT(addr >= end, "check above should have caught this");
                /* XXX: not doing the +1: doesn't "0 bytes beyond" seem ok? */
                BUFPRINT(buf, bufsz, *sofar, len, "%d byte(s) beyond ", addr - end);
            }
            if (options.brief)
                BUFPRINT(buf, bufsz, *sofar, len, "memory that was freed");
            else {
                BUFPRINT(buf, bufsz, *sofar, len, "memory "PFX"-"PFX" that was freed",
                         etp->free_start, end);
            }
        }
        if (etp->free_pcs != NULL) {
            symbolized_callstack_t scs;
            BUFPRINT(buf, bufsz, *sofar, len, " here:"NL);
            /* Not ideal: see comment about using packed_callstack_print above */
            packed_callstack_to_symbolized(etp->free_pcs, &scs);
            symbolized_callstack_print(&scs, buf, bufsz, sofar, info_cstack_pfx,
                                       for_log);
            symbolized_callstack_free(&scs);
        } else
            BUFPRINT(buf, bufsz, *sofar, len, NL);
    }
    /* For wrapping, overlaps_delayed_free gives us a clone */
    if (etp->free_pcs != NULL && !options.replace_malloc)
        packed_callstack_free(etp->free_pcs);
    if (!invalid_heap_arg && alloc_in_heap_routine(drcontext)) {
        BUFPRINT(buf, bufsz, *sofar, len,
                 "%s<inside heap routine and may be false positive: please file a bug>"NL,
                 INFO_PFX);
    }
}

#ifdef USE_DRSYMS
static void
report_symbol_advice(void)
{
    drsym_debug_kind_t kind;
    drsym_error_t res = drsym_get_module_debug_kind(app_path, &kind);
    if (res != DRSYM_SUCCESS || !TESTANY(DRSYM_DWARF_LINE|DRSYM_PDB, kind)) {
        ELOGF(0, f_results, NL);
        NOTIFY_COND(true, f_results,
                    "WARNING: application is missing line number information."NL);
        if (res == DRSYM_SUCCESS && TEST(DRSYM_PECOFF_SYMTAB, kind)) {
            NOTIFY_COND(true, f_results,
                  "Re-compile with the -ggdb flag to include DWARF2 line numbers."NL);
        }
    }
}
#endif

/* Prints error reports to their various files:
 * + stderr: if -results_to_stderr, uses -callstack_style
 * + f_results: if using drsyms, uses -callstack_style
 * + f_global: for postprocessing, uses PRINT_FOR_POSTPROCESS
 * + logfile: if -thread_logs, uses PRINT_FOR_POSTPROCESS
 */
static void
print_error_report(void *drcontext, char *buf, size_t bufsz, bool reporting,
                   error_toprint_t *etp, stored_error_t *err,
                   error_callstack_t *ecs)
{
#ifdef USE_DRSYMS
    /* First, if using drsyms, print the report with user's -callstack_style to
     * f_results and stderr if -results_to_stderr.
     */
    if (reporting) {
        bool potential = (err != NULL && err->potential);
        print_error_to_buffer(buf, bufsz, etp, err, ecs, false/*for log*/);
        report_error_from_buffer(potential ? f_potential : f_results, buf, false);
        if (options.results_to_stderr && !potential) {
            report_error_from_buffer(STDERR, buf, true);
        }
    }
#endif

    /* Next, print to the log to support postprocessing.  Only print suppressed
     * errors if -log_suppressed_errors or at higher verbosity.
     */
    if (etp->errtype < ERROR_MAX_VAL
        IF_DRSYMS(&& (reporting || options.log_suppressed_errors ||
                      options.verbose >= 2))) {
        print_error_to_buffer(buf, bufsz, etp, err, ecs, true/*for log*/);
        report_error_from_buffer(f_global, buf, false);
        if (options.thread_logs) {
            report_error_from_buffer(LOGFILE_GET(drcontext), buf, false);
        }
    }
}

static char *
report_alloc_buf(void *drcontext, size_t *bufsz)
{
    char *buf;
    if (drcontext == NULL ||
        drmgr_get_tls_field(drcontext, tls_idx_report) == NULL) {
        /* at exit time, thread already cleaned up */
        *bufsz = MAX_ERROR_INITIAL_LINES + max_callstack_size();
        buf = (char *) global_alloc(*bufsz, HEAPSTAT_CALLSTACK);
    } else {
        tls_report_t *pt = (tls_report_t *)
            drmgr_get_tls_field(drcontext, tls_idx_report);
        buf = pt->errbuf;
        *bufsz = pt->errbufsz;
    }
    buf[0] = '\0';
    return buf;
}

static void
report_free_buf(void *drcontext, char *buf, size_t bufsz)
{
    if (drcontext == NULL ||
        drmgr_get_tls_field(drcontext, tls_idx_report) == NULL) {
        global_free(buf, bufsz, HEAPSTAT_CALLSTACK);
    }
}

#ifdef WINDOWS
static void
report_core_dump(error_toprint_t *etp, uint flags, uint id, dr_mcontext_t *mc)
{
    /* We create a local CONTEXT var to make it easier to swap to the app's
     * context within the ldmp.  i#600 covers adding proper debugger support and
     * i#549 covers creating a minidump with app state.
     */
    CONTEXT cxt;
    dr_memory_dump_spec_t spec;
    char ldmp_path[MAXIMUM_PATH];
    spec.size = sizeof(spec);
    spec.flags = DR_MEMORY_DUMP_LDMP;
    spec.label = "Dr. Memory error report dump";
    spec.ldmp_path = ldmp_path;
    spec.ldmp_path_size = BUFFER_SIZE_BYTES(ldmp_path);
    /* Syscalls should already have mc->pc filled in */
    if (etp->loc != NULL && etp->loc->type == APP_LOC_PC)
        mc->pc = loc_to_pc(etp->loc);
    if (!dr_mcontext_to_context(&cxt, mc))
        NOTIFY_ERROR("Failed to set CONTEXT for ldmp"NL);
    if (!dr_create_memory_dump(&spec))
        NOTIFY_ERROR("Failed to create ldmp"NL);
    else {
        NOTIFY("%smemory dump created at %s"NL, INFO_PFX, ldmp_path);
        NULL_TERMINATE_BUFFER(ldmp_path);
    }
}
#endif

static void
report_pause_at_error(error_toprint_t *etp, dr_mcontext_t *mc, const char *msg)
{
#ifdef WINDOWS
    /* We create a local CONTEXT var to make it easier to swap to the app's
     * context within the debugger.  i#600 covers adding proper debugger support.
     */
    CONTEXT cxt;
    /* Syscalls should already have mc->pc filled in */
    if (etp->loc != NULL && etp->loc->type == APP_LOC_PC)
        mc->pc = loc_to_pc(etp->loc);
    if (!dr_mcontext_to_context(&cxt, mc))
        NOTIFY_ERROR("Failed to set CONTEXT for ldmp"NL);
#endif
    wait_for_user(msg);
}

/* pcs is only used for invalid heap args */
static void
report_error(error_toprint_t *etp, dr_mcontext_t *mc, packed_callstack_t *pcs)
{
    void *drcontext = dr_get_current_drcontext();
    char fuzzer_buf[FUZZER_MSG_SZ];
    stored_error_t *err;
    bool reporting = false;
    suppress_spec_t *spec;
    error_callstack_t ecs;
    char  *errbuf;
    size_t errbufsz;

#ifdef USE_DRSYMS
    /* we do not want to use dbghelp at init time b/c that's too early so we
     * only check symbols and give warnings if we end up reporting something
     */
    static bool reported_any_error;
    if (!reported_any_error) {
        report_symbol_advice();
        reported_any_error = true;
    }
#endif

    error_callstack_init(&ecs);
    if (mc != NULL)
        etp->xsp = (byte *) mc->xsp;

    /* Our report_max throttling is post-dup-checking, to make the option
     * useful (else if 1st error has 20K instances, won't see any others).
     * Also, num_reported_errors doesn't count suppressed errors.
     * If -log_suppressed_errors is on, suppressed errors are printed to the log
     * until report_max is reached so they can fill it up.
     * If perf of dup check or suppression matching is an issue
     * we can add -report_all_max or something.
     */
    if (options.report_max >= 0 &&
        /* We do combined-total throttling to avoid perf hit, at cost of throttling
         * real errors if too many system-lib.
         */
        num_reported_errors[ERROR_NORMAL] + num_reported_errors[ERROR_POTENTIAL] >=
        options.report_max) {
        /* XXX: we can't split normal vs potential b/c we don't want to take
         * the time to symbolize.  We still want a num_reported_errors split
         * to report whether there are any.
         */
        num_throttled_errors++;
        DO_ONCE({
            NOTIFY(NL);
            NOTIFY("Reached maximum error report limit (-report_max). "
                   "No further errors will be reported."NL);
            ELOGF(0, f_results, NL"Reached maximum error report limit (-report_max). "
                  "No further errors will be reported."NL);
        });
        goto report_error_done;
    }

    /* Disassemble the current instruction if its generally included in a report
     * of this type.
     */
    if (etp->report_instruction &&
        etp->loc != NULL && etp->loc->type == APP_LOC_PC) {
        app_pc cur_pc = loc_to_pc(etp->loc);
        if (cur_pc != NULL) {
            /* We need to match old DR disasm style for compatibility */
            IF_DEBUG(disassemble_set_syntax(DR_DISASM_NO_OPND_SIZE));
            DR_TRY_EXCEPT(drcontext, {
                int dis_len;
                disassemble_to_buffer(drcontext, cur_pc, cur_pc, false/*!show pc*/,
                                      false/*!show bytes*/, ecs.instruction,
                                      BUFFER_SIZE_BYTES(ecs.instruction), &dis_len);
                NULL_TERMINATE_BUFFER(ecs.instruction);
                if (dis_len > 0) {
                    /* XXX: should DR provide control over its newline?
                     * We're not showing bytes, so the only one will be at the
                     * end, which we fix up.
                     */
                    ASSERT(ecs.instruction[dis_len -1] == '\n', "missing newline");
                    while (dis_len > 0 &&
                           (ecs.instruction[dis_len - 1] == '\n' ||
                            /* remove trailing space(s) too */
                            ecs.instruction[dis_len - 1] == ' ')) {
                        ecs.instruction[dis_len - 1] = '\0';
                        dis_len--;
                    }
                }
            }, { /* EXCEPT */
                /* nothing: just skip it */
            });
            /* Restore for our debugging logs */
            IF_DEBUG(disassemble_set_syntax(0));
        }
    }

    /* i#838: If we have a wildcard suppression covering this module for this
     * error type, don't bother taking the stack trace, unless we need to log
     * it.
     */
    if (have_module_wildcard IF_DRSYMS(&& !options.log_suppressed_errors)) {
        if (report_in_suppressed_module(etp->errtype, etp->loc, ecs.instruction)) {
            goto report_error_done;
        }
    }

    err = record_error(etp->errtype, pcs, etp->loc, mc, false/*no lock */);
    if (err->count > 1) {
        if (err->suppressed) {
            /* Suppression count is total, not unique callstacks (i#1527) */
            err->suppress_spec->count_used++;
            if (err->suppressed_by_default)
                num_suppressions_matched_default++;
            else
                num_suppressions_matched_user++;
        } else {
            ASSERT(err->id != 0, "duplicate should have id");
            /* We want -pause_at_un* to pause at dups so we consider it "reporting" */
            reporting = true;
        }
        if (!options.show_duplicates) {
            dr_mutex_unlock(error_lock);
            goto report_error_done;
        }
    }
    ASSERT(options.show_duplicates || err->id == 0, "non-duplicate should not have id");

    /* for invalid heap arg, now that we always do our alloc pre-hook in the
     * callee, the first frame is a retaddr and its line should thus be -1
     * (except for -replace_malloc)
     */
    if (!options.replace_malloc && etp->errtype == ERROR_INVALID_HEAP_ARG)
        packed_callstack_first_frame_retaddr(err->pcs);

    /* Convert to symbolized so we can compare to suppressions */
    packed_callstack_to_symbolized(err->pcs, &ecs.scs);

    if (err->count == 1) {
        reporting = !on_suppression_list(etp->errtype, &ecs, &spec);
        if (!reporting) {
            err->suppressed = true;
            err->suppressed_by_default = spec->is_default;
            err->suppress_spec = spec;
            if (err->suppress_spec->is_default)
                num_suppressions_matched_default++;
            else
                num_suppressions_matched_user++;
            num_total[ERROR_NORMAL][etp->errtype]--;
        } else if (error_is_likely_false_positive(&ecs, etp)) {
            err->potential = true;
            acquire_error_number(err);
            /* Adjust counter set by record_error() */
            num_total[ERROR_NORMAL][err->errtype]--;
            num_total[ERROR_POTENTIAL][err->errtype]++;
            LOG(2, "Error starts with system libs => separating as 'potential' error\n");
            /* We count toward the throttle threshold (we document this in -report_max
             * and -report_leak_max docs).
             */
            num_reported_errors[ERROR_POTENTIAL]++;
        } else {
            acquire_error_number(err);
            report_error_suppression(etp->errtype, &ecs, err->id);
            num_reported_errors[ERROR_NORMAL]++;
        }
    }
    dr_mutex_unlock(error_lock);

    if (fuzzer_error_report(drcontext, fuzzer_buf, FUZZER_MSG_SZ, err->id) > 0)
        etp->fuzzer_msg = fuzzer_buf;
    else
        etp->fuzzer_msg = NULL;

    errbuf = report_alloc_buf(drcontext, &errbufsz);
    print_error_report(drcontext, errbuf, errbufsz, reporting, etp, err, &ecs);
    report_free_buf(drcontext, errbuf, errbufsz);

 report_error_done:
    symbolized_callstack_free(&ecs.scs);
#ifdef WINDOWS
    /* don't create dumps for dup errors or potential errors */
    if (TEST(error_mask[etp->errtype], options.dump_at_error_mask) &&
        reporting && err->count == 1 && !err->potential) {
        report_core_dump(etp, options.dump_at_error_mask, err->id, mc);
    }
#endif
    if (reporting && !err->potential) { /* don't pause at a "potential error" */
        if (etp->errtype == ERROR_UNADDRESSABLE && options.pause_at_unaddressable)
            report_pause_at_error(etp, mc, "pausing at unaddressable access error");
        else if (etp->errtype == ERROR_UNDEFINED && options.pause_at_uninitialized)
            report_pause_at_error(etp, mc, "pausing at uninitialized read error");
        else if (options.pause_at_error)
            report_pause_at_error(etp, mc, "pausing at error");
        else if (options.crash_at_error ||
                 (options.crash_at_unaddressable &&
                  etp->errtype == ERROR_UNADDRESSABLE)) {
            NOTIFY(NL);
            NOTIFY("TERMINATING PROCESS after first %serror found"NL,
                   options.crash_at_error ? "" : "unaddressable ");
            crash_process();
            ASSERT_NOT_REACHED();
        }
    }
}

static void
print_error_to_buffer(char *buf, size_t bufsz, error_toprint_t *etp,
                      stored_error_t *err, error_callstack_t *ecs, bool for_log)
{
    ssize_t len = 0;
    size_t sofar = 0;
    app_pc addr = etp->addr;
    app_pc addr_end = etp->addr + etp->sz;

    /* ensure starts at beginning of line (can be in middle of another log) */
    if (!options.thread_logs)
        BUFPRINT(buf, bufsz, sofar, len, ""NL);
    if (err != NULL && err->suppressed)
        BUFPRINT(buf, bufsz, sofar, len, "SUPPRESSED ");

    /* For Linux and ESXi, postprocess.pl will produce the official
     * error numbers (after symbol suppression might remove some errors).
     * But we still want error numbers here, so that we can refer to them
     * when we list the duplicate counts at the end of the run, and
     * also for PR 423750 which will say "Error #n: reading 0xaddr".
     * On Windows for USE_DRSYMS these are the official error numbers.
     */
    if (err != NULL) {
        BUFPRINT(buf, bufsz, sofar, len, "%sError #%d: ",
                 err->potential ? POTENTIAL_PREFIX_CAP " " : "", err->id);
    }

    if (etp->report_neighbors) {
        /* Gather info up front so we can tweak the title line (i#1593) */
        gather_heap_info(etp, addr, etp->sz);
    }

    if (etp->errtype == ERROR_UNADDRESSABLE) {
        /* i#1593: we now add a label for sub-categories of unaddr to the title */
        const char *subtitle = "";
        if (etp->use_after_free)
            subtitle = " of freed memory";
        else if (etp->on_stack)
            subtitle = " beyond top of stack";
        else if (etp->on_heap)
            subtitle = " beyond heap bounds";
        BUFPRINT(buf, bufsz, sofar, len,
                 "UNADDRESSABLE ACCESS%s: %s", subtitle,
                 etp->access_type == DR_MEMPROT_WRITE ? "writing " :
                 (etp->access_type == DR_MEMPROT_EXEC ? "executing " : "reading "));
        if (!options.brief)
            BUFPRINT(buf, bufsz, sofar, len, PFX"-"PFX" ", addr, addr_end);
        BUFPRINT(buf, bufsz, sofar, len, "%d byte(s)", etp->sz);
        /* only report for syscall params or large (string) ops: always if subset */
        if (!options.brief && etp->container_start != NULL &&
            (etp->container_end - etp->container_start > 8 ||
             addr > etp->container_start || addr_end < etp->container_end ||
             etp->loc->type == APP_LOC_SYSCALL)) {
            ASSERT(etp->container_end > etp->container_start, "invalid range");
            BUFPRINT(buf, bufsz, sofar, len, " within "PFX"-"PFX""NL,
                     etp->container_start, etp->container_end);
        } else
            BUFPRINT(buf, bufsz, sofar, len, NL);
    } else if (etp->errtype == ERROR_UNDEFINED) {
        BUFPRINT(buf, bufsz, sofar, len, "UNINITIALIZED READ: ");
        if (addr < (app_pc)(64*1024)) {
            /* We use a hack to indicate registers.  These addresses should
             * be unadressable, not undefined, if real addresses.
             * FIXME: use dr_loc_t here as well for cleaner multi-type
             */
            BUFPRINT(buf, bufsz, sofar, len,
                     "reading register %s"NL, (addr == (app_pc)REG_EFLAGS) ?
                     "eflags" : get_register_name((reg_id_t)(ptr_uint_t)addr));
        } else {
            BUFPRINT(buf, bufsz, sofar, len, "reading ");
            if (!options.brief) {
                BUFPRINT(buf, bufsz, sofar, len, PFX"-"PFX" ", addr, addr_end);
            }
            BUFPRINT(buf, bufsz, sofar, len, "%d byte(s)", etp->sz);
            /* only report for syscall params or large (string) ops: always if subset */
            if (!options.brief && etp->container_start != NULL &&
                (etp->container_end - etp->container_start > 8 ||
                 addr > etp->container_start || addr_end < etp->container_end ||
                 etp->loc->type == APP_LOC_SYSCALL)) {
                ASSERT(etp->container_end > etp->container_start, "invalid range");
                BUFPRINT(buf, bufsz, sofar, len, " within "PFX"-"PFX""NL,
                         etp->container_start, etp->container_end);
            } else
                BUFPRINT(buf, bufsz, sofar, len, ""NL);
        }
    } else if (etp->errtype == ERROR_INVALID_HEAP_ARG) {
        /* Note that on Windows the call stack will likely show libc, since
         * we monitor Rtl inside ntdll
         */
        ASSERT(etp->msg != NULL, "invalid arg");
        BUFPRINT(buf, bufsz, sofar, len,
                 "INVALID HEAP ARGUMENT%s", etp->msg);
        /* Only print address when reporting neighbors */
        if (!options.brief && etp->aux_pcs == NULL && etp->report_neighbors)
            BUFPRINT(buf, bufsz, sofar, len, " "PFX, addr);
        BUFPRINT(buf, bufsz, sofar, len, NL);
    } else if (etp->errtype == ERROR_WARNING) {
        ASSERT(etp->msg != NULL, "invalid arg");
        BUFPRINT(buf, bufsz, sofar, len, "%sWARNING: %s"NL,
                 /* if in log file, distinguish from internal warnings via "REPORTED" */
                 (for_log ? "REPORTED " : ""), etp->msg);
#ifdef WINDOWS
    } else if (etp->errtype == ERROR_GDI_USAGE ||
               etp->errtype == ERROR_HANDLE_LEAK) {
        ASSERT(etp->msg != NULL, "invalid arg");
        BUFPRINT(buf, bufsz, sofar, len, "%s: %s"NL,
                 suppress_name[etp->errtype], etp->msg);
#endif
    } else if (etp->errtype >= ERROR_LEAK &&
               etp->errtype <= ERROR_MAX_LEAK) {
        if (etp->label != NULL)
            BUFPRINT(buf, bufsz, sofar, len, etp->label);
        BUFPRINT(buf, bufsz, sofar, len, "LEAK %d ", etp->sz);
        if (etp->indirect_size > 0 || !options.brief)
            BUFPRINT(buf, bufsz, sofar, len, "direct ");
        BUFPRINT(buf, bufsz, sofar, len, "bytes ");
        if (!options.brief)
            BUFPRINT(buf, bufsz, sofar, len, PFX"-"PFX" ", addr, addr_end);
        if (etp->indirect_size > 0 || !options.brief) {
            BUFPRINT(buf, bufsz, sofar, len,
                     "+ %d indirect bytes", etp->indirect_size);
        }
        BUFPRINT(buf, bufsz, sofar, len, NL);
    } else {
        ASSERT(false, "unknown error type");
        BUFPRINT(buf, bufsz, sofar, len,
                 "UNKNOWN ERROR TYPE: REPORT THIS BUG"NL);
    }

    if (ecs->scs.num_frames == 0) {
        if (type_is_leak(etp->errtype)) {
            BUFPRINT(buf, bufsz, sofar, len,
                     "<memory was allocated before tool took control>"NL);
        } else {
            BUFPRINT(buf, bufsz, sofar, len, "<empty callstack>"NL);
        }
    } else
        symbolized_callstack_print(&ecs->scs, buf, bufsz, &sofar, NULL, for_log);

    /* Print the timestamp for non-leak reports, unless -brief. */
    if (etp->errtype < ERROR_LEAK && !options.brief) {
        BUFPRINT(buf, bufsz, sofar, len, "%s", INFO_PFX);
        print_timestamp_and_thread(buf, bufsz, &sofar, true);
    }

    if (etp->report_neighbors) {
        /* print auxiliary info about the target address (PR 535568) */
        report_heap_info(etp, buf, bufsz, &sofar, addr, etp->sz,
                         etp->errtype == ERROR_INVALID_HEAP_ARG, for_log);
    }
    if (etp->aux_msg != NULL)
        BUFPRINT(buf, bufsz, sofar, len, "%s", etp->aux_msg);
    if (etp->aux_pcs != NULL) {
        symbolized_callstack_t scs;
        /* to get var-align we need to convert to symbolized.
         * if we remove var-align feature, should use direct packed_callstack_print
         * and avoid this extra work
         */
        packed_callstack_to_symbolized(etp->aux_pcs, &scs);
        symbolized_callstack_print(&scs, buf, bufsz, &sofar, aux_cstack_pfx, for_log);
        symbolized_callstack_free(&scs);
    }

    if (!options.brief && ecs->instruction[0] != '\0') {
        BUFPRINT(buf, bufsz, sofar, len, "%sinstruction: %s"NL,
                 INFO_PFX, ecs->instruction);
    }

    if (etp->fuzzer_msg != NULL)
        BUFPRINT(buf, bufsz, sofar, len, etp->fuzzer_msg);

    if (!for_log && !options.check_leaks && type_is_leak(etp->errtype)) {
        BUFPRINT(buf, bufsz, sofar, len,
                 "   (run with -check_leaks to obtain a callstack)"NL);
    }

    if (for_log)
        BUFPRINT(buf, bufsz, sofar, len, "%s", END_MARKER);
}

#define UNADDR_MSG_SZ 0x100
void
report_unaddr_warning(app_loc_t *loc, dr_mcontext_t *mc, const char *msg,
                      app_pc addr, size_t sz, bool report_instruction)
{
    char buf[UNADDR_MSG_SZ];
    ssize_t len = 0;
    size_t sofar = 0;
    ASSERT(strlen(msg) < (UNADDR_MSG_SZ/2), "msg is too large");
    BUFPRINT(buf, UNADDR_MSG_SZ, sofar, len, "%s "PFX"-"PFX,
             msg, addr, addr + sz, sz);
    report_warning(loc, mc, buf, addr, sz, report_instruction);
}

void
report_unaddressable_access(app_loc_t *loc, app_pc addr, size_t sz,
                            uint access_type, /* DR_MEMPROT_ flag */
                            app_pc container_start, app_pc container_end,
                            dr_mcontext_t *mc)
{
    error_toprint_t etp = {0};
    app_pc redzone_start, app_start, app_end;
    char buf[UNADDR_MSG_SZ];
    etp.errtype = ERROR_UNADDRESSABLE;
    etp.loc = loc;
    etp.addr = addr;
    etp.sz = sz;
    etp.access_type = access_type;
    etp.container_start = container_start;
    etp.container_end = container_end;
    etp.report_instruction = true;
    etp.report_neighbors = true;
    etp.aux_pcs = NULL;
    if (options.track_origins_unaddr && options.redzone_size > 0 &&
        region_in_redzone(addr, sz, &etp.aux_pcs,
                          &app_start, &app_end, &redzone_start, NULL) &&
        /* XXX: we really have no idea whether this came from an uninit var that
         * points at redzone_start b/c of the fill we did, or whether it's an
         * overflow/underflow instead. So we only report possible origins
         * if it points to redzone_start, which may miss some origin reports,
         * but also fewer wrong origin reports.
         */
        redzone_start == addr) {
        ssize_t len = 0;
        size_t sofar = 0;
        ASSERT(etp.aux_pcs != NULL, "aux_pcs must not be NULL");
        BUFPRINT(buf, UNADDR_MSG_SZ, sofar, len,
                 "%sthe unaddressable error may have been caused by using"
                 " an uninitialized"NL, INFO_PFX);
        BUFPRINT(buf, UNADDR_MSG_SZ, sofar, len,
                 "%svariable from memory "PFX"-"PFX" allocated here:"NL,
                 INFO_PFX, app_start, app_end);
        etp.aux_msg = buf;
    }
    report_error(&etp, mc, NULL);
}

void
report_undefined_read(app_loc_t *loc, app_pc addr, size_t sz,
                      app_pc container_start, app_pc container_end,
                      dr_mcontext_t *mc)
{
    error_toprint_t etp = {0};
    etp.errtype = ERROR_UNDEFINED;
    etp.loc = loc;
    etp.addr = addr;
    etp.sz = sz;
    etp.container_start = container_start;
    etp.container_end = container_end;
    etp.report_instruction = true;
    report_error(&etp, mc, NULL);
}

void
report_invalid_heap_arg(app_loc_t *loc, app_pc addr, dr_mcontext_t *mc,
                        const char *msg, bool is_free)
{
    if (is_free && addr == NULL) {
        /* free(NULL) is documented as always being properly handled (nop)
         * so we separate as not really "invalid" but just a warning
         */
        if (options.warn_null_ptr)
            report_warning(loc, mc, "free() called with NULL pointer", NULL, 0, false);
    } else {
        error_toprint_t etp = {0};
        etp.errtype = ERROR_INVALID_HEAP_ARG;
        etp.loc = loc;
        etp.addr = addr;
        etp.msg = msg;
        etp.report_neighbors = true;
        report_error(&etp, mc, NULL);
    }
}

#define MISMATCH_MSG_SZ 0x100
void
report_mismatched_heap(app_loc_t *loc, app_pc addr, dr_mcontext_t *mc,
                       const char *msg, packed_callstack_t *pcs)
{
    error_toprint_t etp = {0};
    char buf[MISMATCH_MSG_SZ];
    ssize_t len = 0;
    size_t sofar = 0;
    etp.errtype = ERROR_INVALID_HEAP_ARG;
    etp.loc = loc;
    etp.addr = addr;
    etp.msg = msg;
    etp.aux_pcs = pcs;
    if (etp.aux_pcs != NULL) {
        BUFPRINT(buf, BUFFER_SIZE_ELEMENTS(buf), sofar, len,
                 "%smemory was allocated here:"NL, INFO_PFX);
    } else {
        BUFPRINT(buf, BUFFER_SIZE_ELEMENTS(buf), sofar, len,
                 "%sre-run with -malloc_callstacks (or -count_leaks) to add the "
                 "allocation callstack."NL, INFO_PFX);
    }
    etp.aux_msg = buf;
    report_error(&etp, mc, NULL);
}

static void
report_misc_error(uint errtype, app_loc_t *loc, dr_mcontext_t *mc, const char *msg,
                  app_pc addr, size_t sz, bool report_instruction,
                  packed_callstack_t *pcs)
{
    error_toprint_t etp = {0};
    etp.errtype = errtype;
    etp.loc = loc;
    etp.addr = addr;
    etp.sz = sz;
    etp.msg = msg;
    etp.report_instruction = report_instruction;
    etp.report_neighbors = (sz > 0);
    report_error(&etp, mc, pcs);
}

/* FIXME i#947: add ability to suppress warning via label or msg-prefix */
void
report_warning(app_loc_t *loc, dr_mcontext_t *mc, const char *msg,
               app_pc addr, size_t sz, bool report_instruction)
{
    report_misc_error(ERROR_WARNING, loc, mc, msg, addr, sz, report_instruction, NULL);
}

#ifdef WINDOWS
void
report_gdi_error(app_loc_t *loc, dr_mcontext_t *mc, const char *msg,
                 packed_callstack_t *aux_pcs, const char *aux_msg)
{
    error_toprint_t etp = {0};
    etp.errtype = ERROR_GDI_USAGE;
    etp.loc = loc;
    etp.msg = msg;
    etp.aux_msg = aux_msg;
    etp.aux_pcs = aux_pcs;
    report_error(&etp, mc, NULL);
}

#define HANDLE_MSG_SZ 0x100
void
report_handle_leak(void *drcontext, dr_mcontext_t *mc, const char *msg,
                   app_loc_t *loc, packed_callstack_t *pcs,
                   packed_callstack_t *aux_pcs, bool potential)
{
    error_toprint_t etp = {0};
    char buf[HANDLE_MSG_SZ];
    etp.errtype = ERROR_HANDLE_LEAK;
    etp.loc     = loc;
    etp.addr    = NULL;
    etp.msg     = msg;
    etp.aux_pcs = aux_pcs;
    etp.potential = potential;
    if (aux_pcs != NULL) {
        ssize_t len   = 0;
        size_t  sofar = 0;
        BUFPRINT(buf, BUFFER_SIZE_ELEMENTS(buf), sofar, len,
                 "%shandles created with the same callstack are closed here:"NL,
                 INFO_PFX);
        etp.aux_msg = buf;
    }
    report_error(&etp, mc, pcs);
}
#endif

/* saves the values of all counts that are modified in report_leak() */
void
report_leak_stats_checkpoint(void)
{
    uint set, i;
    dr_mutex_lock(error_lock);
    saved_leaks_ignored = num_leaks_ignored;
    saved_suppressed_leaks_user = num_suppressed_leaks_user;
    saved_suppressed_leaks_default = num_suppressed_leaks_default;
    for (set = 0; set < ERROR_SET_NUM; set++) {
        for (i = ERROR_LEAK; i <= ERROR_MAX_LEAK; i++) {
            saved_unique[set][i] = num_unique[set][i];
            saved_total[set][i] = num_total[set][i];
            saved_bytes_leaked[set][i] = num_bytes_leaked[set][i];
        }
        saved_total_leaks[set] = num_total_leaks[set];
    }
    saved_throttled_leaks = num_throttled_leaks;
    dr_mutex_unlock(error_lock);
}

/* restores the values of all counts that are modified in report_leak() to their
 * values as recorded in the last report_leak_stats_checkpoint() call.
 */
void
report_leak_stats_revert(void)
{
    int set, i;
    dr_mutex_lock(error_lock);
    num_leaks_ignored = saved_leaks_ignored;
    num_suppressed_leaks_user = saved_suppressed_leaks_user;
    num_suppressed_leaks_default = saved_suppressed_leaks_default;
    for (set = 0; set < ERROR_SET_NUM; set++) {
        for (i = ERROR_LEAK; i <= ERROR_MAX_LEAK; i++) {
            num_unique[set][i] = saved_unique[set][i];
            num_total[set][i] = saved_total[set][i];
            num_bytes_leaked[set][i] = saved_bytes_leaked[set][i];
        }
        num_total_leaks[set] = saved_total_leaks[set];
    }
    num_throttled_leaks = saved_throttled_leaks;
    /* Clear leak error counts */
    for (i = 0; i < HASHTABLE_SIZE(error_table.table_bits); i++) {
        hash_entry_t *he;
        for (he = error_table.table[i]; he != NULL; he = he->next) {
            stored_error_t *err = (stored_error_t *) he->payload;
            if (type_is_leak(err->errtype)) {
                err->count = 0;
            }
        }
    }
    dr_mutex_unlock(error_lock);
}

void
report_leak(bool known_malloc, app_pc addr, size_t size, size_t indirect_size,
            bool early, bool reachable, bool maybe_reachable, uint shadow_state,
            packed_callstack_t *pcs, bool count_reachable, bool show_reachable)
{
    /* If not in a known malloc region it could be an unaddressable byte
     * that was erroneously written to (and we reported already) but
     * we then marked as defined to avoid further errors: so only complain
     * if in known malloc regions.
     */
    char *buf;
    size_t bufsz;
    void *drcontext = dr_get_current_drcontext();
    bool reporting = false;
    const char *label = NULL;
    bool locked_malloc = false;
    stored_error_t *err = NULL;
    uint type;
    uint set = ERROR_NORMAL;
    suppress_spec_t *spec;
    error_toprint_t etp = {0};
    error_callstack_t ecs;
    error_callstack_init(&ecs);

    /* Ignore reachable on extra iter from leak scan */
    if (reachable && !count_reachable)
        return;
    if (!known_malloc) {
        /* This is really a curiosity for developers: not an error for
         * addressable memory to remain within a heap region.
         */
        if (options.verbose < 2)
            return;
        label = "STILL-ADDRESSABLE ";
    }

    if (options.report_leak_max >= 0 &&
        /* Combined-total throttling just like for non-leaks */
        num_total_leaks[ERROR_NORMAL] + num_total_leaks[ERROR_POTENTIAL] >=
        options.report_leak_max) {
        num_throttled_leaks++;
        DO_ONCE({
            NOTIFY(NL);
            NOTIFY("Reached maximum leak report limit (-report_leak_max). "
                   "No further leaks will be reported."NL);
            ELOGF(0, f_results, NL"Reached maximum leak report limit (-report_leak_max). "
                  "No further leaks will be reported."NL);
        });
        return;
    }
    buf = report_alloc_buf(drcontext, &bufsz);
    num_total_leaks[ERROR_NORMAL]++;

    /* we need to know the type prior to dup checking */
    if (reachable && !early) {
        label = "REACHABLE ";
        type = ERROR_REACHABLE_LEAK;
    } else if (label != NULL) {  /* STILL-ADDRESSABLE */
        type = ERROR_MAX_VAL;
    } else if (early && options.ignore_early_leaks) {
        /* early reachable are ignored, since no callstack to act on */
        label = "IGNORED ";
        num_leaks_ignored++;
        type = ERROR_MAX_VAL;
    } else if (maybe_reachable) {
        label = "POSSIBLE ";
        type = ERROR_POSSIBLE_LEAK;
    } else {
        type = ERROR_LEAK;
    }

    /* protect counter updates below */
    dr_mutex_lock(error_lock);
    if (options.check_leaks) {
        /* Though the top frame makes less sense for leaks we do the same
         * top-frame check as for other error suppression.
         * FIXME PR 460923: support matching any prefix
         */
        if (!early && pcs == NULL) {
            locked_malloc = true;
            alloc_callstack_lock(); /* unlocked below */
            pcs = malloc_get_client_data(addr);
        }

        /* We check dups only for real and possible leaks.
         * We have no way to eliminate dups for !check_leaks.
         */
        if (type < ERROR_MAX_VAL) {
            ASSERT(pcs != NULL, "malloc must have callstack");
            err = record_error(type, pcs, NULL, NULL, true/*hold lock*/);
            set = ERROR_SET(err->potential);
            if (err->count > 1) {
                /* Duplicate */
                if (err->suppressed) {
                    ASSERT(err->suppress_spec != NULL, "missing suppress spec");
                    if (err->suppress_spec->is_default)
                        num_suppressed_leaks_default++;
                    else
                        num_suppressed_leaks_user++;
                    err->suppress_spec->bytes_leaked += size + indirect_size;
                } else {
                    /* We only count bytes for non-suppressed leaks */
                    /* Total size does not distinguish direct from indirect (PR 576032) */
                    num_bytes_leaked[set][type] += size + indirect_size;
                }
                DOLOG(3, {
                    LOG(3, "Duplicate leak of %d (%d indirect) bytes:\n",
                        size, indirect_size);
                    packed_callstack_log(err->pcs, f_global);
                });
                dr_mutex_unlock(error_lock);
                goto report_leak_done;
            }
        }

        /* Convert to symbolized so we can compare to suppressions.  Don't try
         * to get stacks for early leaks, leave ecs.scs with 0 frames.
         *
         * i#1852: to improve speed we don't symbolize reachable (and thus don't
         * support suppressing) when show_reachable is off and the only goal
         * is a count of unique instances.
         */
        if (!early && (!reachable || show_reachable)) {
            ASSERT(pcs != NULL, "non-early allocs must have stacks");
            packed_callstack_to_symbolized(pcs, &ecs.scs);
        }

        if (locked_malloc)
            alloc_callstack_unlock();

        /* only real, possible, and reachable leaks can be suppressed */
        if (type < ERROR_MAX_VAL) {
            if (reachable && !show_reachable)
                reporting = true; /* suppressions not supported: i#1852 */
            else
                reporting = !on_suppression_list(type, &ecs, &spec);
        }

        if (reporting && type < ERROR_MAX_VAL) {
            /* We can have identical leaks across nudges: keep same error #.
             * Multiple nudges are kind of messy wrt leaks: we try to not
             * increment counts or add new leaks that were there in the
             * last nudge, but we do re-print the callstacks so it's
             * easy to see all the nudges at that point.
             */
            if ((maybe_reachable && !options.possible_leaks) ||
                (reachable && !options.show_reachable))
                reporting = false;
            if (err->id == 0) {
                if (leak_is_likely_false_positive(&ecs)) {
                    err->potential = true;
                    set = ERROR_POTENTIAL;
                    if (reporting)
                        acquire_error_number(err);
                    /* Fix up the stats */
                    num_total_leaks[ERROR_NORMAL]--;
                    num_total_leaks[ERROR_POTENTIAL]++;
                    /* Adjust counter set by record_error() */
                    num_total[ERROR_NORMAL][type]--;
                    num_total[ERROR_POTENTIAL][type]++;
                    LOG(2, "Leak starts with system libs => hiding\n");
                } else {
                    if (reporting) {
                        acquire_error_number(err);
                        report_error_suppression(type, &ecs, err->id);
                    }
                }
                if (!reporting)
                    num_unique[ERROR_SET(err->potential)][err->errtype]++;
            } else {
                /* num_unique was set to 0 after nudge */
#ifdef STATISTICS /* for num_nudges */
                ASSERT(err->id == 0 || num_nudges > 0 ||
                       (maybe_reachable && !options.possible_leaks) ||
                       (reachable && !options.show_reachable),
                       "invalid dup error report!");
#endif
                num_unique[ERROR_SET(err)][err->errtype]++;
            }
            /* We only count bytes for non-suppressed leaks */
            /* Total size does not distinguish direct from indirect (PR 576032) */
            num_bytes_leaked[set][type] += size + indirect_size;
        } else if (type < ERROR_MAX_VAL) {
            bool already_supp = err->suppressed;
            ASSERT(err != NULL && spec != NULL, "invalid local");
            err->suppressed = true;
            err->suppressed_by_default = spec->is_default;
            err->suppress_spec = spec;
            if (err->suppress_spec->is_default)
                num_suppressed_leaks_default++;
            else
                num_suppressed_leaks_user++;
            err->suppress_spec->bytes_leaked += size + indirect_size;
            if (!already_supp)
                num_total[ERROR_NORMAL][type]--;
        }
    } else if (type < ERROR_MAX_VAL) {
        /* For -no_check_leaks, we still report leaks without callstacks and
         * count how many bytes were leaked.  Without callstacks, we can't
         * de-duplicate, and assume each leak is unique and not "potential".
         */
        num_unique[ERROR_NORMAL][type]++;
        num_bytes_leaked[set][type] += size + indirect_size;
        if (type == ERROR_LEAK ||
            (type == ERROR_POSSIBLE_LEAK && options.possible_leaks) ||
            (type == ERROR_REACHABLE_LEAK && show_reachable)) {
            reporting = true;
        }
    }

    /* Done modifying err and stats. */
    dr_mutex_unlock(error_lock);

    /* If possible leak checking is off, don't report them, just log them. */
    if (maybe_reachable && !options.possible_leaks)
        reporting = false;
    /* Ditto for reachable */
    if (reachable && !options.show_reachable)
        reporting = false;

    etp.errtype = type;
    etp.addr = addr;
    etp.sz = size;
    etp.indirect_size = indirect_size;
    etp.label = label;
    etp.xsp = NULL;

    print_error_report(drcontext, buf, bufsz, reporting, &etp, err, &ecs);

 report_leak_done:
    report_free_buf(drcontext, buf, bufsz);
    symbolized_callstack_free(&ecs.scs);
}

/* FIXME: have some report detail threshold or max log file size */
void
report_malloc(app_pc start, app_pc end, const char *routine, dr_mcontext_t *mc)
{
    DOLOG(3, {
        void *drcontext = dr_get_current_drcontext();
        tls_report_t *pt = (tls_report_t *) drmgr_get_tls_field(drcontext, tls_idx_report);
        ssize_t len = 0;
        size_t sofar = 0;
        BUFPRINT(pt->errbuf, pt->errbufsz, sofar, len,
                 "%s "PFX"-"PFX"\n", routine, start, end);
        print_callstack(pt->errbuf, pt->errbufsz, &sofar, mc, false/*no fps*/,
                        NULL, 0, true, options.callstack_max_frames);
        report_error_from_buffer(LOGFILE_GET(drcontext), pt->errbuf, false);
    });
}

void
report_heap_region(bool add, app_pc start, app_pc end, dr_mcontext_t *mc)
{
    DOLOG(3, {
        ssize_t len = 0;
        size_t sofar = 0;
        char *buf;
        size_t bufsz;
        void *drcontext = dr_get_current_drcontext();
        tls_report_t *pt = (tls_report_t *)
            ((drcontext == NULL) ? NULL : drmgr_get_tls_field(drcontext, tls_idx_report));
        if (pt == NULL) {
            /* at init time no pt yet */
            bufsz = MAX_ERROR_INITIAL_LINES + max_callstack_size();
            buf = (char *) global_alloc(bufsz, HEAPSTAT_CALLSTACK);
        } else {
            buf = pt->errbuf;
            bufsz = pt->errbufsz;
        }
        BUFPRINT(buf, bufsz, sofar, len,
                 "%s heap region "PFX"-"PFX"\n",
                 add ? "adding" : "removing", start, end);
        print_callstack(buf, bufsz, &sofar, mc, false/*no fps*/, NULL, 0, true,
                        options.callstack_max_frames);
        report_error_from_buffer(f_global, buf, false);
        if (pt == NULL)
            global_free(buf, bufsz, HEAPSTAT_CALLSTACK);
    });
}

#if DEBUG
/* To print call stacks at suspected error sites when actual errors aren't
 * reported.  Helps with debugging.  Unknown ioctl() system calls are an
 * example.  We just skip them and have no idea of who made the call, making it
 * harder to identify data structures to track.
 */
void
report_callstack(void *drcontext, dr_mcontext_t *mc)
{
    print_callstack_to_file(drcontext, mc, mc->pc, INVALID_FILE/*use pt->f*/,
                            options.callstack_max_frames);
}
#endif /* DEBUG */

void
report_child_thread(void *drcontext, thread_id_t child)
{
    /* XXX: should these go to results.txt instead?  Will be mixed in
     * w/ the errors, unless we cache their callstacks somewhere until
     * the end.
     */
    if (options.show_threads || options.show_all_threads) {
        tls_report_t *pt = (tls_report_t *) drmgr_get_tls_field(drcontext, tls_idx_report);
        ssize_t len = 0;
        size_t sofar = 0;

        dr_mcontext_t mc; /* do not init whole thing: memset is expensive */
        mc.size = sizeof(mc);
        mc.flags = DR_MC_CONTROL|DR_MC_INTEGER; /* don't need xmm */
        dr_get_mcontext(drcontext, &mc);

        ASSERT(!options.perturb_only, "-perturb_only should disable -show_threads");

        if (options.show_all_threads) {
            BUFPRINT(pt->errbuf, pt->errbufsz, sofar, len,
                     "\nNEW THREAD: child thread "TIDFMT" created by parent thread "
                     TIDFMT" @", child, dr_get_thread_id(drcontext));
            print_timestamp_and_thread(pt->errbuf, pt->errbufsz, &sofar, false);
            BUFPRINT(pt->errbuf, pt->errbufsz, sofar, len, "\n");
            print_callstack(pt->errbuf, pt->errbufsz, &sofar, &mc, false/*no fps*/,
                            NULL, 0, false, options.callstack_max_frames);
            BUFPRINT(pt->errbuf, pt->errbufsz, sofar, len, "\n");
            print_buffer(LOGFILE_GET(drcontext), pt->errbuf);
        } else {
            packed_callstack_t *pcs;
            /* XXX DRi#640: despite DRi#442, pc is no good here: points at wow64
             * do-syscall, so we pass NULL for app_loc_t and skip top frame
             */
            packed_callstack_record(&pcs, &mc, NULL, options.callstack_max_frames);
            dr_mutex_lock(thread_table_lock);
            hashtable_add(&thread_table, (void *)(ptr_int_t)child, (void *)pcs);
            dr_mutex_unlock(thread_table_lock);
        }
    }
}

/* We only symbolized and report thread callstacks when involved in an error (i#714) */
static void
report_delayed_thread(thread_id_t tid)
{
    packed_callstack_t *pcs;
    ASSERT(options.show_threads && !options.show_all_threads, "incorrect usage");
    dr_mutex_lock(thread_table_lock);
    pcs = (packed_callstack_t *)
        hashtable_lookup(&thread_table, (void *)(ptr_int_t)tid);
    if (pcs != NULL) {
        void *drcontext = dr_get_current_drcontext();
        ssize_t len = 0;
        size_t sofar = 0;
        /* we can't use pt->buf b/c we're in the middle of a report */
        size_t bufsz = MAX_ERROR_INITIAL_LINES + max_callstack_size();
        char *buf = (char *) global_alloc(bufsz, HEAPSTAT_CALLSTACK);
        BUFPRINT(buf, bufsz, sofar, len,
                 "\nNEW THREAD: thread id %d created here:\n", tid);
        packed_callstack_print(pcs, 0/*all frames*/,
                               buf, bufsz, &sofar, "");
        BUFPRINT(buf, bufsz, sofar, len, "\n");
        print_buffer(LOGFILE_GET(drcontext), buf);
        global_free(buf, bufsz, HEAPSTAT_CALLSTACK);
        /* we only need to report once */
        hashtable_remove(&thread_table, (void *)(ptr_int_t)tid);
    } else if (tid == main_thread && !main_thread_printed) {
        report_main_thread();
        main_thread_printed = true;
    }
    dr_mutex_unlock(thread_table_lock);
}

static void
report_main_thread(void)
{
    ELOG(0, "\nNEW THREAD: main thread "TIDFMT"\n\n", main_thread);
}
