/* **********************************************************
 * Copyright (c) 2010-2020 Google, Inc.  All rights reserved.
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
 * callstack.c: callstack recording
 */

#include "dr_api.h"
#include "drmgr.h"
#include "callstack.h"
#include "utils.h"
#include "redblack.h"
#ifdef USE_DRSYMS
# include "drsyms.h"
#endif
#include "drsyscall.h"
#ifdef UNIX
# include <string.h>
# include <errno.h>
#endif
#include <limits.h>

/* Options all have 0 as default value */
static callstack_options_t ops;

#ifdef WINDOWS
# define FP_PREFIX ""
#else
# define FP_PREFIX "\t"
#endif
#define LINE_PREFIX "    "

#ifdef STATISTICS
static uint callstack_walks;
static uint callstacks_symbolized;
static uint find_next_fp_scans;
static uint find_next_fp_cache_hits;
static uint find_next_fp_strings;
static uint find_next_fp_string_structs;
static uint cstack_is_retaddr_tgt_mismatch;
static uint symbol_names_truncated;
static uint cstack_is_retaddr;
static uint cstack_is_retaddr_backdecode;
static uint cstack_is_retaddr_unreadable;
static uint cstack_is_retaddr_unseen;
#endif

/* Cached frame pointer values to avoid repeated scans (i#1186) */
typedef struct _fpscan_cache_entry {
    byte *input_fp;
    byte *output_fp;
    app_pc retaddr;
} fpscan_cache_entry;

/* XXX: perhaps this should be based on the max frames, though if someone
 * asks for a ton of frames and optimizes his app with FPO he can't expect
 * great performance.
 */
#define FPSCAN_CACHE_ENTRIES 16

typedef struct _tls_callstack_t {
    char *errbuf; /* buffer for atomic writes to global logfile */
    size_t errbufsz;
    byte *page_buf; /* buffer for app stack safe read */
    app_pc stack_lowest_frame; /* optimization for recording callstacks */
    /* Optimization for Linux main thread, where normal-looking but
     * non-fp values can end up with a too-high stack_lowest_frame,
     * causing us to keep scanning into the argv/envp/auxv area.  Thus
     * for the main thread we store the retaddr of the call from the
     * executable entry point (_start).  Xref i#1186.
     */
    app_pc stack_lowest_retaddr;
    /* Optimization for FPO-optimized apps */
    fpscan_cache_entry fpcache[FPSCAN_CACHE_ENTRIES];
    uint fpcache_idx;
} tls_callstack_t;

static int tls_idx_callstack = -1;

/****************************************************************************
 * Binary callstacks for storing callstacks of allocation sites.
 * Print-format callstacks take up too much room (PR 424179).
 * We do NOT store the frame pointers, to save space.  They are
 * rarely needed in allocation site analysis.
 */

typedef union {
    app_pc addr;
    /* We need space for more than a 24-bit syscall number (size of modoffs)
     * and for a string identifying the param (PR 525269).  We just can't
     * fit that inline easily, and since syscalls are rare enough, we
     * have a pointer to out-of-line storage.
     */
    syscall_loc_t *sysloc;
} frame_loc_t;

/* Packed binary callstack */
/* i#954: using packed data structure so we can use memcmp for comparison */
START_PACKED_STRUCTURE
struct _packed_frame_t {
    frame_loc_t loc;
    /* Modules can move around, with the same module being at two
     * different locations, so we must store both the name (which is a
     * pointer into a never-removed-from module name hashtable) and
     * the offset.  We pack further using an array of names so we can
     * store an index here that is a single byte (if we hit >
     * 256 libraries we switch to full_frame_t) that shares a dword
     * with the module offset. That
     * limits the offset to 16MB.  For modules larger than that, we have
     * extra entries that are adjacent in the modname array.  The
     * hashtable holds the index of the first such entry.
     */
    uint modoffs : 24;
    /* For syscalls, we use index 0.  We do not store the syscall #
     * (it won't fit in modoffs) but rely on loc.sysloc.
     * For non-module addresses, we use index MAX_MODNAMES_STORED.
     */
    uint modname_idx : 8;
} END_PACKED_STRUCTURE;
typedef struct _packed_frame_t packed_frame_t;

/* Hashtable entry is the master entry.  modname_array and full frame field
 * point at same entry.
 */
typedef struct _modname_info_t {
    /* Both strings are strdup-ed */
    const char *name; /* "preferred" name */
    const char *path; /* name with full path */
    /* Index into modname_array, if one of the first MAX_MODOFFS_STORED module
     * names; else -1
     */
    int index;
    /* i#446: Unique module id for postprocessing. */
    uint id;
    /* i#589: don't show module! for executable or other modules */
    bool hide_modname;
    /* Avoid repeated warnings about symbols */
    bool warned_no_syms;
    /* Whether to abort an fp walk out of this module (i#703) */
    bool abort_fp_walk;
    /* i#1310: support user data */
    void *user_data;
} modname_info_t;

/* When the number of modules hits the max for our 8-bit index we
 * have to switch to these frames
 */
/* i#954: using packed data structure so we can use memcmp for comparison */
START_PACKED_STRUCTURE
struct _full_frame_t {
    frame_loc_t loc;
    size_t modoffs;
    /* For syscalls, we use MODNAME_INFO_SYSCALL and loc.sysloc.
     * For non-module addresses, we use NULL.
     */
    modname_info_t *modname;
} END_PACKED_STRUCTURE;
typedef struct _full_frame_t full_frame_t;

/* used to indicate syscall for full_frame_t (NULL indicates not in a module) */
static const modname_info_t MODNAME_INFO_SYSCALL;

#define MAX_MODOFFS_STORED (0x00ffffff)

struct _packed_callstack_t {
    /* share callstacks to save space (PR 465174) */
    uint refcount;
    /* variable-length to save space */
    ushort num_frames;
    /* whether frames are packed_frame_t or full_frame_t */
    bool is_packed:1;
    /* whether first frame is a retaddr (in which case we subtract 1 when printing line) */
    bool first_is_retaddr:1;
    /* whether first frame is a syscall (invariant: later frames never are) */
    bool first_is_syscall:1;
    union {
        packed_frame_t *packed;
        full_frame_t *full;
    } frames;
};

/* multiplexing between packed and full frames */
#define PCS_FRAME_LOC(pcs, n) \
    ((pcs)->is_packed ? (pcs)->frames.packed[n].loc : (pcs)->frames.full[n].loc)
#define PCS_FRAMES(pcs) \
    ((pcs)->is_packed ? (void*)((pcs)->frames.packed) : (void*)((pcs)->frames.full))
#define PCS_FRAME_SZ(pcs) \
    ((pcs)->is_packed ? sizeof(*(pcs)->frames.packed) : sizeof(*(pcs)->frames.full))

/* Hashtable that stores name info.  We never remove entries. */
#define MODNAME_TABLE_HASH_BITS 8
static hashtable_t modname_table;
static bool modname_table_initialized;

/* Array mapping index to name for use with packed_frame_t.
 * Points at same modname_info_t as hashtable entry.
 * Hashtable lock synchronizes writes; no synch on reads.
 */
#define MAX_MODNAMES_STORED UCHAR_MAX
static modname_info_t *modname_array[MAX_MODNAMES_STORED];
/* Index 0 is reserved to indicate a system call as the top frame of a callstack */
static uint modname_array_end = 1;

/* Unique id for looking up full module paths when postprocessing.  Protected by
 * modname_table lock.  0 means syscall or no module.
 */
static uint modname_unique_id = 1;

/* PR 473640: our own module region tree */
static rb_tree_t *module_tree;
static void *modtree_lock;
/* We maintain the modules w/ the lowest and highest addresses for quick
 * queries of stack addrs, etc.
 */
static app_pc modtree_min_start;
static app_pc modtree_max_end;
/* cached values for module_lookup */
static app_pc modtree_last_start;
static size_t modtree_last_size;
static modname_info_t *modtree_last_name_info;
/* cached values for is_in_module() */
static app_pc modtree_last_hit;
static app_pc modtree_last_miss;

/* i#1217: exclude DR and DrMem retaddrs on app stack from -replace_malloc */
static app_pc libdr_base, libdr_end;
static app_pc libtoolbase, libtoolend;

/****************************************************************************
 * Symbolized callstacks for comparing to suppressions.
 * We do not store these long-term except those we read from suppression file.
 * We need to print out to a max-size buffer anyway so we use fixed
 * arrays for the strings.
 */

struct _symbolized_frame_t {
    uint num;
    app_loc_t loc;
    /* For easier suppression comparison we store "<not in a module>" and
     * "system call ..." in func.  is_module distinguishes.
     */
    bool is_module;
    /* i#589: don't show module! for executable or other modules */
    bool hide_modname;
    /* i#635 i#603: Print offsets for frames without symbols. */
    bool has_symbols;
    /* i#446: Unique id of the module. */
    uint modid;
    /* We store the base for use in i#960 */
    app_pc modbase;
    char modname[MAX_MODULE_LEN+1]; /* always null-terminated */
    /* This is a string instead of a number, again for comparison w/ wildcards
     * in the modoffs in suppression frames
     */
    char modoffs[MAX_PFX_LEN+1]; /* always null-terminated */
    char func[MAX_FUNC_LEN+1]; /* always null-terminated */
    size_t funcoffs;
    char fname[MAX_FILENAME_LEN+1]; /* always null-terminated */
    uint64 line;
    size_t lineoffs;
    /* i#1310: copy the user_data from the corresponding modname_info_t */
    void *user_data;
};

/***************************************************************************/

/* i#1439: only allow retaddrs for calls we've seen */
#define RETADDR_TABLE_HASH_BITS 10
static hashtable_t retaddr_table;

static dr_emit_flags_t
event_basic_block_analysis(void *drcontext, void *tag, instrlist_t *bb,
                           bool for_trace, bool translating, OUT void **user_data);

static bool
module_lookup(byte *pc, app_pc *start OUT, size_t *size OUT, modname_info_t **name OUT);

static void
modname_info_free(void *p);

static void
warn_no_symbols(modname_info_t *name_info);

/***************************************************************************/

size_t
max_callstack_size(void)
{
    static const char *max_line = "\tfp=0x12345678 parent=0x12345678 0x12345678 <>"NL;
    size_t max_addr_sym_len = MAX_ADDR_LEN;
#ifdef USE_DRSYMS
    max_addr_sym_len += 1/*' '*/ + MAX_SYMBOL_LEN + 1/*\n*/ +
        strlen(LINE_PREFIX) + MAX_FILE_LINE_LEN;
#endif
    return ((ops.global_max_frames+1)/*for the ... line: over-estimate*/
            *(strlen(max_line)+max_addr_sym_len)) + 1/*null*/;
}

void
callstack_init(callstack_options_t *options)
{
    tls_idx_callstack = drmgr_register_tls_field();
    ASSERT(tls_idx_callstack > -1, "unable to reserve TLS slot");

    ASSERT(options->struct_size <= sizeof(ops), "option struct too large");
    memcpy(&ops, options, options->struct_size);

    hashtable_init_ex(&modname_table, MODNAME_TABLE_HASH_BITS, HASH_STRING_NOCASE,
                      false/*!str_dup*/, false/*!synch*/, modname_info_free, NULL, NULL);
    modname_table_initialized = true;
    modtree_lock = dr_mutex_create();
    module_tree = rb_tree_create(NULL);

    if (!TEST(FP_SEARCH_ALLOW_UNSEEN_RETADDR, ops.fp_flags)) {
        hashtable_config_t hashconfig = {sizeof(hashconfig),};
        hashtable_init(&retaddr_table, RETADDR_TABLE_HASH_BITS,
                       HASH_INTPTR, false/*!str_dup*/);
        hashconfig.resizable = true;
        hashconfig.resize_threshold = 60; /* default is 75 */
        hashtable_configure(&retaddr_table, &hashconfig);
        drmgr_register_bb_instrumentation_event(event_basic_block_analysis, NULL, NULL);
    }

#ifdef USE_DRSYMS
    IF_WINDOWS(ASSERT(using_private_peb(), "private peb not preserved"));
    /* we rely on drsym_init() being called in utils_init() */
#endif
}

void
callstack_exit(void)
{
    ASSERT(libdr_base != NULL, "never found DR lib");
    ASSERT(!(ops.tool_lib_ignore != NULL && libtoolbase == NULL), "never found tool lib");

    hashtable_delete(&modname_table);
    if (!TEST(FP_SEARCH_ALLOW_UNSEEN_RETADDR, ops.fp_flags))
        hashtable_delete_with_stats(&retaddr_table, "retaddr table");

    dr_mutex_lock(modtree_lock);
    rb_tree_destroy(module_tree);
    dr_mutex_unlock(modtree_lock);
    dr_mutex_destroy(modtree_lock);

#ifdef USE_DRSYMS
    IF_WINDOWS(ASSERT(using_private_peb(), "private peb not preserved"));
#endif

    drmgr_unregister_tls_field(tls_idx_callstack);
}

#ifdef STATISTICS
void
callstack_dump_statistics(file_t f)
{
    dr_fprintf(f, "callstack walks: %9u, callstacks symbolized: %8u\n",
               callstack_walks, callstacks_symbolized);
    dr_fprintf(f, "callstack fp scans: %8u, cache hits: %8u\n",
               find_next_fp_scans, find_next_fp_cache_hits);
    dr_fprintf(f, "callstack strings: %6u, structs: %6u, target mismatch: %8u\n",
               find_next_fp_strings, find_next_fp_string_structs,
               cstack_is_retaddr_tgt_mismatch);
    dr_fprintf(f, "callstack is_retaddr: %8u, backdecode: %8u, unreadable: %8u\n",
               cstack_is_retaddr, cstack_is_retaddr_backdecode,
               cstack_is_retaddr_unreadable);
    dr_fprintf(f, "callstack is_retaddr cont'd: unseen %8u\n",
               cstack_is_retaddr_unseen);
    dr_fprintf(f, "symbol names truncated: %8u\n", symbol_names_truncated);
}
#endif

static void
callstack_set_lowest_frame(void *drcontext)
{
    tls_callstack_t *pt = (tls_callstack_t *)
        drmgr_get_tls_field(drcontext, tls_idx_callstack);
    dr_mcontext_t mc; /* do not init whole thing: memset is expensive */
    app_pc stack_base;
    size_t stack_size;
    mc.size = sizeof(mc);
    mc.flags = DR_MC_CONTROL; /* only need xsp */
    dr_get_mcontext(drcontext, &mc);
    if (dr_query_memory((app_pc)mc.xsp, &stack_base, &stack_size, NULL)) {
        LOG(2, "lowest frame for thread "TIDFMT" = top of stack "PFX"-"PFX
            ", sp="PFX"\n",
            dr_get_thread_id(drcontext), stack_base, stack_base + stack_size, mc.xsp);
        pt->stack_lowest_frame = stack_base + stack_size;
    } else {
        LOG(2, "unable to query stack: leaving lowest frame for thread "TIDFMT
            " NULL\n", dr_get_thread_id(drcontext));
    }
}

void
callstack_thread_init(void *drcontext)
{
#ifdef UNIX
    static bool first = true;
#endif
    tls_callstack_t *pt = (tls_callstack_t *)
        thread_alloc(drcontext, sizeof(*pt), HEAPSTAT_MISC);
    drmgr_set_tls_field(drcontext, tls_idx_callstack, pt);
    memset(pt, 0, sizeof(*pt));
    /* PR 456181: we need our error reports to use a single atomic write.
     * We use a thread-private buffer to avoid using stack space or locks.
     * We can have a second callstack for delayed frees (i#205).
     */
    pt->errbufsz = MAX_ERROR_INITIAL_LINES + max_callstack_size() * 2;
    pt->errbuf = (char *) thread_alloc(drcontext, pt->errbufsz, HEAPSTAT_CALLSTACK);
    /* We take the space hit to avoid serializing all mallocs just for callstacks */
    pt->page_buf = (byte *) thread_alloc(drcontext, PAGE_SIZE, HEAPSTAT_CALLSTACK);
#ifdef WINDOWS
    if (get_TEB() != NULL) {
        pt->stack_lowest_frame = get_TEB()->StackBase;
    }
#else
    if (first) {
        /* We can't get mcontext for main thread (DR limitation), but
         * it won't help us much anyway b/c of all the argv, env, and auxv
         * stuff at the base of the stack.
         * Instead we find the entry point which will be the lowest
         * retaddr we should have.
         */
        module_data_t *data = dr_get_main_module();
        instr_t inst;
        app_pc pc = data->entry_point;
        app_pc stop = data->entry_point + PAGE_SIZE;
        uint i;
        /* Ensure we don't walk off the end of the segment (i#1846) */
        for (i = 0; i < data->num_segments; i++) {
            if (pc >= data->segments[i].start &&
                pc < data->segments[i].end) {
                if (data->segments[i].end < stop)
                    stop = data->segments[i].end;
                break;
            }
        }
        instr_init(drcontext, &inst);
        do {
            pc = decode(drcontext, pc, &inst);
            /* We look for the first call.  There might be a jmp instead,
             * or the first call might just be a leaf helper function:
             * we just won't have this optimization in those cases.
             */
            if (instr_valid(&inst) && instr_is_call(&inst)) {
                pt->stack_lowest_retaddr = pc;
                break;
            }
            instr_reset(drcontext, &inst);
        } while (pc != NULL && pc < stop);
        instr_free(drcontext, &inst);
        LOG(1, "stack_lowest_retaddr for main thread = 1st call "PFX" > entry "PFX"\n",
            pt->stack_lowest_retaddr, data->entry_point);
        dr_free_module_data(data);
        first = false;
    } else {
        callstack_set_lowest_frame(drcontext);
    }
#endif
}

void
callstack_thread_exit(void *drcontext)
{
    tls_callstack_t *pt = (tls_callstack_t *)
        drmgr_get_tls_field(drcontext, tls_idx_callstack);
    thread_free(drcontext, (void *) pt->errbuf, pt->errbufsz, HEAPSTAT_CALLSTACK);
    thread_free(drcontext, (void *) pt->page_buf, PAGE_SIZE, HEAPSTAT_CALLSTACK);
    drmgr_set_tls_field(drcontext, tls_idx_callstack, NULL);
    thread_free(drcontext, pt, sizeof(*pt), HEAPSTAT_MISC);
}

static dr_emit_flags_t
event_basic_block_analysis(void *drcontext, void *tag, instrlist_t *bb,
                           bool for_trace, bool translating, OUT void **user_data)
{
    instr_t *instr;
    ASSERT(!TEST(FP_SEARCH_ALLOW_UNSEEN_RETADDR, ops.fp_flags), "hashtable not init!");
    /* do nothing for translation */
    if (translating)
        return DR_EMIT_DEFAULT;
    for (instr  = instrlist_first(bb); instr != NULL; instr  = instr_get_next(instr)) {
        if (instr_is_app(instr) && instr_is_call(instr)) {
            app_pc retaddr = instr_get_app_pc(instr) +  instr_length(drcontext, instr);
            /* we never remove from the table, and dups are fine */
            hashtable_add(&retaddr_table, (void *)retaddr, (void *)tag);
        }
    }
    return DR_EMIT_DEFAULT;
}

/***************************************************************************/

static void
init_symbolized_frame(symbolized_frame_t *frame OUT, uint frame_num)
{
    memset(frame, 0, sizeof(*frame));
    frame->num = frame_num;
    frame->func[0] = '?';
    frame->func[1] = '\0';
}

#ifdef USE_DRSYMS
/* Symbol lookup: i#44/PR 243532 */
static void
lookup_func_and_line(symbolized_frame_t *frame OUT,
                     modname_info_t *name_info IN, size_t modoffs)
{
    drsym_error_t symres;
    drsym_info_t sym;
    const char *modpath = name_info->path;
    char name[MAX_FUNC_LEN];
    char file[MAXIMUM_PATH];
    sym.struct_size = sizeof(sym);
    sym.name = name;
    sym.name_size = BUFFER_SIZE_BYTES(name);
    sym.file = file;
    sym.file_size = BUFFER_SIZE_BYTES(file);
    IF_WINDOWS(ASSERT(using_private_peb(), "private peb not preserved"));
    STATS_INC(symbol_address_lookups);
    symres = drsym_lookup_address(modpath, modoffs, &sym,
                                  DRSYM_DEMANGLE |
                                  (TEST(PRINT_EXPAND_TEMPLATES, ops.print_flags) ?
                                   DRSYM_DEMANGLE_PDB_TEMPLATES : 0));
    if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
        LOG(4, "symbol %s+"PIFX" => %s+"PIFX" ("PIFX"-"PIFX") kind="PIFX"\n",
            modpath, modoffs, sym.name, modoffs - sym.start_offs,
            sym.start_offs, sym.end_offs, sym.debug_kind);
        if (sym.name_available_size >= sym.name_size) {
            DO_ONCE({
                WARN("WARNING: at least one function name longer than max: %s\n",
                     sym.name);
            });
            STATS_INC(symbol_names_truncated);
        }
        frame->has_symbols = TEST(DRSYM_SYMBOLS, sym.debug_kind);
        /* sym.name could be something like "BigInteger::operator%" */
        dr_snprintf(frame->func, MAX_FUNC_LEN, "%s", sym.name);
        NULL_TERMINATE_BUFFER(frame->func);
        frame->funcoffs = (modoffs - sym.start_offs);
        if (symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
            frame->fname[0] = '\0';
            frame->line = 0;
            frame->lineoffs = 0;
        } else {
            char *fname = sym.file;
            /* i#1634: if sym.file is longer than MAX_FILENAME_LEN,
             * we skip some prefix.
             */
            /* frame->fname has the size of MAX_FILENAME_LEN+1, so we do not need
             * extra byte for NULL.
             */
            if (strlen(fname) > MAX_FILENAME_LEN) {
                fname += (strlen(fname) - MAX_FILENAME_LEN + 3 /* ... */);
                if (strchr(fname, DIRSEP) != NULL)
                    fname = strchr(fname, DIRSEP);
            }
            dr_snprintf(frame->fname, MAX_FILENAME_LEN, "%s%s",
                        fname == sym.file ? "" : "...", fname);
            NULL_TERMINATE_BUFFER(frame->fname);
            frame->line = sym.line;
            frame->lineoffs = sym.line_offs;
        }
    }

    if (!frame->has_symbols) {
        warn_no_symbols(name_info);
    }
}

bool
print_symbol(byte *addr, char *buf, size_t bufsz, size_t *sofar,
             bool use_custom_flags, uint custom_flags)
{
    bool res;
    ssize_t len = 0;
    drsym_error_t symres;
    drsym_info_t sym;
    char name[MAX_FUNC_LEN];
    module_data_t *data;
    uint flags = use_custom_flags ? custom_flags : ops.print_flags;
    const char *modname;
    data = dr_lookup_module(addr);
    if (data == NULL)
        return false;
    ASSERT(data->start <= addr && data->end > addr, "invalid module lookup");
    modname = dr_module_preferred_name(data);
    if (modname == NULL)
        modname = "";
    sym.struct_size = sizeof(sym);
    sym.name = name;
    sym.name_size = BUFFER_SIZE_BYTES(name);
    sym.file = NULL;
    IF_WINDOWS(ASSERT(using_private_peb(), "private peb not preserved"));
    STATS_INC(symbol_address_lookups);
    symres = drsym_lookup_address(data->full_path, addr - data->start, &sym,
                                  DRSYM_DEMANGLE |
                                  (TEST(PRINT_EXPAND_TEMPLATES, flags) ?
                                   DRSYM_DEMANGLE_PDB_TEMPLATES : 0));
    if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
        if (sym.name_available_size >= sym.name_size) {
            DO_ONCE({
                LOG(1, "WARNING: at least one symbol name longer than max: %s\n",
                    sym.name);
            });
            STATS_INC(symbol_names_truncated);
        }
        /* I like having +0x%x to show offs within func but we'll match addr2line */
        BUFPRINT_NO_ASSERT(buf, bufsz, *sofar, len, " %s!%s", modname, sym.name);
        if (TEST(PRINT_SYMBOL_OFFSETS, flags)) {
            /* no assert for any of these bufprints: for just printing we'll truncate */
            BUFPRINT_NO_ASSERT(buf, bufsz, *sofar, len, "+"PIFX,
                               addr - data->start - sym.start_offs);
        }
        res = true;
    } else {
        BUFPRINT_NO_ASSERT(buf, bufsz, *sofar, len, " %s!?", modname);
        res = false;
    }
    dr_free_module_data(data);
    return res;
}
#endif

#ifdef DEBUG
static void
dump_app_stack(void *drcontext, tls_callstack_t *pt, dr_mcontext_t *mc, size_t amount,
               app_pc pc)
{
    byte *xsp = (byte *) MC_SP_REG(mc);
    LOG(1, "callstack stack pc="PFX" xsp="PFX" xbp="PFX":\n", pc, MC_SP_REG(mc),
        MC_FP_REG(mc));
    DR_TRY_EXCEPT(dr_get_current_drcontext(), {
        while (xsp < (byte *)MC_SP_REG(mc) + amount && xsp < pt->stack_lowest_frame) {
            void *val = *(void **)xsp;
            char buf[128];
            size_t sofar = 0;
            ssize_t len;
            BUFPRINT(buf, BUFFER_SIZE_ELEMENTS(buf), sofar, len,
                     "\t"PFX"  "PFX, xsp, val);
            IF_DRSYMS(print_symbol(val, buf, BUFFER_SIZE_ELEMENTS(buf), &sofar, false, 0);)
            LOG(1, "%s\n", buf);
            xsp += sizeof(void*);
        }
    }, { /* EXCEPT */
        LOG(1, "<"PFX "unreadable => aborting>\n", xsp);
    });
}
#endif

static bool
frame_include_srcfile(symbolized_frame_t *frame IN)
{
    return (frame->fname[0] != '\0' &&
            /* i#589: support hiding source files matching pattern */
            (ops.srcfile_hide == NULL ||
             !text_matches_any_pattern(frame->fname,
                                       ops.srcfile_hide, FILESYS_CASELESS)));
}

/* We provide control over many aspects of callstack formatting (i#290)
 * encoded in print_flags.
 * We put file:line in [] and absaddr <mod!offs> in ()
 *
 * Example:
 *  0  suppress.exe!do_uninit_read+0x27 [e:\derek\drmemory\git\src\tests\suppress.c @ 53] (0x004011d7 <suppress.exe+0x11d7>)
 *  1  suppress.exe!uninit_test1+0xb [e:\derek\drmemory\git\src\tests\suppress.c @ 59] (0x0040119c <suppress.exe+0x119c>)
 *  2  suppress.exe!test+0xf [e:\derek\drmemory\git\src\tests\suppress.c @ 213] (0x00401070 <suppress.exe+0x1070>)
 *  3  suppress.exe!main+0x31 [e:\derek\drmemory\git\src\tests\suppress.c @ 247] (0x00401042 <suppress.exe+0x1042>)
 *  4  suppress.exe!__tmainCRTStartup+0x15e [f:\sp\vctools\crt_bld\self_x86\crt\src\crt0.c @ 327] (0x00401d87 <suppress.exe+0x1d87>)
 *  5  KERNEL32.dll!BaseProcessStart+0x27 (0x7d4e9982 <KERNEL32.dll+0x29982>)
 */
static void
print_file_and_line(symbolized_frame_t *frame IN,
                    char *buf, size_t bufsz, size_t *sofar,
                    uint print_flags, const char *prefix,
                    bool include_srcfile)
{
    ssize_t len = 0;
    /* XXX: add option for printing "[]" if field not present? */
    if (include_srcfile) {
        const char *fname = frame->fname;
        if (TEST(PRINT_SRCFILE_NEWLINE, print_flags)) {
            BUFPRINT(buf, bufsz, *sofar, len, NL"%s"LINE_PREFIX,
                     prefix == NULL ? "" : prefix);
        } else
            BUFPRINT(buf, bufsz, *sofar, len, " [");
        if (ops.srcfile_prefix != NULL) {
            /* i#575: support truncating source file prefix */
            const char *matched;
            const char *match =
                text_contains_any_string(fname, ops.srcfile_prefix,
                                         FILESYS_CASELESS, &matched);
            if (match != NULL) {
                fname = match + strlen(matched);
                if (fname[0] == DIRSEP IF_WINDOWS(|| fname[0] == ALT_DIRSEP))
                    fname++;
            }
        }
        BUFPRINT(buf, bufsz, *sofar, len, "%."STRINGIFY(MAX_FILENAME_LEN)"s", fname);
        if (TEST(PRINT_VSTUDIO_FILE_LINE, print_flags))
            BUFPRINT(buf, bufsz, *sofar, len, "(");
        else if (!TEST(PRINT_SRCFILE_NO_COLON, print_flags))
            BUFPRINT(buf, bufsz, *sofar, len, ":");
        else /* windbg format */
            BUFPRINT(buf, bufsz, *sofar, len, " @ ");
        /* XXX: printf won't truncate ints.  we could use dr_snprintf
         * to limit line# to MAX_LINENO_DIGITS, but would be hacky w/
         * BUFPRINT.  for now we live w/ potentially truncating callstacks later
         * if have giant line#s.
         */
        BUFPRINT(buf, bufsz, *sofar, len, "%"UINT64_FORMAT_CODE, frame->line);
        if (TEST(PRINT_LINE_OFFSETS, print_flags))
            BUFPRINT(buf, bufsz, *sofar, len, "+"PIFX, frame->lineoffs);
        if (TEST(PRINT_VSTUDIO_FILE_LINE, print_flags)) {
            /* VS2005+ doesn't need the trailing colon, but VS6 does. */
            BUFPRINT(buf, bufsz, *sofar, len, "):");
        }
        if (!TEST(PRINT_SRCFILE_NEWLINE, print_flags))
            BUFPRINT(buf, bufsz, *sofar, len, "]");
    } else {
        if (TEST(PRINT_SRCFILE_NEWLINE, print_flags))
            BUFPRINT(buf, bufsz, *sofar, len, NL""LINE_PREFIX"??:0");
    }
}

#ifdef X64
# define PIFC INT64_FORMAT"x"
#else
# define PIFC "x"
#endif

static void
print_frame(symbolized_frame_t *frame IN,
            char *buf, size_t bufsz, size_t *sofar,
            bool use_custom_flags, uint custom_flags,
            size_t max_func_len, const char *prefix)
{
    ssize_t len = 0;
    size_t align_sym = 0, align_mod = 0, align_moffs = 0;
    uint flags = use_custom_flags ? custom_flags : ops.print_flags;
    bool include_srcfile = frame_include_srcfile(frame);
    bool print_addrs, later_info;

    if (!frame->has_symbols && TEST(PRINT_NOSYMS_OFFSETS, flags)) {
        /* i#603: Print absaddr and/or mod/offs if we don't have symbols. */
        flags |= PRINT_ABS_ADDRESS | PRINT_MODULE_OFFSETS;
        /* i#635: Print symoffs if we don't have symbols. */
        flags |= PRINT_SYMBOL_OFFSETS;
    }

    /* To avoid trailing whitespace, determine now what will be printed at end
     * of line.
     */
    print_addrs =
        ((frame->loc.type == APP_LOC_PC && TEST(PRINT_ABS_ADDRESS, flags)) ||
         (frame->is_module && TEST(PRINT_MODULE_OFFSETS | PRINT_MODULE_ID,
                                   flags)));
    later_info = print_addrs || TEST(PRINT_SYMBOL_OFFSETS, flags) ||
        (include_srcfile && !TEST(PRINT_SRCFILE_NEWLINE, flags));

    if (prefix != NULL)
        BUFPRINT(buf, bufsz, *sofar, len, "%s", prefix);

    if (TEST(PRINT_ALIGN_COLUMNS, flags)) {
        /* XXX: could expose these as options.  could also align "abs <mod+offs>". */
        /* Avoid trailing whitespace by not aligning if line-final (i#584) */
        if (TESTANY(PRINT_SYMBOL_FIRST, flags) || later_info) {
            /* Shift alignment to match func name lengths, up to a limit */
            align_sym = (max_func_len > 0 ? (max_func_len < 60 ? max_func_len : 60) : 35);
        }
        if ((TEST(PRINT_SYMBOL_OFFSETS, flags) && !TEST(PRINT_SYMBOL_FIRST, flags)) ||
            later_info)
            align_mod = 13; /* 8.3! */
        if (TEST(PRINT_SYMBOL_FIRST, flags) || later_info)
            align_moffs = 6;
    }

    if (TEST(PRINT_FRAME_NUMBERS, flags))
        BUFPRINT(buf, bufsz, *sofar, len, "#%2d ", frame->num);

    if (!frame->is_module) {
        /* we already printed the syscall string or "<not in a module>" to func */
        BUFPRINT(buf, bufsz, *sofar, len, "%-*s",
                 align_sym, frame->func);
        if (frame->loc.type == APP_LOC_SYSCALL) {
            if (TEST(PRINT_SRCFILE_NEWLINE, flags))
                BUFPRINT(buf, bufsz, *sofar, len, NL""LINE_PREFIX"<system call>");
        } else
            ASSERT(frame->func[0] == '<' /* "<not in a module>" */, "inconsistency");
    } else {
        if (!TEST(PRINT_SYMBOL_FIRST, flags)) {
            if (!frame->hide_modname || strcmp(frame->func, "?") == 0)
                BUFPRINT(buf, bufsz, *sofar, len, "%s!", frame->modname);
            else if (align_mod > 0)
                align_mod += strlen(frame->modname) + 1 /*!*/;
            BUFPRINT(buf, bufsz, *sofar, len, "%-*s",
                     align_mod + align_sym - strlen(frame->modname), frame->func);
        } else
            BUFPRINT(buf, bufsz, *sofar, len, "%-*s", align_sym, frame->func);
        if (TEST(PRINT_SYMBOL_OFFSETS, flags))
            BUFPRINT(buf, bufsz, *sofar, len, "+0x%-*"PIFC, align_moffs, frame->funcoffs);
        if (TEST(PRINT_SYMBOL_FIRST, flags))
            BUFPRINT(buf, bufsz, *sofar, len, " %-*s", align_mod, frame->modname);

        /* if file+line are inlined, put before abs+mod!offs */
        if (!TEST(PRINT_SRCFILE_NEWLINE, flags))
            print_file_and_line(frame, buf, bufsz, sofar, flags, prefix, include_srcfile);
    }

    if (print_addrs) {
        BUFPRINT(buf, bufsz, *sofar, len, " (");
        if (frame->loc.type == APP_LOC_PC && TEST(PRINT_ABS_ADDRESS, flags)) {
            BUFPRINT(buf, bufsz, *sofar, len, PFX, loc_to_pc(&frame->loc));
            if (frame->is_module && TEST(PRINT_MODULE_OFFSETS, flags))
                BUFPRINT(buf, bufsz, *sofar, len, " ");
        }
        if (frame->is_module && TEST(PRINT_MODULE_OFFSETS, flags)) {
            BUFPRINT(buf, bufsz, *sofar, len,
                     "<%." STRINGIFY(MAX_MODULE_LEN) "s+%s>",
                     frame->modname, frame->modoffs);
        }
        BUFPRINT(buf, bufsz, *sofar, len, ")");
        if (TEST(PRINT_MODULE_ID, flags)) {
            /* i#446: We need unique module ids when postprocessing. */
            BUFPRINT(buf, bufsz, *sofar, len, " modid:%d", frame->modid);
        }
    }
    /* if file+line are on separate line, put after abs+mod!offs */
    if (TEST(PRINT_SRCFILE_NEWLINE, flags)) {
        if (frame->is_module) {
            print_file_and_line(frame, buf, bufsz, sofar, flags, prefix, include_srcfile);
        } else if (frame->loc.type == APP_LOC_PC) {
            BUFPRINT(buf, bufsz, *sofar, len, NL""LINE_PREFIX"??:0");
        }
    }

    BUFPRINT(buf, bufsz, *sofar, len, NL);
}

/* Fills in frame xor pcs.
 * Returns whether a new frame was added (won't be if skip_non_module and pc
 * is not in a module)
 * sub1_sym is for PR 543863: subtract one from retaddrs in callstacks
 */
static bool
address_to_frame(symbolized_frame_t *frame OUT, packed_callstack_t *pcs OUT,
                 app_pc pc, module_data_t *mod_in /*optional*/,
                 bool skip_non_module, bool sub1_sym, uint frame_num)
{
    modname_info_t *name_info;
    app_pc mod_start;
    ASSERT((frame != NULL && pcs == NULL) || (frame == NULL && pcs != NULL),
           "address_to_frame: can't pass frame and pcs");

    if (frame != NULL) {
        init_symbolized_frame(frame, frame_num);
        pc_to_loc(&frame->loc, pc);
    }

    if (module_lookup(pc, &mod_start, NULL, &name_info)) {
        ASSERT(pc >= mod_start, "internal pc-not-in-module error");
        ASSERT(name_info != NULL, "module should have info");
        ASSERT(mod_in == NULL || mod_in->start == mod_start, "module mismatch");
        if (pcs != NULL) {
            size_t sz = (pc - mod_start);
            uint pcs_idx = pcs->num_frames;
            if (pcs->is_packed) {
                pcs->frames.packed[pcs_idx].loc.addr = pc;
                if (name_info == NULL) { /* handling missing module in release build */
                    /* We already asserted above */
                    if (sz > MAX_MODOFFS_STORED) /* We lose data here */
                        pcs->frames.packed[pcs_idx].modoffs = MAX_MODOFFS_STORED;
                    else
                        pcs->frames.packed[pcs_idx].modoffs = sz;
                    pcs->frames.packed[pcs_idx].modname_idx = MAX_MODNAMES_STORED;
                } else {
                    int idx = name_info->index;
                    while (sz > MAX_MODOFFS_STORED) {
                        sz -= MAX_MODOFFS_STORED;
                        if (idx + 1 == MAX_MODNAMES_STORED)
                            break;
                        idx++;
                        ASSERT(idx < modname_array_end, "large-modname entries truncated");
                        ASSERT(strcmp(modname_array[idx-1]->name,
                                      modname_array[idx]->name) == 0,
                               "not enough large-modname entries");
                    }
                    pcs->frames.packed[pcs_idx].modoffs = sz;
                    pcs->frames.packed[pcs_idx].modname_idx = idx;
                }
            } else {
                pcs->frames.full[pcs_idx].loc.addr = pc;
                pcs->frames.full[pcs_idx].modoffs = sz;
                pcs->frames.full[pcs_idx].modname = name_info;
            }
            pcs->num_frames++;
        } else {
            const char *modname = (name_info->name == NULL) ?
                "<name unavailable>" : name_info->name;
            frame->is_module = true;
            frame->hide_modname = name_info->hide_modname;
            frame->user_data = name_info->user_data;
            frame->modbase = mod_start;
            dr_snprintf(frame->modname, MAX_MODULE_LEN, "%s", modname);
            NULL_TERMINATE_BUFFER(frame->modname);
            dr_snprintf(frame->modoffs, MAX_PFX_LEN, PIFX, pc - mod_start);
            NULL_TERMINATE_BUFFER(frame->modoffs);
#ifdef USE_DRSYMS
            if (name_info->path != NULL) {
                lookup_func_and_line(frame, name_info,
                                     pc - mod_start - (sub1_sym ? 1 : 0));
            }
#endif
        }
        return true;
    } else if (!skip_non_module) {
        if (pcs != NULL) {
            if (pcs->is_packed) {
                pcs->frames.packed[pcs->num_frames].loc.addr = pc;
                pcs->frames.packed[pcs->num_frames].modoffs = MAX_MODOFFS_STORED;
                pcs->frames.packed[pcs->num_frames].modname_idx = MAX_MODNAMES_STORED;
            } else {
                pcs->frames.full[pcs->num_frames].loc.addr = pc;
                pcs->frames.full[pcs->num_frames].modoffs = 0;
                pcs->frames.full[pcs->num_frames].modname = NULL;
            }
            pcs->num_frames++;
        } else {
            ASSERT(!frame->is_module, "frame not initialized");
            dr_snprintf(frame->func, MAX_FUNC_LEN, "<not in a module>");
            NULL_TERMINATE_BUFFER(frame->func);
        }
        return true;
    }
    return false;
}

static bool
print_address_common(char *buf, size_t bufsz, size_t *sofar,
                     app_pc pc, module_data_t *mod_in /*optional*/,
                     bool skip_non_module, bool sub1_sym, bool for_log,
                     bool *last_frame OUT, uint frame_num)
{
    symbolized_frame_t frame; /* 480 bytes but our stack can handle it */
    if (address_to_frame(&frame, NULL, pc, mod_in, skip_non_module, sub1_sym, 0)) {
        frame.num = frame_num;
        print_frame(&frame, buf, bufsz, sofar, for_log, PRINT_FOR_LOG, 0, NULL);
        if (last_frame != NULL && ops.truncate_below != NULL) {
            *last_frame = text_matches_any_pattern((const char *)frame.func,
                                                   ops.truncate_below, false);
        }
        return true;
    }
    return false;
}

bool
print_address(char *buf, size_t bufsz, size_t *sofar,
              app_pc pc, module_data_t *mod_in /*optional*/, bool for_log)
{
    return print_address_common(buf, bufsz, sofar, pc, mod_in,
                                false/*include non-module*/, false/*don't sub1*/,
                                for_log, NULL, 0);
}

#ifndef X64
/* Walks a wide character string.  Stops if it encounters any (widened) non-ascii
 * component, or a null wchar.
 * Reads from start, presumed to be in a safe buffer copy of orig, up to
 * a max of safe_wchars, at which point it goes and reads from the original
 * memory (orig + safe_wchars), up to a total max of max_wchars.
 * Returns 0 if no proper wide string was found; else returns the length
 * of the null-terminated wide string it found.
 */
static size_t
walk_wide_string(wchar_t *start, size_t safe_wchars,
                 wchar_t *orig, size_t max_wchars)
{
    size_t len = 0;
    wchar_t *s = start;
    while (s - start < safe_wchars && IS_WCHAR_AT(s)) {
        len++;
        s++;
    }
    if (s - start < safe_wchars) {
        if (*s == L'\0') /* terminating null */
            return len;
        else
            return 0;
    } else {
        /* don't let the safe-read buffer limit prevent us identifying a wide string */
        s = orig + (s - start);
        DR_TRY_EXCEPT(dr_get_current_drcontext(), {
            while (s - orig < max_wchars && IS_WCHAR_AT(s)) {
                len++;
                s++;
            }
            if (s - orig >= max_wchars || *s != L'\0')
                len = 0;
        }, { /* EXCEPT */
            len = 0;
        });
        return len;
    }
    return 0;
}
#endif

#ifdef X86
# define OP_CALL_DIR 0xe8
# define OP_CALL_IND 0xff
# define OP_JMP_DIR_SHORT 0xeb
# define OP_JMP_DIR_LONG 0xe9
# define OP_JMP_IND 0xff
# define OP_SEG_FS   0x64
# define WOW64_SYSOFFS  0xc0
#endif

static bool
is_retaddr(app_pc pc, bool exclude_tool_lib)
{
    /* XXX: for our purposes we really want is_in_code_section().  Since
     * is_in_module() is used for is_image(), we would need a separate rbtree.  We
     * could do +rx segment via mem query and avoid walking sections.  We'd have to
     * store the range since might not be there at unmap time?  So far the 3 backward
     * derefs looking for calls haven't been slow enough or have enough false
     * positives to make the +rx-only seem worth the effort: global var addresses on
     * the stack don't seem any more common than things like SEH handlers that would
     * match +rx anyway, and rare for global var to have what looks like a call prior
     * to it.
     */
#ifdef ARM
    bool is_thumb = TEST(1, (ptr_uint_t)pc);
    pc = (app_pc) ALIGN_BACKWARD(pc, 2);
#endif
    STATS_INC(cstack_is_retaddr);
    if (!is_in_module(pc-1))
        return false;
    if (exclude_tool_lib &&
        ((pc >= libdr_base && pc < libdr_end) ||
         (pc >= libtoolbase && pc < libtoolend)))
        return false;
    if (!TEST(FP_SEARCH_DO_NOT_DISASM, ops.fp_flags)) {
        /* The is_in_module() check is more expensive than our 3 derefs here.
         * We do not bother to cache frequent/recent values.
         */
        /* more efficient to read 3 dwords than safe_read 6 into a buffer */
        bool match;
        STATS_INC(cstack_is_retaddr_backdecode);
        DR_TRY_EXCEPT(dr_get_current_drcontext(), {
            IF_X86_ELSE({
                match = ((*(pc - 5) == OP_CALL_DIR
                      /* rule out call to next instr used for PIC */
                      IF_UNIX(&& *(int*)(pc - 4) != 0)) ||
                     (*(pc - 2) == OP_CALL_IND &&
                      /* indirect through mem: 0xff /2 (mod==0)
                       *   => top 5 bits are 0x02, and rule out disp32 (rm==0x5)
                       */
                      ((((*(pc - 1) >> 3) == 0x02) && ((*(pc - 1) & 0x3) != 0x5)) ||
                       /* indirect through reg: 0xff /2 (mod==3)
                        *   => top 5 bits are 0xd0 (0x3 << 3 | 0x2)
                        */
                       ((*(pc - 1) & 0xf8) == 0xd0))) ||
                     /* indirect through mem: 0xff /2 + disp8 (mod==1) */
                     (*(pc - 3) == OP_CALL_IND && ((*(pc - 2) >> 3) == 0x0a)) ||
                     /* indirect through mem: 0xff /2 + disp32 (mod==2) */
                     (*(pc - 6) == OP_CALL_IND &&
                      ((*(pc - 5) >> 3) == 0x12 || *(pc - 5) == 0x15)
                      /* i#1217: rule out WOW64 syscall from DR code invoked on app
                       * stack by -replace_malloc.  We always have a syscall
                       * in an app_loc_t so we should never need it in a frame.
                       */
                      IF_NOT_X64(&& (*(uint*)(pc - 4) != WOW64_SYSOFFS ||
                                     *(pc - 7) != OP_SEG_FS))
                      ) ||
                     /* indirect through mem: 0xff /2 + sib (w/o sib reg=5) */
                     (*(pc - 3) == OP_CALL_IND &&
                      (*(pc - 2) == 0x14 && ((*(pc - 1) & 0x3) != 5))));
            }, {
                match =
                    (is_thumb &&
                     /* T32 bl <label> */
                     ((((*(pc - 3) & 0xf0) == 0xf0) &&
                       ((*(pc - 1) & 0xd0) == 0xd0)) ||
                      /* T32 blx <label> */
                      (((*(pc - 3) & 0xf0) == 0xf0) &&
                       ((*(pc - 1) & 0xd0) == 0xc0)) ||
                      /* T32 blx <reg> */
                      (*(pc - 1) == 0x47 &&
                       ((*(pc - 2) & 0x87) == 0x80)))) ||
                    (!is_thumb &&
                     /* A32 bl <label> */
                     (((*(pc - 1) & 0x0f) == 0x0b) ||
                      /* A32 blx <label> */
                      ((*(pc - 1) & 0xfe) == 0xfa) ||
                      /* A32 blx <reg> */
                      (((*(pc - 1) & 0x0f) == 0x01) &&
                       *(pc - 2) == 0x2f &&
                       *(pc - 3) == 0xff &&
                       ((*(pc - 4) & 0xf0) == 0x30))));
            })
        }, { /* EXCEPT */
            match = false;
            /* If we end up with a lot of these we could either cache
             * frequent/recent or switch to +rx instead of whole module
             */
            LOG(3, "is_retaddr: can't read "PFX"\n", pc);
            STATS_INC(cstack_is_retaddr_unreadable);
        });
#ifdef USE_DRSYMS
        DOLOG(5, {
            char buf[128];
            size_t sofar = 0;
            ssize_t len;
            BUFPRINT(buf, BUFFER_SIZE_ELEMENTS(buf), sofar, len,
                     "is_retaddr %d: "PFX" == ", match, pc);
            print_symbol(pc, buf, BUFFER_SIZE_ELEMENTS(buf), &sofar, false, 0);
            LOG(1, "%s\n", buf);
        });
#endif
        if (!match)
            return false;
    }
    if (!TEST(FP_SEARCH_ALLOW_UNSEEN_RETADDR, ops.fp_flags) &&
        /* Do not check for retaddrs in tool libs which of course won't
         * be in our table.
         */
        !((pc >= libdr_base && pc < libdr_end) ||
          (pc >= libtoolbase && pc < libtoolend))) {
        /* i#1439: only allow retaddrs for calls we've seen */
        if (hashtable_lookup(&retaddr_table, (void *)pc) == NULL) {
            LOG(4, "is_retaddr: never-before-seen "PFX"\n", pc);
            STATS_INC(cstack_is_retaddr_unseen);
            return false;
        }
    }
    return true;
}

#ifdef ARM
/* XXX: we should share this with DR's decode_raw_jmp_target().
 * Should DR export that?
 * It's ARM-only right now but we could make an x86 version and use it
 * in several places where we directly de-reference the immed today.
 */
static byte *
get_call_target(byte *pc, dr_isa_mode_t mode)
{
    if (mode == DR_ISA_ARM_A32) {
        uint word = *(uint*)pc;
        int disp = word & 0xffffff;
        if (TEST(0x800000, disp))
            disp |= 0xff000000; /* sign-extend */
        return pc + 8 + (disp << 2);
    } else {
        /* A10,B13,B11,A9:0,B10:0 x2, but B13 and B11 are flipped if A10 is 0 */
        /* XXX: share with decoder's TYPE_J_b26_b13_b11_b16_b0 */
        ushort valA = *(ushort *)pc;
        ushort valB = *(ushort *)(pc + 2);
        uint bitA10 = (valA & 0x0400) >> 10;
        uint bitB13 = (valB & 0x2000) >> 13;
        uint bitB11 = (valB & 0x0800) >> 11;
        int disp = valB & 0x7ff; /* B10:0 */
        disp |= (valA & 0x3ff) << 11;
        disp |= ((bitA10 == 0 ? (bitB11 == 0 ? 1 : 0) : bitB11) << 21);
        disp |= ((bitA10 == 0 ? (bitB13 == 0 ? 1 : 0) : bitB13) << 22);
        disp |= bitA10 << 23;
        if (bitA10 == 1)
            disp |= 0xff000000; /* sign-extend */
        return pc + 4 + (disp << 1);
    }
}
#endif

/* Checks that the call preceding next_retaddr targets the function containing
 * frame_addr, or that a cross-module call is indirect, depending on ops.fp_flags.
 * If it can't tell, it returns true.
 */
static bool
check_retaddr_targets_frame(app_pc frame_addr, app_pc next_retaddr, bool fp_walk)
{
    app_pc frame_mod_start, ra_mod_start;
    modname_info_t *frame_name, *ra_name;
    app_pc pc = next_retaddr, call_target = NULL;
    bool res = true;
    symbolized_frame_t frame_sym;
#ifdef ARM
    bool is_thumb = TEST(1, (ptr_uint_t)next_retaddr);
    pc = (app_pc) ALIGN_BACKWARD(pc, 2);
#endif
    LOG(4, "%s: checking does "PFX" => "PFX"\n", __FUNCTION__, next_retaddr, frame_addr);
    if (TEST(FP_DO_NOT_VERIFY_CROSS_MOD_IND, ops.fp_flags) &&
        !TESTANY(FP_VERIFY_CALL_TARGET | FP_VERIFY_CROSS_MODULE_TARGET, ops.fp_flags))
        return true; /* no checks were requested */
    if (!module_lookup(frame_addr, &frame_mod_start, NULL, &frame_name) ||
        /* do not check anything targeting a replaced routine */
        (frame_addr >= libdr_base && frame_addr < libdr_end) ||
        (frame_addr >= libtoolbase && frame_addr < libtoolend))
        return true; /* no info */
    if (TEST(FP_VERIFY_CROSS_MODULE_TARGET, ops.fp_flags) ||
        !TEST(FP_DO_NOT_VERIFY_CROSS_MOD_IND, ops.fp_flags)) {
        /* check whether cross-module */
        if (!module_lookup(next_retaddr, &ra_mod_start, NULL, &ra_name)) {
            if (TEST(FP_VERIFY_CROSS_MODULE_TARGET, ops.fp_flags))
                return true; /* no module info, and no further checks */
        } else if (frame_mod_start == ra_mod_start) {
            if (TEST(FP_VERIFY_CROSS_MODULE_TARGET, ops.fp_flags))
                return true; /* only supposed to check cross-module */
        } else if (fp_walk && frame_name->abort_fp_walk) {
            /* i#703: break fp chain on exiting suspect libs */
            LOG(3, "%s: breaking fp chain as module %s is suspect\n", __FUNCTION__,
                frame_name->name);
            return false;
        } else if (!TEST(FP_DO_NOT_VERIFY_CROSS_MOD_IND, ops.fp_flags)) {
            /* Only allow a cross-module transition that's an indirect call.
             * When done only on scans (and not fp walks), this has minimal
             * overhead and rules out bogus frames, in particular from Windows
             * system calls (i#1436).
             */
            DR_TRY_EXCEPT(dr_get_current_drcontext(), {
                IF_X86_ELSE({
                    if (*(pc - 5) == OP_CALL_DIR) {
                        pc = *(int*)(pc - 4) + pc;
                        /* Follow "call; jmp*", where jmp* is 0xff /4 */
                        if (*pc != OP_JMP_IND ||
                            ((*(pc + 1) >> 3) != 0x14 && *(pc + 1) != 0x25))
                            res = false;
                    }
                }, {
                    /* We assume the PLT is always ARM and looks sthg like this:
                     *    0xe28fc600  add     r12, pc, #0, 12
                     *    0xe28cca08  add     r12, r12, #8, 20        ; 0x8000
                     *    0xe5bcfaf4  ldr     pc, [r12, #2804]!       ; 0xaf4
                     */
                    if ((is_thumb &&
                         /* T32 bl <label> */
                         ((*(pc - 3) & 0xf0) == 0xf0) &&
                         ((*(pc - 1) & 0xd0) == 0xd0)) ||
                        (!is_thumb &&
                         /* A32 blx <reg> */
                         ((*(pc - 1) & 0x0f) == 0x01) &&
                         *(pc - 2) == 0x2f &&
                         *(pc - 3) == 0xff &&
                         ((*(pc - 4) & 0xf0) == 0x30)))
                        res = false;
                    else if ((is_thumb &&
                         /* T32 blx <label> */
                         ((*(pc - 3) & 0xf0) == 0xf0) &&
                         ((*(pc - 1) & 0xd0) == 0xc0)) ||
                        (!is_thumb &&
                         /* A32 bl <label> */
                         ((*(pc - 1) & 0x0f) == 0x09))) {
                        pc = get_call_target(pc - 4, is_thumb);
                        LOG(4, "%s: call tgt is "PFX"\n", __FUNCTION__, pc);
                        /* Just look for an add -- rare in func prologue 1st instr */
                        if (((*(uint*)pc) & 0xe2800000) == 0xe2800000)
                            res = false;
                    }
                })
            }, { /* EXCEPT */
                res = false;
                LOG(3, "%s: can't read "PFX"\n", __FUNCTION__, pc);
                STATS_INC(cstack_is_retaddr_unreadable);
            });
            LOG(4, "%s: candidate cross-module retaddr "PFX" has %s call\n", __FUNCTION__,
                next_retaddr, res ? "indirect" : "direct");
            DOSTATS({
                if (!res)
                    STATS_INC(cstack_is_retaddr_tgt_mismatch);
            });
            if (!res || !TEST(FP_VERIFY_CROSS_MODULE_TARGET, ops.fp_flags))
                return res;
        }
    }
    if (!TESTANY(FP_VERIFY_CALL_TARGET | FP_VERIFY_CROSS_MODULE_TARGET, ops.fp_flags))
        return true; /* no further checks */
#ifdef USE_DRSYMS
    /* Here we check that the target of the retaddr matches the function
     * containing frame_addr.  This is risky b/c the retaddr could target
     * some other routine that then tailcalls to frame_addr's function.
     * At some point it's cheaper and more accurate to read the debug info.
     */
    frame_sym.funcoffs = 0;
    lookup_func_and_line(&frame_sym, frame_name, frame_addr - frame_mod_start);
    DR_TRY_EXCEPT(dr_get_current_drcontext(), {
        IF_X86_ELSE({
            /* We only support a direct call or a 32-bit memory indirect: not
             * feasible to figure out register values in prior frames.
             */
            if (*(pc - 5) == OP_CALL_DIR) {
                pc = *(int*)(pc - 4) + pc;
                /* Follow "call; jmp*", where jmp* is 0xff /4 */
                if (*pc == OP_JMP_IND && *(pc + 1) == 0x25) {
                    int disp32 = *(int*)(pc + 2);
                    app_pc indir = IF_X64_ELSE(pc + disp32, (app_pc) disp32);
                    call_target = *(app_pc*)indir;
                } else
                    call_target = pc;
            } else if (*(pc - 6) == OP_CALL_IND && *(pc - 5) == 0x15) {
                int disp32 = *(int*)(pc - 4);
                app_pc indir = IF_X64_ELSE(pc + disp32, (app_pc) disp32);
                LOG(4, "%s: call* @ "PFX" targets poi("PFX")\n", __FUNCTION__,
                    pc - 6, indir);
                call_target = *(app_pc*)indir;
                /* Account for forwarding stubs like kernel32!HeapCreateStub */
                if (*call_target == OP_JMP_DIR_SHORT ||
                    *call_target == OP_JMP_DIR_LONG) {
                    /* Bail -- too complex to find where it's going.  Sometimes
                     * there's yet another jmp* intermediary.
                     */
                    LOG(3, "%s: call* targets a stub: bailing\n", __FUNCTION__);
                    call_target = NULL;
                }
            }
        }, {
            /* FIXME i#1726: port to ARM */
        })
    }, { /* EXCEPT */
        res = false;
        LOG(3, "%s: can't read "PFX"\n", __FUNCTION__, pc);
        STATS_INC(cstack_is_retaddr_unreadable);
    });
    if (res && call_target != NULL) {
        LOG(4, "check: frame="PFX" (func "PFX"), ra="PFX", ra targets "PFX"\n",
            frame_addr, frame_addr - frame_sym.funcoffs, next_retaddr, call_target);
        res = (frame_sym.funcoffs != 0 && call_target == frame_addr - frame_sym.funcoffs);
    }
    DOSTATS({
        if (!res)
            STATS_INC(cstack_is_retaddr_tgt_mismatch);
    });
    LOG(4, "%s: returning %d\n", __FUNCTION__, res);
    return res;
#else
    return true; /* no info */
#endif
}

static void
fpcache_update(tls_callstack_t *pt, byte *fp_in, byte *fp_out, app_pc retaddr)
{
    pt->fpcache[pt->fpcache_idx].input_fp = fp_in;
    pt->fpcache[pt->fpcache_idx].output_fp = fp_out;
    pt->fpcache[pt->fpcache_idx].retaddr = retaddr;
    pt->fpcache_idx = (pt->fpcache_idx + 1) % FPSCAN_CACHE_ENTRIES;
}

static app_pc
find_next_fp(void *drcontext, tls_callstack_t *pt, app_pc fp, app_pc prior_ra,
             bool top_frame, app_pc *retaddr/*OUT*/)
{
    byte *page_buf = pt->page_buf;
    app_pc orig_fp = fp;
    ASSERT(page_buf != NULL, "thread's page_buf is not initialized");
    /* Heuristic: scan stack for retaddr, or fp + retaddr pair */
    ASSERT(fp != NULL, "internal callstack-finding error");
    /* PR 416281: word-align fp so page assumptions hold */
    fp = (app_pc) ALIGN_BACKWARD(fp, sizeof(app_pc));

    /* Optimization: do not repeatedly walk the base of the stack beyond
     * the lowest frame, querying for modules.
     * FIXME: for now we use the lowest frame found in the first callstack
     * for this thread: but that can lead to erroneously prematurely
     * terminating callstacks so we should keep our eyes open.
     * Perhaps we should replace this w/ the actual stack bounds?
     */
    if (pt != NULL && pt->stack_lowest_frame != NULL &&
        ((fp >= pt->stack_lowest_frame &&
          (fp - pt->stack_lowest_frame) < ops.stack_swap_threshold) ||
         /* if hit a zero or bad fp near the lowest frame, don't scan.
          * some apps like perlbmk have some weird loader callstacks
          * and then a solid bottom frame so try not to scan every time.
          * xref i#246.
          */
         (!top_frame && (pt->stack_lowest_frame - fp) < FP_NO_SCAN_NEAR_LOW_THRESH))) {
        LOG(4, "find_next_fp: aborting b/c "PFX" is beyond stack_lowest_frame "PFX"\n",
            fp, pt->stack_lowest_frame);
        return NULL;
    }
    /* Check the cache.  We verify by reading the retaddr.  With
     * -zero_retaddr, we'll only be wrong if there's a non-retaddr
     * slot holding this retaddr and the real next retaddr is in front
     * of it.  With -no_zero_retaddr, there are more chances of
     * skipping frames, so we disable the cache in that scenario.
     *
     * XXX: we should also try a structured cache of the last callstack,
     * which could result in greater speedup: but is also more complex
     * to implement.
     */
    if (ops.old_retaddrs_zeroed) {
        uint i;
        for (i = 0; i < FPSCAN_CACHE_ENTRIES; i++) {
            if (orig_fp == pt->fpcache[i].input_fp) {
                app_pc ra;
                if (safe_read(pt->fpcache[i].output_fp + sizeof(app_pc),
                              sizeof(ra), &ra) &&
                    ra == pt->fpcache[i].retaddr &&
                    /* i#1231: we don't zero for full mode but we want the cache */
                    (ops.is_dword_defined == NULL ||
                     ops.is_dword_defined(drcontext,
                                          pt->fpcache[i].output_fp + sizeof(app_pc)))) {
                    if (retaddr != NULL)
                        *retaddr = ra;
                    LOG(4, "find_next_fp: cache hit "PFX" => "PFX", ra="PFX"\n",
                        orig_fp, pt->fpcache[i].output_fp, ra);
                    /* Make sure we don't clobber this hit on our next miss */
                    pt->fpcache_idx = (i + 1) % FPSCAN_CACHE_ENTRIES;
                    STATS_INC(find_next_fp_cache_hits);
                    return pt->fpcache[i].output_fp;
                } else {
                    pt->fpcache[i].input_fp = NULL; /* invalidate */
                }
            }
        }
    }
    /* PR 454536: dr_memory_is_readable() is racy so we use a safe_read().
     * On Windows safe_read() costs 1 system call: perhaps DR should
     * use try/except there like on Linux?
     * We use stack_lowest_frame, based on the stack bounds, to avoid
     * incurring a fault (checked up above).
     * XXX: should support partial safe read for invalid page next to stack
     */
    if (safe_read((app_pc)ALIGN_BACKWARD(fp, PAGE_SIZE), PAGE_SIZE, page_buf)) {
        app_pc buf_pg = (app_pc) ALIGN_BACKWARD(fp, PAGE_SIZE);
        app_pc tos = fp;
        app_pc sp;
        app_pc slot0 = 0, slot1;
        bool match, match_next_frame, fp_defined = false;
        size_t ret_offs = TEST(FP_SEARCH_REQUIRE_FP, ops.fp_flags) ? sizeof(app_pc) : 0;
        app_pc stop = tos + ops.fp_scan_sz;
        IF_NOT_X64(uint conseq_wchar = 0;)
#ifdef WINDOWS
        /* if on original thread stack, stop at limit (i#588) */
        TEB *teb = get_TEB();
        if (teb != NULL && fp >= (app_pc)teb->StackLimit && fp < (app_pc)teb->StackBase)
            stop = (app_pc)teb->StackBase;
#endif
        /* Scan one page worth and look for potential fp,retaddr pair */
        STATS_INC(find_next_fp_scans);
        /* We only look at fp if TEST(FP_SEARCH_REQUIRE_FP, ops.fp_flags) */
        for (sp = tos; sp < stop; sp+=sizeof(app_pc)) {
            match = false;
            match_next_frame = false;
            if (retaddr != NULL)
                *retaddr = NULL;
            if (TEST(FP_SEARCH_REQUIRE_FP, ops.fp_flags)) {
                ASSERT((app_pc)ALIGN_BACKWARD(sp, PAGE_SIZE) == buf_pg, "buf error");
                if (ops.is_dword_defined != NULL)
                    fp_defined = ops.is_dword_defined(drcontext, sp);
                if (fp_defined)
                    slot0 = *((app_pc*)&page_buf[sp - buf_pg]);
            }
            /* Retrieve next page if slot1 will touch it */
            if ((app_pc)ALIGN_BACKWARD(sp + ret_offs, PAGE_SIZE) != buf_pg) {
                buf_pg = (app_pc) ALIGN_BACKWARD(sp + ret_offs, PAGE_SIZE);
                if (!safe_read(buf_pg, PAGE_SIZE, page_buf)) {
                    LOG(4, "find_next_fp: returning NULL b/c couldn't read next page\n");
                    break;
                }
            }
            LOG(5, "find_next_fp: considering sp="PFX"\n", sp);
            if (TEST(FP_SEARCH_REQUIRE_FP, ops.fp_flags) && !fp_defined) {
                IF_NOT_X64(conseq_wchar = 0;)
                continue;
            }
            if (ops.is_dword_defined != NULL &&
                !ops.is_dword_defined(drcontext, sp + ret_offs)) {
                IF_NOT_X64(conseq_wchar = 0;)
                continue; /* retaddr not defined */
            }
            if (!TEST(FP_SEARCH_REQUIRE_FP, ops.fp_flags) ||
                (slot0 > tos && slot0 - tos < ops.stack_swap_threshold)) {
                byte *buf_ptr = (byte *) &page_buf[(sp + ret_offs) - buf_pg];
                slot1 = *((app_pc*)buf_ptr);
                /* We should only consider retaddr in code section but
                 * let's keep it simple for now.
                 * We ignore DGC: perhaps a dr_is_executable_memory() could
                 * be used instead of checking modules.
                 * OPT: keep all modules in hashtable for quicker check
                 * that doesn't require alloc+free of heap */
#ifndef X64
                if (IS_WCHARx2_AT(buf_ptr))
                    conseq_wchar += 2;
                else
                    conseq_wchar = 0;
#endif
                if (is_retaddr(slot1, true/*i#1217*/)) {
                    match = true;
#ifndef X64
                    /* Check for wide strings or *_STRING structures (i#1331, i#1271).
                     * XXX: these are quite difficult to construct authentic tests
                     * for so unfortunately we do not have automated tests and have
                     * tested only by running Chromium unit_tests.
                     */
                    if (conseq_wchar > 0) {
                        /* i#1331: rule out wide strings that have
                         * address-look-alike sequences in the middle.
                         */
#                       define STACK_WIDE_STRING_MIN_LEN 16
#                       define STACK_WIDE_STRING_MAX_READ 512
                        wchar_t *str = (wchar_t*) (buf_ptr + sizeof(app_pc));
                        size_t len =
                            walk_wide_string(str, (wchar_t *)(page_buf + PAGE_SIZE) - str,
                                             (wchar_t*)(sp + ret_offs),
                                             STACK_WIDE_STRING_MAX_READ);
                        if (len > 0 && len + conseq_wchar >= STACK_WIDE_STRING_MIN_LEN) {
                            LOG(2, "find_next_fp: ra "PFX"@"PFX" really wchar '%S'\n",
                                slot1, sp, str - conseq_wchar);
                            STATS_INC(find_next_fp_strings);
                            match = false;
                        } else {
                            /* i#1271: rule out *_STRING data struct with
                             * 2 short fields followed by a buffer pointer.
                             * We assume the 2 shorts will match IS_WCHARx2_AT.
                             * str points at the buffer field.
                             */
                            wchar_t *strbuf;
                            if (safe_read(str, sizeof(strbuf), &strbuf) &&
                                walk_wide_string(strbuf, 0/*all unsafe*/, strbuf,
                                                 STACK_WIDE_STRING_MAX_READ) >=
                                STACK_WIDE_STRING_MIN_LEN) {
                                LOG(2, "find_next_fp: ra "PFX"@"PFX
                                    " really *_STRING '%S'\n", slot1, sp, strbuf);
                                STATS_INC(find_next_fp_string_structs);
                                match = false;
                            }
                        }
                    }
#endif
#ifdef WINDOWS
                } else if (top_frame && TEST(FP_SEARCH_REQUIRE_FP, ops.fp_flags)) {
                    /* PR 475715: msvcr80!malloc pushes ebx and then ebp!  It then
                     * uses ebp as scratch, so we end up here for the top frame
                     * of a leak callstack.
                     */
                    slot1 = *((app_pc*)&page_buf[(sp + 2*ret_offs) - buf_pg]);
                    if (is_retaddr(slot1, true/*i#1217*/)) {
                        match = true;
                        /* Do extra check for this case even if flags don't call for it */
                        match_next_frame = true;
                        /* Since there's a gap we return the retaddr */
                        ASSERT(retaddr != NULL, "invalid arg");
                        *retaddr = slot1;
                    }
#endif
                }
            }
            if (match && prior_ra != NULL &&
                !TEST(FP_DO_NOT_VERIFY_TARGET_IN_SCAN, ops.fp_flags) &&
                !check_retaddr_targets_frame(prior_ra, slot1, false))
                match = false;
            if (match) {
                app_pc parent_ret_ptr = slot0 + ret_offs;
                app_pc parent_ret;
                if (!TEST(FP_SEARCH_REQUIRE_FP, ops.fp_flags)) {
                    /* caller expects fp,ra pair */
                    LOG(4, "find_next_fp "PFX" => "PFX", ra="PFX"\n",
                        orig_fp, sp - sizeof(app_pc), slot1);
                    fpcache_update(pt, orig_fp, sp - sizeof(app_pc), slot1);
                    return sp - sizeof(app_pc);
                }
                if ((TEST(FP_SEARCH_MATCH_SINGLE_FRAME, ops.fp_flags) &&
                     !match_next_frame)) {
                    LOG(4, "find_next_fp "PFX" => "PFX", ra="PFX"\n",
                        orig_fp, sp, slot1);
                    fpcache_update(pt, orig_fp, sp, slot1);
                    return sp;
                }
                /* Require the next retaddr to be in a module as well, to avoid
                 * continuing past the bottom frame on ESXi (xref PR 469043)
                 */
                if (buf_pg == (app_pc)ALIGN_BACKWARD(parent_ret_ptr, PAGE_SIZE)) {
                    parent_ret = *((app_pc*)&page_buf[parent_ret_ptr - buf_pg]);
                } else {
                    if (!safe_read(parent_ret_ptr, sizeof(parent_ret), &parent_ret))
                        parent_ret = NULL;
                }
                if (parent_ret != NULL && is_retaddr(parent_ret, true/*i#1217*/)) {
                    LOG(4, "find_next_fp "PFX" => "PFX", ra="PFX"\n",
                        orig_fp, sp, slot1);
                    fpcache_update(pt, orig_fp, sp, slot1);
                    return sp;
                }
                match = false;
            }
        }
    } else
        LOG(4, "find_next_fp: returning NULL b/c couldn't read stack page\n");
    return NULL;
}

/* XXX i#1222: on win64, we should use SEH unwind tables to walk the callstack. */
void
print_callstack(char *buf, size_t bufsz, size_t *sofar, dr_mcontext_t *mc,
                bool print_fps, packed_callstack_t *pcs, int num_frames_printed,
                bool for_log, uint max_frames,
                bool (*frame_cb)(app_pc pc, byte *fp, void *user_data), void *user_data)
{
    void *drcontext = dr_get_current_drcontext();
    tls_callstack_t *pt = (tls_callstack_t *)
        ((drcontext == NULL) ? NULL : drmgr_get_tls_field(drcontext, tls_idx_callstack));
    int num = num_frames_printed;   /* PR 475453 - wrong call stack depths */
    ssize_t len = 0;
    ptr_uint_t *pc = (mc == NULL ? NULL : (ptr_uint_t *) MC_FP_REG(mc));
    size_t prev_sofar = 0;
    struct {
        app_pc next_fp;
        app_pc retaddr;
    } appdata;
    app_pc custom_retaddr = NULL;
    app_pc prev_lowest_frame = NULL, lowest_frame = NULL;
    bool first_iter = true;
    bool have_appdata = false;
    bool scanned = false;
    bool last_frame = false;
    byte *tos = (mc == NULL ? NULL : (byte *) MC_SP_REG(mc));

    ASSERT(max_frames <= ops.global_max_frames, "max_frames > global_max_frames");

    if (mc == NULL)
        goto print_callstack_done;

    ASSERT(num == 0 || num == 1, "only 1 frame can already be printed");
    ASSERT((buf != NULL && sofar != NULL && pcs == NULL) ||
           (buf == NULL && sofar == NULL && pcs != NULL),
           "print_callstack: can't pass buf and pcs");

    /* XXX: for ARM should we use %lr, which drwrap_replace_native stored?
     * The problem is that the current %lr value might also be on the stack,
     * and how would we know whether to skip it?
     */

#ifdef DEBUG
    if (mc != NULL && ops.dump_app_stack > 0) {
        dump_app_stack(drcontext, pt, mc, ops.dump_app_stack,
                       (pcs == NULL ? NULL : PCS_FRAME_LOC(pcs, 0).addr));
    }
#endif
    STATS_INC(callstack_walks);

    LOG(4, "initial fp="PFX" vs sp="PFX" def=%d\n",
        MC_FP_REG(mc), MC_SP_REG(mc),
        (ops.is_dword_defined == NULL) ?
        0 : ops.is_dword_defined(drcontext, (byte*)MC_FP_REG(mc)));
    if (MC_SP_REG(mc) != 0 &&
        (!ALIGNED(MC_FP_REG(mc), sizeof(void*)) ||
         MC_FP_REG(mc) < MC_SP_REG(mc) ||
         MC_FP_REG(mc) - MC_SP_REG(mc) > ops.stack_swap_threshold ||
         (ops.ignore_xbp != NULL &&
          ops.ignore_xbp(drcontext, mc)) ||
#ifdef WINDOWS
         /* don't trust ebp when in Windows syscall wrapper */
         (pcs != NULL && pcs->first_is_syscall) ||
#endif
         /* avoid stale fp,ra pair (i#640) */
         (ops.is_dword_defined != NULL &&
          (!ops.is_dword_defined(drcontext, (byte*)MC_FP_REG(mc)) ||
           !ops.is_dword_defined(drcontext, (byte*)MC_FP_REG(mc) + sizeof(void*)))) ||
         (MC_FP_REG(mc) != 0 &&
          (!safe_read((byte *)MC_FP_REG(mc), sizeof(appdata), &appdata) ||
           /* check the very first retaddr since ebp might point at
            * a misleading stack slot
            */
           (!TEST(FP_DO_NOT_CHECK_FIRST_RETADDR, ops.fp_flags) &&
            !is_retaddr(appdata.retaddr, false/*include drmem*/)))))) {
        /* We may start out in the middle of a frameless function that is
         * using ebp for other purposes.  Heuristic: scan stack for fp + retaddr.
         */
        LOG(4, "find_next_fp b/c starting w/ non-fp ebp "PFX" (def=%d %d)\n",
            MC_FP_REG(mc), ops.is_dword_defined == NULL ?
            0 : ops.is_dword_defined(drcontext, (byte*)MC_FP_REG(mc)),
            ops.is_dword_defined == NULL ?
            0 : ops.is_dword_defined(drcontext, (byte*)MC_FP_REG(mc) + sizeof(void*)));
#if defined(LINUX) && !defined(X64)
        if (pcs != NULL && pcs->first_is_syscall &&
            !TEST(FP_DO_NOT_SKIP_VSYSCALL_PUSH, ops.fp_flags)) {
            /* i#1265: skip the vsyscall sysenter "push ebp" to avoid skipping
             * over a frame, as the libc routine that invoked the syscall often
             * doesn't have a fp.  We want to only apply this when in vsyscall,
             * but even w/ a sysenter/syscall gateway there are still syscalls
             * that use OP_int: thus we check for TOS holding a retaddr (should
             * be relatively rare to get here so overhead not critical).
             */
            drsys_gateway_t gateway;
            if (drsys_syscall_gateway(&gateway) == DRMF_SUCCESS &&
                (gateway == DRSYS_GATEWAY_SYSENTER || gateway == DRSYS_GATEWAY_SYSCALL) &&
                safe_read(tos, sizeof(custom_retaddr), &custom_retaddr) &&
                !is_retaddr(custom_retaddr, true/*exclude tool*/)) {
                tos += sizeof(app_pc);
            }
        }
#endif
        pc = (ptr_uint_t *) find_next_fp(drcontext, pt, tos,
                                         /* Pass in the top frame for prior_ra */
                                         (pcs != NULL && num_frames_printed == 1) ?
                                         PCS_FRAME_LOC(pcs, 0).addr : NULL,
                                         true/*top frame*/,
                                         &custom_retaddr);
        scanned = true;
    }
    while (pc != NULL) {
        if (!have_appdata &&
            !safe_read((byte *)pc, sizeof(appdata), &appdata)) {
            LOG(4, "truncating callstack: can't read "PFX"\n", pc);
            break;
        }
        LOG(4, "print_callstack: pc="PFX" => FP="PFX", RA="PFX"\n",
            pc, appdata.next_fp, appdata.retaddr);
        /* if we scanned and took the top dword as retaddr, don't use beyond-TOS as FP */
        if ((byte *)pc < tos)
            appdata.next_fp = NULL;
        if (custom_retaddr != NULL) {
            /* Support frames where there's a gap between ebp and retaddr (PR 475715) */
            appdata.retaddr = custom_retaddr;
            custom_retaddr = NULL;
        }
        if (buf != NULL) {
            prev_sofar = *sofar;
            if (for_log)
                BUFPRINT(buf, bufsz, *sofar, len, FP_PREFIX"#%2d ", num);
            if (print_fps) {
                BUFPRINT(buf, bufsz, *sofar, len, "fp="PFX" parent="PFX" ",
                         pc, appdata.next_fp);
            }
        }
        prev_lowest_frame = lowest_frame;
        lowest_frame = (app_pc) pc;
        /* Unlesss FP_SHOW_NON_MODULE_FRAMES, we do not include not-in-a-module
         * addresses.  Perhaps something like dr_is_executable_memory() could
         * help us show non-module actual code: for now we skip it and just use
         * it to find the next real frame w/ a module, and to skip crap at the
         * base of callstacks.
         */
        /* PR 543863: subtract one from retaddrs in callstacks so the line# is
         * for the call and not for the next source code line, but only for
         * symbol lookup so we still display a valid instr addr.
         */
        if (pcs != NULL && first_iter && num == 1 &&
            PCS_FRAME_LOC(pcs, 0).addr == appdata.retaddr) {
            /* caller already added this frame */
            if (buf != NULL) /* undo the fp= print */
                *sofar = prev_sofar;
        } else if ((pcs == NULL &&
                    print_address_common(buf, bufsz, sofar, appdata.retaddr, NULL,
                                         !TEST(FP_SHOW_NON_MODULE_FRAMES, ops.fp_flags),
                                         true, for_log, &last_frame, num)) ||
                   (pcs != NULL &&
                    address_to_frame(NULL, pcs, appdata.retaddr, NULL,
                                     !TEST(FP_SHOW_NON_MODULE_FRAMES, ops.fp_flags),
                                     true, pcs->num_frames))) {
            num++;
            if (frame_cb != NULL) {
                if (!(*frame_cb)(appdata.retaddr, appdata.next_fp, user_data))
                    break;
            }
            if (last_frame)
                break;
            if (appdata.retaddr == pt->stack_lowest_retaddr &&
                pt->stack_lowest_retaddr != NULL) {
                LOG(4, "ending callstack: hit stack_lowest_retaddr "PFX"\n",
                    appdata.retaddr);
                break;
            }
        } else {
            lowest_frame = prev_lowest_frame; /* be sure to undo (i#1186) */
            if (buf != NULL) /* undo the fp= print */
                *sofar = prev_sofar;
            if (first_iter) { /* don't trust "num==num_frames_printed" as test for 1st */
                /* We may have started in a frameless function using ebp for
                 * other purposes but it happens to point to higher on the stack.
                 * Start over w/ top of stack to avoid skipping a frame (i#521).
                 */
                LOG(4, "find_next_fp "PFX" b/c starting w/ non-fp ebp "PFX"\n",
                    MC_SP_REG(mc), MC_FP_REG(mc));
                pc = (ptr_uint_t *) find_next_fp(drcontext, pt,
                                                 (app_pc)MC_SP_REG(mc), NULL,
                                                 true/*top frame*/, &custom_retaddr);
                scanned = true;
                first_iter = false; /* don't loop */
                continue;
            }
        }
        first_iter = false;
        /* pcs->num_frames could be larger if frames were printed before this routine */
        if (num >= max_frames || (pcs != NULL && pcs->num_frames >= max_frames)) {
            if (buf != NULL)
                BUFPRINT(buf, bufsz, *sofar, len, FP_PREFIX"..."NL);
            LOG(4, "truncating callstack: hit max frames %d %d\n",
                num, pcs == NULL ? -1 : pcs->num_frames);
            break;
        }
        /* yes I've seen weird recursive cases before */
        if (pc == (ptr_uint_t *) appdata.next_fp) {
            LOG(4, "truncating callstack: recursion\n");
            break;
        }
        have_appdata = false;
        if (appdata.next_fp == 0) {
            /* We definitely need to search for the first frame, and also in the
             * middle to cross loader/glue stubs/thunks or a signal/exception
             * frames (though for sigaltstck we'll stop).  However, on ESXi,
             * searching past a 0 (the parent of the _start base frame) finds
             * some data structures low on the stack (high addresses) that match
             * its heuristics but are actually loader data structures; they make
             * all callstacks erroneously long.
             */
            if (!TEST(FP_STOP_AT_BAD_ZERO_FRAME, ops.fp_flags)) {
                LOG(4, "find_next_fp b/c hit zero fp\n");
                pc = (ptr_uint_t *) find_next_fp(drcontext, pt,
                                                 ((app_pc)pc) + sizeof(appdata),
                                                 appdata.retaddr, false/*!top*/, NULL);
                scanned = true;
            } else {
                LOG(4, "truncating callstack: zero frame ptr\n");
                break;
            }
        } else {
            /* appdata.next_fp is candidate */
            bool out_of_range =
                (appdata.next_fp < (app_pc)pc ||
                 /* i#1042: 0xffffffff`ffffffff - 0x00000000`00aaf1e0 >= 0x20000
                  * return false, so we cast it to ptr_uint_t.
                  */
                 (ptr_uint_t)(appdata.next_fp - (app_pc)pc) >=
                 ops.stack_swap_threshold);
            app_pc prior_ra = appdata.retaddr;
            app_pc next_fp = appdata.next_fp;
            if (!out_of_range &&
                !safe_read((byte *)next_fp, sizeof(appdata), &appdata)) {
                LOG(4, "truncating callstack: can't read "PFX"\n", pc);
                break;
            }
            if (out_of_range ||
                (!TEST(FP_DO_NOT_CHECK_RETADDR, ops.fp_flags) &&
                 /* checking retaddr on regular fp chain walk is a 40% perf hit
                  * on cfrac and roboop so we avoid it if we've never had to
                  * do a scan, trusting the fp's to be genuine (overridden by
                  * FP_CHECK_RETADDR_PRE_SCAN)
                  */
                 (scanned || TEST(FP_CHECK_RETADDR_PRE_SCAN, ops.fp_flags)) &&
                 !is_retaddr(appdata.retaddr, false/*include drmem*/))) {
                if (!TEST(FP_STOP_AT_BAD_NONZERO_FRAME, ops.fp_flags)) {
                    LOG(4, "find_next_fp "PFX" b/c hit bad non-zero fp "PFX"\n",
                        ((app_pc)pc) + sizeof(appdata), appdata.next_fp);
                    pc = (ptr_uint_t *) find_next_fp(drcontext, pt,
                                                     ((app_pc)pc) + sizeof(appdata),
                                                     prior_ra, false/*!top*/, NULL);
                    scanned = true;
                } else {
                    LOG(4, "truncating callstack: bad frame ptr "PFX"\n", next_fp);
                    break;
                }
            } else if (TEST(FP_DO_NOT_WALK_FP, ops.fp_flags) ||
                       (!TEST(FP_DO_NOT_VERIFY_TARGET_IN_WALK, ops.fp_flags) &&
                        !check_retaddr_targets_frame(prior_ra, appdata.retaddr, true))) {
                LOG(4, "find_next_fp "PFX" b/c not walking fp, or skips "PFX"\n",
                    ((app_pc)pc) + sizeof(appdata), appdata.next_fp);
                pc = (ptr_uint_t *) find_next_fp(drcontext, pt,
                                                 ((app_pc)pc) + sizeof(appdata),
                                                 prior_ra, false/*!top*/, NULL);
                scanned = true;
            } else {
                have_appdata = true;
                pc = (ptr_uint_t *) next_fp;
            }
        }
        if (pc == NULL)
            LOG(4, "truncating callstack: can't find next fp\n");
    }
 print_callstack_done:
    if (num == 0 && buf != NULL && print_fps) {
        BUFPRINT(buf, bufsz, *sofar, len,
                 FP_PREFIX"<call stack frame ptr "PFX" unreadable>"NL, pc);
    }
    if (pt != NULL && lowest_frame > pt->stack_lowest_frame) {
        if (pt->stack_lowest_frame == NULL) {
            /* For main thread we couldn't query esp before, so do so now (i#1495) */
            callstack_set_lowest_frame(drcontext);
        }
        if (lowest_frame > pt->stack_lowest_frame) {
            pt->stack_lowest_frame = lowest_frame;
            LOG(4, "set lowest frame to "PFX"\n", lowest_frame);
        }
    }

    if (buf != NULL) {
        buf[bufsz-2] = '\n';
        buf[bufsz-1] = '\0';
    }
}

void
print_buffer(file_t f, char *buf)
{
    /* PR 427929: avoid truncation if over DR's internal buffer limit
     * by doing direct write
     */
    /* PR 458200: for PR 456181 we'd like this to be an atomic
     * write.  Since our writes are smaller than any disk buffer or kernel
     * buffer (definitely smaller than 1 page), we should never get a partial
     * write.  All we need to do is check for EINTR and retry.
     * Even if there is a chance of partial write it should be quite rare
     * and the consequences are simply a messed-up callstack: long-term
     * when we do symbols online then it will be visible to the user
     * and should be re-constructible by the user.
     */
    size_t sz = strlen(buf);
    ssize_t res;
    if (f == INVALID_FILE) {
        ASSERT(IF_WINDOWS(f == STDERR ||) false, "print_buffer invalid file");
        return;
    }
    while (true) {
        res = dr_write_file(f, buf, sz);
        if (res < 0) {
#ifdef UNIX
            /* DR converts Mac's +errno,CF to -errno
             * XXX: should we document that dr_write_file() returns -errno
             * on failure on both Linux and Mac?
             */
            /* FIXME: haven't tested this */
            if (res == -EINTR)
                continue;
#endif
            REPORT_DISK_ERROR();
        }
        /* getting weird failures on stderr: aborting silently on those */
        ASSERT(IF_WINDOWS(f == STDERR ||) res == sz, "dr_write_file partial write");
        break;
    }
}

#if DEBUG
/* Prints a callstack using pt->errbuf and prints to pt->f if f == INVALID_FILE,
 * else prints to the f passed in.
 */
void
print_callstack_to_file(void *drcontext, dr_mcontext_t *mc, app_pc pc, file_t f,
                        uint max_frames)
{
    size_t sofar = 0;
    ssize_t len;
    tls_callstack_t *pt = (tls_callstack_t *)
        ((drcontext == NULL) ? NULL : drmgr_get_tls_field(drcontext, tls_idx_callstack));
    /* mc and pc will be NULL for startup heap iter */
    if (pt == NULL) {
        LOG(1, "Can't report callstack as pt is NULL\n");
        return;
    }

    ASSERT(max_frames <= ops.global_max_frames, "max_frames > global_max_frames");

    BUFPRINT(pt->errbuf, pt->errbufsz, sofar, len, "# 0 ");
    print_address(pt->errbuf, pt->errbufsz, &sofar, pc, NULL, true/*for log*/);
    print_callstack(pt->errbuf, pt->errbufsz, &sofar, mc,
                    true/*incl fp*/, NULL, 1, true, max_frames, NULL, NULL);
    print_buffer(f == INVALID_FILE ? LOGFILE_GET(drcontext) : f, pt->errbuf);
}
#endif /* DEBUG */

app_pc
callstack_next_retaddr(dr_mcontext_t *mc)
{
    app_pc res = NULL;
    packed_callstack_t *pcs;
    packed_callstack_record(&pcs, mc, NULL, 1);
    if (pcs->num_frames > 0)
        res = PCS_FRAME_LOC(pcs, 0).addr;
    packed_callstack_destroy(pcs);
    return res;
}

/****************************************************************************
 * Binary callstacks for storing callstacks of allocation sites.
 */

/* Used for standalone allocation, rather than printing as part of an error report.
 * Caller must call free_callstack() to free buf_out.
 */
void
packed_callstack_record(packed_callstack_t **pcs_out/*out*/, dr_mcontext_t *mc,
                        app_loc_t *loc, uint max_frames)
{
    packed_callstack_t *pcs = (packed_callstack_t *)
        global_alloc(sizeof(*pcs), HEAPSTAT_CALLSTACK);
    size_t sz_out;
    int num_frames_printed = 0;
    ASSERT(max_frames <= ops.global_max_frames, "max_frames > global_max_frames");
    ASSERT(pcs_out != NULL, "invalid args");
    memset(pcs, 0, sizeof(*pcs));
    pcs->refcount = 1;
    if (modname_array_end < MAX_MODNAMES_STORED) {
        pcs->is_packed = true;
        pcs->frames.packed = (packed_frame_t *)
            global_alloc(sizeof(*pcs->frames.packed) * max_frames,
                         HEAPSTAT_CALLSTACK);
    } else {
        pcs->is_packed = false;
        pcs->frames.full = (full_frame_t *)
            global_alloc(sizeof(*pcs->frames.full) * max_frames, HEAPSTAT_CALLSTACK);
    }
    if (loc != NULL) {
        if (loc->type == APP_LOC_SYSCALL) {
            /* For syscalls, we use index 0 and external storage.
             * We copy from loc.  The syscall aux identifier (PR 525269)
             * is supposed to be a string literal and so we can clone it
             * and compare it by just using its address.
             */
            pcs->first_is_syscall = true;
            if (pcs->is_packed) {
                pcs->frames.packed[0].modname_idx = 0;
                pcs->frames.packed[0].loc.sysloc = (syscall_loc_t *)
                    global_alloc(sizeof(syscall_loc_t), HEAPSTAT_CALLSTACK);
                *pcs->frames.packed[0].loc.sysloc = loc->u.syscall;
            } else {
                pcs->frames.full[0].modname = (modname_info_t *) &MODNAME_INFO_SYSCALL;
                pcs->frames.full[0].loc.sysloc = (syscall_loc_t *)
                    global_alloc(sizeof(syscall_loc_t), HEAPSTAT_CALLSTACK);
                *pcs->frames.full[0].loc.sysloc = loc->u.syscall;
            }
            pcs->num_frames++;
        } else {
            app_pc pc = loc_to_pc(loc);
            ASSERT(loc->type == APP_LOC_PC, "unknown loc type");
            address_to_frame(NULL, pcs, pc, NULL, false, false, 0);
        }
        num_frames_printed = 1;
    }
    print_callstack(NULL, 0, NULL, mc, false, pcs, num_frames_printed, false,
                    max_frames, NULL, NULL);
    if (pcs->is_packed) {
        packed_frame_t *frames_out;
        sz_out = sizeof(*pcs->frames.packed) * pcs->num_frames;
        if (sz_out == 0)
            frames_out = NULL;
        else {
            frames_out = (packed_frame_t *) global_alloc(sz_out, HEAPSTAT_CALLSTACK);
            memcpy(frames_out, pcs->frames.packed, sz_out);
        }
        global_free(pcs->frames.packed, sizeof(*pcs->frames.packed) * max_frames,
                    HEAPSTAT_CALLSTACK);
        pcs->frames.packed = frames_out;
    } else {
        full_frame_t *frames_out;
        sz_out = sizeof(*pcs->frames.full) * pcs->num_frames;
        if (sz_out == 0)
            frames_out = NULL;
        else {
            frames_out = (full_frame_t *) global_alloc(sz_out, HEAPSTAT_CALLSTACK);
            memcpy(frames_out, pcs->frames.full, sz_out);
        }
        global_free(pcs->frames.full, sizeof(*pcs->frames.full) * max_frames,
                    HEAPSTAT_CALLSTACK);
        pcs->frames.full = frames_out;
    }
    *pcs_out = pcs;
}

void
packed_callstack_first_frame_retaddr(packed_callstack_t *pcs)
{
    pcs->first_is_retaddr = true;
}

/* Returns false if a syscall.  If returns true, also fills in the OUT params. */
static bool
packed_callstack_frame_modinfo(packed_callstack_t *pcs, uint frame,
                               modname_info_t **name_info OUT, size_t *modoffs OUT)
{
    modname_info_t *info = NULL;
    size_t offs = 0;
    ASSERT(pcs != NULL, "invalid arg");
    ASSERT(frame < pcs->num_frames, "invalid arg");
    /* modname_idx==0 or modname==NULL is the code for a system call */
    if (!pcs->is_packed) {
        info = pcs->frames.full[frame].modname;
        if (info == &MODNAME_INFO_SYSCALL) {
            ASSERT(frame == 0, "syscall should only be top frame");
            ASSERT(pcs->first_is_syscall, "flag not set");
            return false;
        }
        offs = pcs->frames.full[frame].modoffs;
    } else {
        if (pcs->frames.packed[frame].modname_idx == 0) {
            ASSERT(frame == 0, "syscall should only be top frame");
            ASSERT(pcs->first_is_syscall, "flag not set");
            return false;
        }
        if (pcs->frames.packed[frame].modoffs < MAX_MODOFFS_STORED) {
            /* If module is larger than 16M, we need to adjust offset.
             * The hashtable holds the first index.
             */
            int start_idx;
            int idx = pcs->frames.packed[frame].modname_idx;
            ASSERT(idx < MAX_MODNAMES_STORED, "invalid modname idx");
            offs = pcs->frames.packed[frame].modoffs;
            info = modname_array[idx];
            start_idx = info->index;
            ASSERT(start_idx != 0, "module in array must be in table");
            if (start_idx < idx)
                offs += (idx - start_idx) * MAX_MODOFFS_STORED;
        }
    }
    if (name_info != NULL)
        *name_info = info;
    if (modoffs != NULL)
        *modoffs = offs;
    return true;
}

static void
packed_frame_to_symbolized(packed_callstack_t *pcs IN, symbolized_frame_t *frame OUT,
                           uint idx)
{
    modname_info_t *info = NULL;
    size_t offs;
    init_symbolized_frame(frame, idx);
    if (!packed_callstack_frame_modinfo(pcs, idx, &info, &offs)) {
        size_t sofar = 0;
        ssize_t len;
        const char *name = "<unknown>";
        frame->loc.type = APP_LOC_SYSCALL;

        frame->loc.u.syscall = *(PCS_FRAME_LOC(pcs, idx).sysloc);

        /* we print the string now so we can compare to suppressions.
         * we use func since modname is too short in windows.
         */
        BUFPRINT(frame->func, MAX_FUNC_LEN, sofar, len, "system call ");
        if (ops.get_syscall_name != NULL)
            name = (*ops.get_syscall_name)(frame->loc.u.syscall.sysnum);
        /* strip syscall # if have name, to be independent of windows ver */
        ASSERT(name != NULL, "syscall name should not be NULL");
        if (name[0] != '\0' && name[0] != '<' /* "<unknown>" */) {
            BUFPRINT(frame->func, MAX_FUNC_LEN, sofar, len, "%s", name);
        } else {
            BUFPRINT(frame->func, MAX_FUNC_LEN, sofar, len, "%d.%d",
                     frame->loc.u.syscall.sysnum.number,
                     frame->loc.u.syscall.sysnum.secondary);
        }
        if (frame->loc.u.syscall.syscall_aux != NULL) {
            /* syscall aux identifier (PR 525269) */
            BUFPRINT(frame->func, MAX_FUNC_LEN, sofar, len, " %s",
                     frame->loc.u.syscall.syscall_aux);
        }
        NULL_TERMINATE_BUFFER(frame->func);
    } else {
        pc_to_loc(&frame->loc, PCS_FRAME_LOC(pcs, idx).addr);
        if (info != NULL) {
            const char *modname = (info->name == NULL) ?
                "<name unavailable>" : info->name;
            frame->is_module = true;
            frame->hide_modname = info->hide_modname;
            frame->user_data = info->user_data;
            frame->modid = info->id;
            /* Lazily compute frame->modbase so leave it NULL here */
            dr_snprintf(frame->modname, MAX_MODULE_LEN, "%s", modname);
            NULL_TERMINATE_BUFFER(frame->modname);
            dr_snprintf(frame->modoffs, MAX_PFX_LEN, PIFX, offs);
            NULL_TERMINATE_BUFFER(frame->modoffs);
#ifdef USE_DRSYMS
            /* PR 543863: subtract one from retaddrs in callstacks so the line#
             * is for the call and not for the next source code line, but only
             * for symbol lookup so we still display a valid instr addr.
             * We assume first frame is not a retaddr.
             */
            lookup_func_and_line(frame, info,
                                 (idx == 0 && !pcs->first_is_retaddr) ? offs : offs-1);
#endif
        } else {
            ASSERT(!frame->is_module, "frame not initialized");
            dr_snprintf(frame->func, MAX_FUNC_LEN, "<not in a module>");
            NULL_TERMINATE_BUFFER(frame->func);
        }
    }
}

/* 0 for num_frames means to print them all prefixed with tabs and
 * absolute addresses.
 * otherwise num_frames indicates the number of frames to be printed.
 */
void
packed_callstack_print(packed_callstack_t *pcs, uint num_frames,
                       char *buf, size_t bufsz, size_t *sofar, const char *prefix)
{
    uint i;
    symbolized_frame_t frame; /* 480 bytes but our stack can handle it */
    STATS_INC(callstacks_symbolized);
    ASSERT(pcs != NULL, "invalid args");
    for (i = 0; i < pcs->num_frames && (num_frames == 0 || i < num_frames); i++) {
        packed_frame_to_symbolized(pcs, &frame, i);
        print_frame(&frame, buf, bufsz, sofar, false, 0, 0, prefix);
        if (ops.truncate_below != NULL &&
            text_matches_any_pattern((const char *)frame.func, ops.truncate_below, false))
            break;
    }
}

void
packed_callstack_to_symbolized(packed_callstack_t *pcs IN,
                               symbolized_callstack_t *scs OUT)
{
    uint i;
    STATS_INC(callstacks_symbolized);
    scs->num_frames = pcs->num_frames;
    scs->num_frames_allocated = pcs->num_frames;
    ASSERT(scs->num_frames > 0, "invalid empty callstack");
    scs->frames = (symbolized_frame_t *)
        global_alloc(sizeof(*scs->frames) * scs->num_frames, HEAPSTAT_CALLSTACK);
    ASSERT(pcs != NULL, "invalid args");
    for (i = 0; i < pcs->num_frames; i++) {
        packed_frame_to_symbolized(pcs, &scs->frames[i], i);
        /* we truncate for real and not just on printing (i#700) */
        if (ops.truncate_below != NULL &&
            text_matches_any_pattern((const char *)scs->frames[i].func,
                                     ops.truncate_below, false)) {
            /* not worth re-allocating */
            scs->num_frames = i + 1;
            break;
        }
    }
}

#ifdef DEBUG
void
packed_callstack_log(packed_callstack_t *pcs, file_t f)
{
    void *drcontext = dr_get_current_drcontext();
    tls_callstack_t *pt = (tls_callstack_t *)
        ((drcontext == NULL) ? NULL : drmgr_get_tls_field(drcontext, tls_idx_callstack));
    char *buf;
    size_t bufsz;
    size_t sofar = 0;
    ASSERT(pcs != NULL, "invalid args");
    if (pt == NULL) {
        /* at init time no pt yet */
        bufsz = MAX_ERROR_INITIAL_LINES + max_callstack_size();
        buf = (char *) global_alloc(bufsz, HEAPSTAT_CALLSTACK);
    } else {
        buf = pt->errbuf;
        bufsz = pt->errbufsz;
    }
    packed_callstack_print(pcs, 0, buf, bufsz, &sofar, NULL);
    if (f == INVALID_FILE)
        LOG_LARGE(0, buf);
    else
        ELOG_LARGE_F(0, f, buf);
    if (pt == NULL)
        global_free(buf, bufsz, HEAPSTAT_CALLSTACK);
}
#endif

uint
packed_callstack_free(packed_callstack_t *pcs)
{
    uint refcount;
    ASSERT(pcs != NULL, "invalid args");
    refcount = atomic_add32_return_sum((volatile int *)&pcs->refcount, - 1);
    if (refcount == 0) {
        if (pcs->first_is_syscall) {
            global_free(PCS_FRAME_LOC(pcs, 0).sysloc, sizeof(syscall_loc_t),
                        HEAPSTAT_CALLSTACK);
        }
        if (pcs->is_packed) {
            if (pcs->frames.packed != NULL) {
                global_free(pcs->frames.packed,
                            sizeof(*pcs->frames.packed)*pcs->num_frames,
                            HEAPSTAT_CALLSTACK);
            }
        } else {
            if (pcs->frames.full != NULL) {
                global_free(pcs->frames.full,
                            sizeof(*pcs->frames.full)*pcs->num_frames,
                            HEAPSTAT_CALLSTACK);
            }
        }
        global_free(pcs, sizeof(*pcs), HEAPSTAT_CALLSTACK);
    }
    return refcount;
}

uint
packed_callstack_refcount(packed_callstack_t *pcs)
{
    return pcs->refcount;
}

void
packed_callstack_add_ref(packed_callstack_t *pcs)
{
    ASSERT(pcs != NULL, "invalid args");
    ATOMIC_INC32(pcs->refcount);
    ASSERT(pcs->refcount > 0, "refcount overflowed");
}

packed_callstack_t *
packed_callstack_clone(packed_callstack_t *src)
{
    packed_callstack_t *dst = (packed_callstack_t *)
        global_alloc(sizeof(*dst), HEAPSTAT_CALLSTACK);
    ASSERT(src != NULL, "invalid args");
    memset(dst, 0, sizeof(*dst));
    dst->refcount = 1;
    dst->num_frames = src->num_frames;
    dst->is_packed = src->is_packed;
    dst->first_is_retaddr = src->first_is_retaddr;
    dst->first_is_syscall = src->first_is_syscall;
    if (dst->is_packed) {
        dst->frames.packed = (packed_frame_t *)
            global_alloc(sizeof(*dst->frames.packed) * src->num_frames,
                         HEAPSTAT_CALLSTACK);
        memcpy(dst->frames.packed, src->frames.packed,
               sizeof(*dst->frames.packed) * src->num_frames);
    } else {
        dst->frames.full = (full_frame_t *)
            global_alloc(sizeof(*dst->frames.full) * src->num_frames,
                         HEAPSTAT_CALLSTACK);
        memcpy(dst->frames.full, src->frames.full,
               sizeof(*dst->frames.full) * src->num_frames);
    }
    if (dst->first_is_syscall) {
        if (dst->is_packed) {
            dst->frames.packed[0].loc.sysloc = (syscall_loc_t *)
                global_alloc(sizeof(syscall_loc_t), HEAPSTAT_CALLSTACK);
        } else {
            dst->frames.full[0].loc.sysloc = (syscall_loc_t *)
                global_alloc(sizeof(syscall_loc_t), HEAPSTAT_CALLSTACK);
        }
        memcpy(PCS_FRAME_LOC(dst, 0).sysloc, PCS_FRAME_LOC(src, 0).sysloc,
               sizeof(syscall_loc_t));
    }
    return dst;
}

uint
packed_callstack_hash(packed_callstack_t *pcs)
{
    uint hash = 0;
    uint i;
    for (i = 0; i < pcs->num_frames; i++) {
        if (!pcs->first_is_syscall || i > 0)
            hash ^= (ptr_uint_t) PCS_FRAME_LOC(pcs, i).addr;
    }
    return hash;
}

bool
packed_callstack_cmp(packed_callstack_t *pcs1, packed_callstack_t *pcs2)
{
    uint i;
    if (PCS_FRAMES(pcs1) == NULL) {
        if (PCS_FRAMES(pcs2) != NULL)
            return false;
        return true;
    }
    if (PCS_FRAMES(pcs2) == NULL)
        return false;
    if (pcs1->num_frames != pcs2->num_frames)
        return false;
    if (!pcs1->first_is_syscall && !pcs2->first_is_syscall &&
        ((pcs1->is_packed && pcs2->is_packed) ||
         (!pcs1->is_packed && !pcs2->is_packed))) {
        return (memcmp(PCS_FRAMES(pcs1), PCS_FRAMES(pcs2),
                       PCS_FRAME_SZ(pcs1)*pcs1->num_frames) == 0);
    }
    /* One is packed, the other is not; or, one has a syscall.
     * We have to walk the frames.
     */
    for (i = 0; i < pcs1->num_frames; i++) {
        modname_info_t *info1 = NULL, *info2 = NULL;
        size_t offs1 = 0, offs2 = 0;
        bool nonsys1, nonsys2;
        nonsys1 = packed_callstack_frame_modinfo(pcs1, i, &info1, &offs1);
        nonsys2 = packed_callstack_frame_modinfo(pcs2, i, &info2, &offs2);
        if ((nonsys1 && !nonsys2) || (!nonsys1 && nonsys2))
            return false;
        if (!nonsys1) {
            if (memcmp(PCS_FRAME_LOC(pcs1, i).sysloc, PCS_FRAME_LOC(pcs2, i).sysloc,
                       sizeof(syscall_loc_t)) != 0)
                return false;
        } else {
            if (PCS_FRAME_LOC(pcs1, i).addr != PCS_FRAME_LOC(pcs2, i).addr)
                return false;
            if (info1 != info2)
                return false;
            if (offs1 != offs2)
                return false;
        }
    }
    return true;
}

void
packed_callstack_md5(packed_callstack_t *pcs, byte digest[MD5_RAW_BYTES])
{
    if (pcs->num_frames == 0) {
        memset(digest, 0, sizeof(digest[0])*MD5_RAW_BYTES);
    } else {
        get_md5_for_region((const byte *)PCS_FRAMES(pcs),
                           PCS_FRAME_SZ(pcs)*pcs->num_frames, digest);
    }
}

void
packed_callstack_crc32(packed_callstack_t *pcs, uint crc[2])
{
    crc32_whole_and_half((const char *)PCS_FRAMES(pcs),
                         PCS_FRAME_SZ(pcs)*pcs->num_frames, crc);
}

uint
packed_callstack_num_frames(packed_callstack_t *pcs)
{
    return pcs->num_frames;
}

/* destroy the packted callstack */
void
packed_callstack_destroy(packed_callstack_t *pcs)
{
    uint count;
    LOG(4, "%s: force-free pcs "PFX"\n", __FUNCTION__, pcs);
    /* There might be callstack left not deleted by the app (e.g., leaks),
     * so we need to force-remove here.
     */
    do {
        count = packed_callstack_free(pcs);
        /* XXX: do we need widen the refcount, it seems unlikely to do 4 billion
         * handle creation system calls from one call site.
         */
        ASSERT(count < UINT_MAX - 1, "underflow in count: likely double-free");
    } while (count > 0);
}

/* add the packed callstack into the hashtable, assuming the caller is holding the lock */
packed_callstack_t *
packed_callstack_add_to_table(hashtable_t *table, packed_callstack_t *pcs
                              _IF_STATS(uint *callstack_count))
{
    packed_callstack_t *existing;

    existing = hashtable_lookup(table, (void *)pcs);
    if (existing == NULL) {
        /* avoid calling lookup twice by not calling hashtable_add() */
        IF_DEBUG(void *prior =)
            hashtable_add_replace(table, (void *)pcs, (void *)pcs);
        ASSERT(prior == NULL, "just did lookup: cannot happen");
        DOLOG(3, {
            LOG(3, "@@@ unique callstack #%d\n", *callstack_count);
            packed_callstack_log(pcs, INVALID_FILE);
        });
        STATS_INC(*callstack_count);
    } else {
        IF_DEBUG(uint count =) packed_callstack_free(pcs);
        ASSERT(count == 0, "refcount should be 0");
        pcs = existing;
    }
    /* The callstack in table is one reference, and the other references
     * will add its reference count. Once all other references are gone
     * and the refcount hits 1, we can remove it from the table.
     */
    packed_callstack_add_ref(pcs);
    return pcs;
}

/***************************************************************************
 * SYMBOLIZED CALLSTACKS
 */

void
symbolized_callstack_print(const symbolized_callstack_t *scs IN,
                           char *buf, size_t bufsz, size_t *sofar,
                           const char *prefix, bool for_log)
{
    uint i;
    size_t max_flen = 0;
    uint print_flags = for_log ? PRINT_FOR_POSTPROCESS : ops.print_flags;
    ASSERT(scs != NULL, "invalid args");
    if (TEST(PRINT_ALIGN_COLUMNS, print_flags)) {
        for (i = 0; i < scs->num_frames; i++) {
            size_t flen = strlen(scs->frames[i].func);
            if (flen > max_flen)
                max_flen = flen;
        }
    }
    for (i = 0; i < scs->num_frames; i++) {
        print_frame(&scs->frames[i], buf, bufsz, sofar, for_log, print_flags,
                    max_flen, prefix);
        /* ops.truncate_below should have been done when symbolized cstack created.
         * too much of a perf hit to assert on every single frame.
         */
    }
}

void
symbolized_callstack_free(symbolized_callstack_t *scs)
{
    ASSERT(scs != NULL, "invalid args");
    if (scs->frames != NULL) {
        global_free(scs->frames, sizeof(*scs->frames) * scs->num_frames_allocated,
                    HEAPSTAT_CALLSTACK);
    }
}

bool
symbolized_callstack_frame_is_module(const symbolized_callstack_t *scs, uint frame)
{
    ASSERT(scs != NULL, "invalid args");
    if (scs->num_frames <= frame)
        return false;
    return scs->frames[frame].is_module;
}

char *
symbolized_callstack_frame_modname(const symbolized_callstack_t *scs, uint frame)
{
    ASSERT(scs != NULL, "invalid args");
    if (scs->num_frames <= frame)
        return NULL;
    ASSERT(scs->frames[frame].is_module ||
           scs->frames[frame].modname[0] == '\0', "modname not initialized");
    return scs->frames[frame].modname;
}

char *
symbolized_callstack_frame_modoffs(const symbolized_callstack_t *scs, uint frame)
{
    ASSERT(scs != NULL, "invalid args");
    if (scs->num_frames <= frame)
        return 0;
    return scs->frames[frame].modoffs;
}

app_pc
symbolized_callstack_frame_modbase(const symbolized_callstack_t *scs, uint frame)
{
    ASSERT(scs != NULL, "invalid args");
    if (scs->num_frames <= frame)
        return NULL;
    if (scs->frames[frame].is_module) {
        if (scs->frames[frame].modbase == NULL) {
            ASSERT(scs->frames[frame].loc.type == APP_LOC_PC &&
                   scs->frames[frame].loc.u.addr.valid, "invalid frame");
            /* If this fails we'll just try again: should be rare, and caller's
             * fault if asking about an unloaded module.
             */
            module_lookup(scs->frames[frame].loc.u.addr.pc,
                          &scs->frames[frame].modbase, NULL, NULL);
        }
    }
    return scs->frames[frame].modbase;
}

char *
symbolized_callstack_frame_func(const symbolized_callstack_t *scs, uint frame)
{
    ASSERT(scs != NULL, "invalid args");
    if (scs->num_frames <= frame)
        return NULL;
    return scs->frames[frame].func;
}

char *
symbolized_callstack_frame_file(const symbolized_callstack_t *scs, uint frame)
{
    ASSERT(scs != NULL, "invalid args");
    if (scs->num_frames <= frame)
        return NULL;
    return scs->frames[frame].fname;
}

void *
symbolized_callstack_frame_data(const symbolized_callstack_t *scs, uint frame)
{
    ASSERT(scs != NULL, "invalid args");
    if (scs->num_frames <= frame)
        return false;
    return scs->frames[frame].user_data;
}

/***************************************************************************
 * MODULES
 */

/* For storing binary callstacks we need to store module names in a shared
 * location to save space and handle unloaded and reloaded modules.
 * Returns the index into modname_array, or -1 on error.
 */
static modname_info_t *
add_new_module(void *drcontext, const module_data_t *info)
{
    modname_info_t *name_info;
    const char *name;
    IF_DEBUG(static bool has_noname = false;)
    size_t sz;
    name = dr_module_preferred_name(info);
    if (name == NULL) {
        name = "";
        /* if multiple w/o names, we lose data */
        ASSERT(!has_noname, "multiple modules w/o name: may lose data");
        IF_DEBUG(has_noname = true;)
    }

    hashtable_lock(&modname_table);
    /* key via path to reduce chance of duplicate name (i#729) */
    name_info = (modname_info_t *) hashtable_lookup(&modname_table,
                                                    (void*)info->full_path);
    if (name_info == NULL) {
        name_info = (modname_info_t *)
            global_alloc(sizeof(*name_info), HEAPSTAT_HASHTABLE);
        name_info->name = drmem_strdup(name, HEAPSTAT_HASHTABLE);
        name_info->path = drmem_strdup(info->full_path, HEAPSTAT_HASHTABLE);
        name_info->index = modname_array_end; /* store first index if multi-entry */
        name_info->id = modname_unique_id++;
        /* we cache this value to avoid re-matching on every frame */
        name_info->hide_modname =
            (ops.modname_hide != NULL &&
             text_matches_any_pattern(name_info->name, ops.modname_hide,
                                      FILESYS_CASELESS));
        name_info->abort_fp_walk =
            (ops.bad_fp_list != NULL &&
             text_matches_any_pattern(name_info->name, ops.bad_fp_list,
                                      FILESYS_CASELESS));
        if (ops.module_load != NULL)
            name_info->user_data = ops.module_load(name_info->path, name, info->start);
        name_info->warned_no_syms = false;
        hashtable_add(&modname_table, (void*)name_info->path, (void*)name_info);
        /* We need an entry for every 16M of module size */
        sz = info->end - info->start;
        while (true) {
            if (modname_array_end >= MAX_MODNAMES_STORED) {
                DO_ONCE({
                    LOG(1, "hit max # packed modules: switching to unpacked frames\n");
                });
                /* Alternative is to have missing names for error reports: for
                 * dup entries we'd just get offset wrong; for first entry we'd
                 * miss in table and print out <unknown module>: not acceptable.
                 */
                name_info->index = -1;
                break;
            }
            LOG(2, "modname_array %d = %s\n", modname_array_end, name);
            modname_array[modname_array_end] = name_info;
            modname_array_end++;
            if (sz <= MAX_MODOFFS_STORED)
                break;
            sz -= MAX_MODOFFS_STORED;
        }
    }

    /* i#446: Log module load events with a full path and unique id for
     * postprocessing.
     */
    dr_fprintf(f_global, NL"module load event: \"%s\" "PFX"-"PFX" modid: %d %s"NL,
               name, info->start, info->end, name_info->id, info->full_path);

    hashtable_unlock(&modname_table);
    return name_info;
}

static void
modname_info_free(void *p)
{
    modname_info_t *info = (modname_info_t *) p;
    if (ops.module_load != NULL)
        ops.module_unload(info->path, info->user_data);
    if (info->name != NULL)
        global_free((void *)info->name, strlen(info->name) + 1, HEAPSTAT_HASHTABLE);
    if (info->path != NULL)
        global_free((void *)info->path, strlen(info->path) + 1, HEAPSTAT_HASHTABLE);
    global_free((void *)info, sizeof(*info), HEAPSTAT_HASHTABLE);
}

/* Caller must hold modtree_lock */
static void
callstack_module_add_region(app_pc start, app_pc end, modname_info_t *info)
{
    IF_DEBUG(rb_node_t *node = )
        rb_insert(module_tree, start, (end - start), (void *)info);
#ifdef DEBUG
    if (node != NULL) {
# ifdef MACOS
        /* dyld shared cache shares __LINKEDIT segments */
        LOG(2, "new module segment overlaps w/ existing\n");
# else
        ASSERT(false, "new module overlaps w/ existing");
# endif
    }
#endif
    if (start < modtree_min_start || modtree_min_start == NULL)
        modtree_min_start = start;
    if (end > modtree_max_end)
        modtree_max_end = end;
}

/* Caller must hold modtree_lock */
static void
callstack_module_remove_region(app_pc start, app_pc end)
{
    rb_node_t *node = rb_find(module_tree, start);
    ASSERT(node != NULL, "module mismatch");
    if (node != NULL) {
        app_pc node_start;
        size_t node_size;
        rb_node_fields(node, &node_start, &node_size, NULL);
        ASSERT(start == node_start &&
               end == node_start + node_size, "module mismatch");
        rb_delete(module_tree, node);
    }
}

static void
callstack_module_get_text_bounds(const module_data_t *info, bool loaded,
                                 app_pc *start OUT, app_pc *end OUT)
{
    ASSERT(loaded, "only supports fully loaded modules");
#ifdef UNIX
    /* Yes, our own x64 libs are not contiguous */
    if (!info->contiguous) {
        /* We assume the 1st segment has .text */
        *start = info->segments[0].start;
        *end = info->segments[0].end;
    } else
#endif
        {
            *start = info->start;
            *end = info->end;
        }
}

/* For storing binary callstacks we need to store module names in a shared
 * location to save space and handle unloaded and reloaded modules.
 */
void
callstack_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    modname_info_t *name_info = add_new_module(drcontext, info);

    /* Record DR and DrMem lib bounds.  We assume they are contiguous. */
    if (text_matches_pattern(name_info->name, DYNAMORIO_LIBNAME, FILESYS_CASELESS)) {
        ASSERT(libdr_base == NULL, "duplicate DR lib");
        callstack_module_get_text_bounds(info, loaded, &libdr_base, &libdr_end);
    } else if (ops.tool_lib_ignore != NULL &&
               text_matches_pattern(name_info->name, ops.tool_lib_ignore,
                                    FILESYS_CASELESS)) {
        ASSERT(libtoolbase == NULL, "duplicate tool lib");
        callstack_module_get_text_bounds(info, loaded, &libtoolbase, &libtoolend);
    }

    /* PR 473640: maintain our own module tree */
    dr_mutex_lock(modtree_lock);
    ASSERT(info->end > info->start, "invalid mod bounds");
#ifdef WINDOWS
    callstack_module_add_region(info->start, info->end, name_info);
#else
    if (info->contiguous)
        callstack_module_add_region(info->start, info->end, name_info);
    else {
        /* Add the non-contiguous segments (i#160/PR 562667) */
        app_pc seg_base;
        uint i;
        ASSERT(info->num_segments > 1 && info->segments != NULL, "invalid seg data");
        seg_base = info->segments[0].start;
        for (i = 1; i < info->num_segments; i++) {
            if (info->segments[i].start > info->segments[i - 1].end) {
                callstack_module_add_region(seg_base, info->segments[i - 1].end,
                                            name_info);
                seg_base = info->segments[i].start;
            } else {
                ASSERT(info->segments[i].start == info->segments[i - 1].end,
                       "module list should be sorted");
            }
        }
        callstack_module_add_region(seg_base, info->segments[i - 1].end, name_info);
    }
#endif
    /* update cached values */
    modtree_last_hit = NULL;
    modtree_last_miss = NULL;
    dr_mutex_unlock(modtree_lock);
}

void
callstack_module_unload(void *drcontext, const module_data_t *info)
{
    /* PR 473640: maintain our own module tree */
    rb_node_t *node;
    app_pc node_start;
    size_t node_size;
    ASSERT(info->end > info->start, "invalid mod bounds");
    LOG(1, "module unload event: \"%s\" "PFX"-"PFX"\n",
        (dr_module_preferred_name(info) == NULL) ? "" :
        dr_module_preferred_name(info), info->start, info->end);
    dr_mutex_lock(modtree_lock);

#ifdef WINDOWS
    callstack_module_remove_region(info->start, info->end);
#else
    if (info->contiguous)
        callstack_module_remove_region(info->start, info->end);
    else {
        /* Remove all non-contiguous segments (i#160/PR 562667) */
        app_pc seg_base;
        uint i;
        ASSERT(info->num_segments > 1 && info->segments != NULL, "invalid seg data");
        seg_base = info->segments[0].start;
        for (i = 1; i < info->num_segments; i++) {
            if (info->segments[i].start > info->segments[i - 1].end) {
                callstack_module_remove_region(seg_base, info->segments[i - 1].end);
                seg_base = info->segments[i].start;
            } else {
                ASSERT(info->segments[i].start == info->segments[i - 1].end,
                       "module list should be sorted");
            }
        }
        callstack_module_remove_region(seg_base, info->segments[i - 1].end);
    }
#endif

    /* update cached bounds */
    node = rb_max_node(module_tree);
    if (node != NULL) {
        rb_node_fields(node, &node_start, &node_size, NULL);
        modtree_max_end = node_start + node_size;
    } else
        modtree_max_end = NULL;
    node = rb_min_node(module_tree);
    if (node != NULL) {
        rb_node_fields(node, &node_start, NULL, NULL);
        modtree_min_start = node_start;
    } else
        modtree_min_start = NULL;
    modtree_last_start = NULL;
    modtree_last_hit = NULL;
    modtree_last_miss = NULL;

    dr_mutex_unlock(modtree_lock);
}

static bool
module_lookup(byte *pc, app_pc *start OUT, size_t *size OUT, modname_info_t **name)
{
    rb_node_t *node;
    bool res = false;
    dr_mutex_lock(modtree_lock);
    /* We cache to avoid the rb_in_node cost */
    if (modtree_last_start != NULL &&
        pc >= modtree_last_start && pc < modtree_last_start + modtree_last_size) {
        /* use cached values */
        res = true;
        LOG(5, "module_lookup: using cached "PFX"\n", modtree_last_start);
    } else {
        LOG(5, "module_lookup: "PFX" doesn't match cached "PFX"\n",
            pc, modtree_last_start);
        node = rb_in_node(module_tree, pc);
        if (node != NULL) {
            res = true;
            rb_node_fields(node, &modtree_last_start, &modtree_last_size,
                           (void **) &modtree_last_name_info);
        }
    }
    if (res) {
        if (start != NULL)
            *start = modtree_last_start;
        if (size != NULL)
            *size = modtree_last_size;
        if (name != NULL)
            *name = modtree_last_name_info;
    }
    dr_mutex_unlock(modtree_lock);
    return res;
}

/* this is exported for PR 570839 for is_image() */
bool
is_in_module(byte *pc)
{
    /* We cache the last page queried for performance */
    bool res = false;
    /* This is a perf bottleneck so we use caching.
     * We read these values w/o a lock, assuming they are written
     * atomically (since aligned they won't cross cache lines).
     */
    if (pc < modtree_min_start || pc >= modtree_max_end)
        res = false;
    else if ((app_pc) ALIGN_BACKWARD(pc, PAGE_SIZE) == modtree_last_miss)
        res = false;
    else if ((app_pc) ALIGN_BACKWARD(pc, PAGE_SIZE) == modtree_last_hit)
        res = true;
    else {
        dr_mutex_lock(modtree_lock);
        LOG(5, "is_in_module: "PFX" missed cached "PFX"-"PFX", miss="PFX", hit="PFX"\n",
            pc, modtree_min_start, modtree_max_end, modtree_last_miss, modtree_last_hit);
        res = (rb_in_node(module_tree, pc) != NULL);
        /* XXX: we could cache the range on a hit, and the range from prev lower
         * to next higher on a miss: but going to wait for this to show up
         * in pclookup.
         */
        if (res)
            modtree_last_hit = (app_pc) ALIGN_BACKWARD(pc, PAGE_SIZE);
        else
            modtree_last_miss = (app_pc) ALIGN_BACKWARD(pc, PAGE_SIZE);
        dr_mutex_unlock(modtree_lock);
    }
    return res;
}

const char *
module_lookup_path(byte *pc)
{
    modname_info_t *name_info;
    bool found = module_lookup(pc, NULL, NULL, &name_info);
    return found ? name_info->path : NULL;
}

/* Exported for i#838, module wildcard suppression. */
const char *
module_lookup_preferred_name(byte *pc)
{
    modname_info_t *name_info;
    bool found = module_lookup(pc, NULL, NULL, &name_info);
    return found ? name_info->name : NULL;
}

void *
module_lookup_user_data(byte *pc, app_pc *start OUT, size_t *size OUT)
{
    modname_info_t *name_info;
    bool found = module_lookup(pc, NULL, NULL, &name_info);
    return found ? name_info->user_data : NULL;
}

/* Warn once (or twice with races) about modules that don't have symbols, and
 * log them so we can fetch symbols at the end of the run.
 */
static void
warn_no_symbols(modname_info_t *name_info)
{
    if (!name_info->warned_no_syms) {
        name_info->warned_no_syms = true;
        WARN("WARNING: unable to load symbols for %s\n", name_info->path);
        if (ops.missing_syms_cb != NULL) {
            ops.missing_syms_cb(name_info->path);
        }
    }
}

void
module_check_for_symbols(const char *modpath)
{
    drsym_debug_kind_t kind;
    modname_info_t *name_info;

    if (!modname_table_initialized) {
        return;  /* Happens for perturb_only. */
    }

    hashtable_lock(&modname_table);
    name_info = (modname_info_t *) hashtable_lookup(&modname_table,
                                                    (void *)modpath);
    /* The lookup can fail on ntdll lookups during dr_init, because we haven't
     * hit the initial module load events yet.  That's OK, we'll probably catch
     * those modules later.
     */
    if (name_info != NULL) {
        drsym_error_t res = drsym_get_module_debug_kind(modpath, &kind);
        if (res != DRSYM_SUCCESS || !TEST(DRSYM_SYMBOLS, kind)) {
            warn_no_symbols(name_info);
        }
    }
    hashtable_unlock(&modname_table);
}

/****************************************************************************
 * Application locations
 */

void
pc_to_loc(app_loc_t *loc, app_pc pc)
{
    ASSERT(loc != NULL, "invalid param");
    loc->type = APP_LOC_PC;
    loc->u.addr.valid = true;
    loc->u.addr.pc = pc;
}

void
syscall_to_loc(app_loc_t *loc, drsys_sysnum_t sysnum, const char *aux)
{
    ASSERT(loc != NULL, "invalid param");
    loc->type = APP_LOC_SYSCALL;
    loc->u.syscall.sysnum = sysnum;
    loc->u.syscall.syscall_aux = aux;
}

/* loc_to_pc() and loc_to_print() must be defined by the tool-specific code */
