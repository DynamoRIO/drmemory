/* **********************************************************
 * Copyright (c) 2010-2012 Google, Inc.  All rights reserved.
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
#include "per_thread.h"
#include "callstack.h"
#include "utils.h"
#include "redblack.h"
#ifdef USE_DRSYMS
# include "drsyms.h"
#endif
#ifdef LINUX
# include <string.h>
# include <errno.h>
#endif
#include <limits.h>

/* global options: xref PR 612970 on using generalized per-file options */
static uint op_max_frames;
static uint op_stack_swap_threshold;
static uint op_fp_flags; /* set of FP_ flags */
static uint op_print_flags; /* set of PRINT_ flags */
static size_t op_fp_scan_sz;
/* optional: only needed if packed_callstack_record is passed a pc<64K */
static const char * (*op_get_syscall_name)(uint);
static bool (*op_is_dword_defined)(byte *);
static bool (*op_ignore_xbp)(void *drcontext, dr_mcontext_t *mc);
static const char *op_truncate_below;
static const char *op_modname_hide;
static const char *op_srcfile_prefix;
static const char *op_srcfile_hide;

#define IGNORE_FILE_CASE IF_WINDOWS_ELSE(true, false)

/* PR 454536: to avoid races we read a page all at once */
static void *page_buf_lock;
static char page_buf[PAGE_SIZE];

#ifdef WINDOWS
# define FP_PREFIX ""
#else
# define FP_PREFIX "\t"
#endif
#define LINE_PREFIX "    "

#ifdef STATISTICS
uint find_next_fp_scans;
uint symbol_names_truncated;
uint cstack_is_retaddr;
uint cstack_is_retaddr_backdecode;
uint cstack_is_retaddr_unreadable;
#endif

/****************************************************************************
 * Binary callstacks for storing callstacks of allocation sites.
 * Print-format callstacks take up too much room (PR 424179).
 * We do NOT store the frame pointers, to save space.  They are
 * rarely needed in allocation site analysis.
 */

typedef union {
    app_pc addr;
    /* syscalls store a string identifying param (PR 525269) */
    const char *syscall_aux;
} frame_loc_t;

/* Packed binary callstack */
typedef struct _packed_frame_t {
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
    /* For syscalls, we use index 0 and store syscall # in modoffs.
     * For non-module addresses, we use index MAX_MODNAMES_STORED.
     */
    uint modname_idx : 8;
} packed_frame_t;

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
    /* i#589: don't show module! for executable or other modules */
    bool hide_modname;
#ifdef DEBUG
    /* Avoid repeated warnings about symbols */
    bool warned_no_syms;
#endif
} modname_info_t;

/* When the number of modules hits the max for our 8-bit index we
 * have to switch to these frames
 */
typedef struct _full_frame_t {
    frame_loc_t loc;
    size_t modoffs;
    /* For syscalls, we use MODNAME_INFO_SYSCALL and store the syscall # in modoffs.
     * For non-module addresses, we use NULL.
     */
    modname_info_t *modname;
} full_frame_t;

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

/* Array mapping index to name for use with packed_frame_t.
 * Points at same modname_info_t as hashtable entry.
 * Hashtable lock synchronizes writes; no synch on reads.
 */
#define MAX_MODNAMES_STORED UCHAR_MAX
static modname_info_t *modname_array[MAX_MODNAMES_STORED];
/* Index 0 is reserved to indicate a system call as the top frame of a callstack */
static uint modname_array_end = 1;

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
};

/***************************************************************************/

static bool
module_lookup(byte *pc, app_pc *start OUT, size_t *size OUT, modname_info_t **name OUT);

static void
modname_info_free(void *p);

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
    return ((op_max_frames+1)/*for the ... line: over-estimate*/
            *(strlen(max_line)+max_addr_sym_len)) + 1/*null*/;
}

void
callstack_init(uint callstack_max_frames, uint stack_swap_threshold,
               uint fp_flags, size_t fp_scan_sz, uint print_flags,
               const char *(*get_syscall_name)(uint),
               bool (*is_dword_defined)(byte *),
               bool (*ignore_xbp)(void *, dr_mcontext_t *),
               const char *callstack_truncate_below,
               const char *callstack_modname_hide,
               const char *callstack_srcfile_hide,
               const char *callstack_srcfile_prefix)
{
    op_max_frames = callstack_max_frames;
    op_stack_swap_threshold = stack_swap_threshold;
    op_fp_flags = fp_flags;
    op_fp_scan_sz = fp_scan_sz;
    op_print_flags = print_flags;
    op_get_syscall_name = get_syscall_name;
    op_is_dword_defined = is_dword_defined;
    op_ignore_xbp = ignore_xbp;
    op_truncate_below = callstack_truncate_below;
    op_modname_hide = callstack_modname_hide;
    op_srcfile_hide = callstack_srcfile_hide;
    op_srcfile_prefix = callstack_srcfile_prefix;
    page_buf_lock = dr_mutex_create();
    hashtable_init_ex(&modname_table, MODNAME_TABLE_HASH_BITS, HASH_STRING_NOCASE,
                      false/*!str_dup*/, false/*!synch*/, modname_info_free, NULL, NULL);
    modtree_lock = dr_mutex_create();
    module_tree = rb_tree_create(NULL);

#ifdef USE_DRSYMS
    IF_WINDOWS(ASSERT(using_private_peb(), "private peb not preserved"));
    /* we rely on drsym_init() being called in utils_init() */
#endif
}

void
callstack_exit(void)
{
    dr_mutex_destroy(page_buf_lock);

    hashtable_delete(&modname_table);

    dr_mutex_lock(modtree_lock);
    rb_tree_destroy(module_tree);
    dr_mutex_unlock(modtree_lock);
    dr_mutex_destroy(modtree_lock);

#ifdef USE_DRSYMS
    IF_WINDOWS(ASSERT(using_private_peb(), "private peb not preserved"));
#endif
}

void
callstack_thread_init(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    /* PR 456181: we need our error reports to use a single atomic write.
     * We use a thread-private buffer to avoid using stack space or locks.
     * We can have a second callstack for delayed frees (i#205).
     */
    pt->errbufsz = MAX_ERROR_INITIAL_LINES + max_callstack_size() * 2;
    pt->errbuf = (char *) thread_alloc(drcontext, pt->errbufsz, HEAPSTAT_CALLSTACK);
#ifdef WINDOWS
    if (get_TEB() != NULL) {
        pt->stack_lowest_frame = get_TEB()->StackBase;
    } 
#endif
}

void
callstack_thread_exit(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    thread_free(drcontext, (void *) pt->errbuf, pt->errbufsz, HEAPSTAT_CALLSTACK);
}

/***************************************************************************/

static void
init_symbolized_frame(symbolized_frame_t *frame OUT, uint frame_num)
{
    frame->num = frame_num;
    memset(&frame->loc, 0, sizeof(frame->loc));
    frame->is_module = false;
    frame->hide_modname = false;
    frame->has_symbols = false;
    frame->modname[0] = '\0';
    frame->modoffs[0] = '\0';
    frame->func[0] = '?';
    frame->func[1] = '\0';
    frame->funcoffs = 0;
    frame->fname[0] = '\0';
    frame->line = 0;
    frame->lineoffs = 0;
}

#ifdef USE_DRSYMS
/* Symbol lookup: i#44/PR 243532 */
static void
lookup_func_and_line(symbolized_frame_t *frame OUT,
                     modname_info_t *name_info IN, size_t modoffs)
{
    ssize_t len = 0;
    drsym_error_t symres;
    drsym_info_t *sym;
    const char *modpath = name_info->path;
    char sbuf[sizeof(*sym) + MAX_FUNC_LEN];
    sym = (drsym_info_t *) sbuf;
    sym->struct_size = sizeof(*sym);
    sym->name_size = MAX_FUNC_LEN;
    IF_WINDOWS(ASSERT(using_private_peb(), "private peb not preserved"));
    symres = drsym_lookup_address(modpath, modoffs, sym, DRSYM_DEMANGLE);
    if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
        LOG(4, "symbol %s+"PIFX" => %s+"PIFX" ("PIFX"-"PIFX")\n",
            modpath, modoffs, sym->name, modoffs - sym->start_offs,
            sym->start_offs, sym->end_offs);
        if (sym->name_available_size >= sym->name_size) {
            DO_ONCE({ 
                WARN("WARNING: at least one function name longer than max: %s\n",
                     sym->name);
            });
            STATS_INC(symbol_names_truncated);
        }
        frame->has_symbols = TEST(DRSYM_SYMBOLS, sym->debug_kind);
        dr_snprintf(frame->func, MAX_FUNC_LEN, sym->name);
        NULL_TERMINATE_BUFFER(frame->func);
        frame->funcoffs = (modoffs - sym->start_offs);
        if (symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
            frame->fname[0] = '\0';
            frame->line = 0;
            frame->lineoffs = 0;
        } else {
            dr_snprintf(frame->fname, MAX_FILENAME_LEN, sym->file);
            NULL_TERMINATE_BUFFER(frame->fname);
            frame->line = sym->line;
            frame->lineoffs = sym->line_offs;
        }
    } else {
# ifdef DEBUG
        /* only warn once (or twice w/ races) */
        if (!name_info->warned_no_syms) {
            name_info->warned_no_syms = true;
            WARN("WARNING: unable to load symbols for %s\n", modpath);
        }
# endif
    }
}

bool
print_symbol(byte *addr, char *buf, size_t bufsz, size_t *sofar)
{
    bool res;
    ssize_t len = 0;
    drsym_error_t symres;
    drsym_info_t *sym;
    char sbuf[sizeof(*sym) + MAX_FUNC_LEN];
    module_data_t *data;
    const char *modname;
    data = dr_lookup_module(addr);
    if (data == NULL)
        return false;
    ASSERT(data->start <= addr && data->end > addr, "invalid module lookup");
    modname = dr_module_preferred_name(data);
    if (modname == NULL)
        modname = "";
    sym = (drsym_info_t *) sbuf;
    sym->struct_size = sizeof(*sym);
    sym->name_size = MAX_FUNC_LEN;
    IF_WINDOWS(ASSERT(using_private_peb(), "private peb not preserved"));
    symres = drsym_lookup_address(data->full_path, addr - data->start, sym,
                                  DRSYM_DEMANGLE);
    if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
        if (sym->name_available_size >= sym->name_size) {
            DO_ONCE({ 
                LOG(1, "WARNING: at least one symbol name longer than max: %s\n",
                    sym->name);
            });
            STATS_INC(symbol_names_truncated);
        }
        /* I like having +0x%x to show offs within func but we'll match addr2line */
        BUFPRINT_NO_ASSERT(buf, bufsz, *sofar, len, " %s!%s", modname, sym->name);
        if (TEST(PRINT_SYMBOL_OFFSETS, op_print_flags)) {
            /* no assert for any of these bufprints: for just printing we'll truncate */
            BUFPRINT_NO_ASSERT(buf, bufsz, *sofar, len, "+"PIFX,
                               addr - data->start - sym->start_offs);
        }
        res = true;
    } else {
        BUFPRINT_NO_ASSERT(buf, bufsz, *sofar, len, " %s!?", modname);
        res = false;
    }
    dr_free_module_data(data);
    return res;;
}
#endif

static bool
frame_include_srcfile(symbolized_frame_t *frame IN)
{
    return (frame->fname[0] != '\0' &&
            /* i#589: support hiding source files matching pattern */
            (op_srcfile_hide == NULL ||
             !text_matches_any_pattern(frame->fname, op_srcfile_hide, IGNORE_FILE_CASE)));
}

/* We provide control over many aspects of callstack formatting (i#290)
 * encoded in op_print_flags.
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
        if (op_srcfile_prefix != NULL) {
            /* i#575: support truncating source file prefix */
            const char *matched;
            const char *match =
                text_contains_any_string(fname, op_srcfile_prefix,
                                         IGNORE_FILE_CASE, &matched);
            if (match != NULL) {
                fname = match + strlen(matched);
                if (fname[0] == '/' || fname[0] == '\\')
                    fname++;
            }
        }
        BUFPRINT(buf, bufsz, *sofar, len, "%."STRINGIFY(MAX_FILENAME_LEN)"s", fname);
        if (!TEST(PRINT_SRCFILE_NO_COLON, print_flags))
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
    uint flags = use_custom_flags ? custom_flags : op_print_flags;
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
         (frame->is_module              && TEST(PRINT_MODULE_OFFSETS, flags)));
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
        if (last_frame != NULL && op_truncate_below != NULL) {
            *last_frame = text_matches_any_pattern((const char *)frame.func,
                                                   op_truncate_below, false);
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

#define OP_CALL_DIR 0xe8
#define OP_CALL_IND 0xff

static bool
is_retaddr(byte *pc)
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
    STATS_INC(cstack_is_retaddr);
    if (!is_in_module(pc))
        return false;
    if (!TEST(FP_SEARCH_DO_NOT_DISASM, op_fp_flags)) {
        /* The is_in_module() check is more expensive than our 3 derefs here.
         * We do not bother to cache frequent/recent values.
         */
        /* more efficient to read 3 dwords than safe_read 6 into a buffer */
        bool match;
        STATS_INC(cstack_is_retaddr_backdecode);
        DR_TRY_EXCEPT(dr_get_current_drcontext(), {
            match = (*(pc - 5) == OP_CALL_DIR ||
                     /* indirect through reg: 0xff /2 */
                     (*(pc - 2) == OP_CALL_IND && ((*(pc - 1) >> 3) & 0x7) == 2) ||
                     /* indirect through reg w/ 1B offs: 0xff /2 offs */
                     (*(pc - 3) == OP_CALL_IND && ((*(pc - 2) >> 3) & 0x7) == 2) ||
                     /* indirect through mem: 0xff /2 + disp */
                     (*(pc - 6) == OP_CALL_IND && ((*(pc - 5) >> 3) & 0x7) == 2));
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
            print_symbol(pc, buf, BUFFER_SIZE_ELEMENTS(buf), &sofar);
            LOG(1, "%s\n", buf);
        });
#endif
        return match;
    } else
        return true;
}

/* caller must hold page_buf_lock */
static app_pc
find_next_fp(per_thread_t *pt, app_pc fp, bool top_frame, app_pc *retaddr/*OUT*/)
{
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
          (fp - pt->stack_lowest_frame) < op_stack_swap_threshold) ||
         /* if hit a zero or bad fp near the lowest frame, don't scan.
          * some apps like perlbmk have some weird loader callstacks
          * and then a solid bottom frame so try not to scan every time.
          * xref i#246.
          */
         (!top_frame && (pt->stack_lowest_frame - fp) < FP_NO_SCAN_NEAR_LOW_THRESH))) {
        LOG(4, "find_next_fp: aborting b/c beyond stack_lowest_frame\n");
        return NULL;
    }
    /* PR 454536: dr_memory_is_readable() is racy so we use a safe_read().
     * On Windows safe_read() costs 1 system call: perhaps DR should
     * use try/except there like on Linux?
     * Should we also store the stack bounds and then we know when
     * to stop instead of incurring a fault on every callstack?
     * XXX: should support partial safe read for invalid page next to stack 
     */
    if (safe_read((app_pc)ALIGN_BACKWARD(fp, PAGE_SIZE), PAGE_SIZE, page_buf)) {
        app_pc buf_pg = (app_pc) ALIGN_BACKWARD(fp, PAGE_SIZE);
        app_pc tos = fp;
        app_pc sp;
        app_pc slot0 = 0, slot1;
        bool match, match_next_frame, fp_defined = false;
        size_t ret_offs = TEST(FP_SEARCH_REQUIRE_FP, op_fp_flags) ? sizeof(app_pc) : 0;
        app_pc stop = tos + op_fp_scan_sz;
#ifdef WINDOWS
        /* if on original thread stack, stop at limit (i#588) */
        TEB *teb = get_TEB();
        if (teb != NULL && fp >= (app_pc)teb->StackLimit && fp < (app_pc)teb->StackBase)
            stop = (app_pc)teb->StackBase;
#endif
        /* Scan one page worth and look for potential fp,retaddr pair */
        STATS_INC(find_next_fp_scans);
        /* We only look at fp if TEST(FP_SEARCH_REQUIRE_FP, op_fp_flags) */
        for (sp = tos; sp < stop; sp+=sizeof(app_pc)) {
            match = false;
            match_next_frame = false;
            if (retaddr != NULL)
                *retaddr = NULL;
            if (TEST(FP_SEARCH_REQUIRE_FP, op_fp_flags)) {
                ASSERT((app_pc)ALIGN_BACKWARD(sp, PAGE_SIZE) == buf_pg, "buf error");
                if (op_is_dword_defined != NULL)
                    fp_defined = op_is_dword_defined(sp);
                if (fp_defined)
                    slot0 = *((app_pc*)&page_buf[sp - buf_pg]);
            }
            /* Retrieve next page if slot1 will touch it */
            if ((app_pc)ALIGN_BACKWARD(sp + ret_offs, PAGE_SIZE) != buf_pg) {
                buf_pg = (app_pc) ALIGN_BACKWARD(sp + ret_offs, PAGE_SIZE);
                if (!safe_read(buf_pg, PAGE_SIZE, page_buf))
                    break;
            }
            if (TEST(FP_SEARCH_REQUIRE_FP, op_fp_flags) && !fp_defined)
                continue;
            if (op_is_dword_defined != NULL &&
                !op_is_dword_defined(sp + ret_offs))
                continue; /* retaddr not defined */
            if (!TEST(FP_SEARCH_REQUIRE_FP, op_fp_flags) ||
                (slot0 > tos && slot0 - tos < op_stack_swap_threshold)) {
                slot1 = *((app_pc*)&page_buf[(sp + ret_offs) - buf_pg]);
                /* We should only consider retaddr in code section but
                 * let's keep it simple for now.
                 * We ignore DGC: perhaps a dr_is_executable_memory() could
                 * be used instead of checking modules.
                 * OPT: keep all modules in hashtable for quicker check
                 * that doesn't require alloc+free of heap */
                if (is_retaddr(slot1))
                    match = true;
#ifdef WINDOWS
                else if (top_frame && TEST(FP_SEARCH_REQUIRE_FP, op_fp_flags)) {
                    /* PR 475715: msvcr80!malloc pushes ebx and then ebp!  It then
                     * uses ebp as scratch, so we end up here for the top frame
                     * of a leak callstack.
                     */
                    slot1 = *((app_pc*)&page_buf[(sp + 2*ret_offs) - buf_pg]);
                    if (is_retaddr(slot1)) {
                        match = true;
                        /* Do extra check for this case even if flags don't call for it */
                        match_next_frame = true;
                        /* Since there's a gap we return the retaddr */
                        ASSERT(retaddr != NULL, "invalid arg");
                        *retaddr = slot1;
                    }
                }
#endif
            }
            if (match) {
                app_pc parent_ret_ptr = slot0 + ret_offs;
                app_pc parent_ret;
                if (!TEST(FP_SEARCH_REQUIRE_FP, op_fp_flags)) {
                    /* caller expects fp,ra pair */
                    return sp - sizeof(app_pc);
                }
                if ((TEST(FP_SEARCH_MATCH_SINGLE_FRAME, op_fp_flags) &&
                     !match_next_frame))
                    return sp;
                /* Require the next retaddr to be in a module as well, to avoid
                 * continuing past the bottom frame on ESXi (xref PR 469043)
                 */
                if (buf_pg == (app_pc)ALIGN_BACKWARD(parent_ret_ptr, PAGE_SIZE)) {
                    parent_ret = *((app_pc*)&page_buf[parent_ret_ptr - buf_pg]);
                } else {
                    if (!safe_read(parent_ret_ptr, sizeof(parent_ret), &parent_ret))
                        parent_ret = NULL;
                }
                if (parent_ret != NULL && is_retaddr(parent_ret)) {
                    return sp;
                }
                match = false;
            }
        }
    }
    return NULL;
}

void
print_callstack(char *buf, size_t bufsz, size_t *sofar, dr_mcontext_t *mc, 
                bool print_fps, packed_callstack_t *pcs, int num_frames_printed,
                bool for_log)
{
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)
        ((drcontext == NULL) ? NULL : dr_get_tls_field(drcontext));
    int num = num_frames_printed;   /* PR 475453 - wrong call stack depths */
    ssize_t len = 0;
    ptr_uint_t *pc = (mc == NULL ? NULL : (ptr_uint_t *) mc->ebp);
    size_t prev_sofar = 0;
    struct {
        app_pc next_fp;
        app_pc retaddr;
    } appdata;
    app_pc custom_retaddr = NULL;
    app_pc lowest_frame = NULL;
    bool first_iter = true;
    bool have_appdata = false;
    bool scanned = false;
    bool last_frame = false;

    ASSERT(num == 0 || num == 1, "only 1 frame can already be printed");
    ASSERT((buf != NULL && sofar != NULL && pcs == NULL) ||
           (buf == NULL && sofar == NULL && pcs != NULL),
           "print_callstack: can't pass buf and pcs");

    /* lock the buffer used by find_next_fp */
    if (buf != NULL)
        dr_mutex_lock(page_buf_lock);

    if (mc != NULL) {
    LOG(4, "initial fp="PFX" vs sp="PFX" def=%d\n",
               mc->ebp, mc->esp,
               (op_is_dword_defined == NULL) ? 0 : op_is_dword_defined((byte*)mc->ebp));
    }
    if (mc != NULL && mc->esp != 0 &&
        (!ALIGNED(mc->ebp, sizeof(void*)) ||
         mc->ebp < mc->esp || 
         mc->ebp - mc->esp > op_stack_swap_threshold ||
         (op_ignore_xbp != NULL &&
          op_ignore_xbp(drcontext, mc)) ||
         /* avoid stale fp,ra pair (i#640) */
         (op_is_dword_defined != NULL &&
          (!op_is_dword_defined((byte*)mc->ebp) ||
           !op_is_dword_defined((byte*)mc->ebp + sizeof(void*)))) ||
         (!safe_read((byte *)mc->ebp, sizeof(appdata), &appdata) ||
          /* check the very first retaddr since ebp might point at
           * a misleading stack slot
           */
          (!TEST(FP_DO_NOT_CHECK_FIRST_RETADDR, op_fp_flags) &&
           !is_retaddr(appdata.retaddr))))) {
        /* We may start out in the middle of a frameless function that is
         * using ebp for other purposes.  Heuristic: scan stack for fp + retaddr.
         */
        LOG(4, "find_next_fp b/c starting w/ non-fp ebp\n");
        pc = (ptr_uint_t *) find_next_fp(pt, (app_pc)mc->esp, true/*top frame*/,
                                         &custom_retaddr);
        scanned = true;
    }
    while (pc != NULL) {
        if (!have_appdata &&
            !safe_read((byte *)pc, sizeof(appdata), &appdata)) {
            LOG(4, "truncating callstack: can't read "PFX"\n", pc);
            break;
        }
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
                                         !TEST(FP_SHOW_NON_MODULE_FRAMES, op_fp_flags),
                                         true, for_log, &last_frame, num)) ||
                   (pcs != NULL &&
                    address_to_frame(NULL, pcs, appdata.retaddr, NULL,
                                     !TEST(FP_SHOW_NON_MODULE_FRAMES, op_fp_flags),
                                     true, pcs->num_frames))) {
            num++;
            if (last_frame)
                break;
        } else {
            if (buf != NULL) /* undo the fp= print */
                *sofar = prev_sofar;
            if (first_iter) { /* don't trust "num == num_frames_printed" as test for 1st */
                /* We may have started in a frameless function using ebp for
                 * other purposes but it happens to point to higher on the stack.
                 * Start over w/ top of stack to avoid skipping a frame (i#521).
                 */
                LOG(4, "find_next_fp b/c starting w/ non-fp ebp\n");
                pc = (ptr_uint_t *) find_next_fp(pt, (app_pc)mc->esp, true/*top frame*/,
                                                 &custom_retaddr);
                scanned = true;
                first_iter = false; /* don't loop */
                continue;
            }
        }
        first_iter = false;
        /* pcs->num_frames could be larger if frames were printed before this routine */
        if (num >= op_max_frames || (pcs != NULL && pcs->num_frames >= op_max_frames)) {
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
            if (!TEST(FP_STOP_AT_BAD_ZERO_FRAME, op_fp_flags)) {
                LOG(4, "find_next_fp b/c hit zero fp\n");
                pc = (ptr_uint_t *) find_next_fp(pt, ((app_pc)pc) + sizeof(appdata),
                                                 false/*!top*/, NULL);
                scanned = true;
            } else {
                LOG(4, "truncating callstack: zero frame ptr\n");
                break;
            }
        } else {
            /* appdata.next_fp is candidate */
            bool out_of_range =
                (appdata.next_fp < (app_pc)pc ||
                 (appdata.next_fp - (app_pc)pc) >= op_stack_swap_threshold);
            app_pc next_fp = appdata.next_fp;
            if (!out_of_range &&
                !safe_read((byte *)next_fp, sizeof(appdata), &appdata)) {
                LOG(4, "truncating callstack: can't read "PFX"\n", pc);
                break;
            }
            if (out_of_range ||
                (!TEST(FP_DO_NOT_CHECK_RETADDR, op_fp_flags) &&
                 /* checking retaddr on regular fp chain walk is a 40% perf hit
                  * on cfrac and roboop so we avoid it if we've never had to
                  * do a scan, trusting the fp's to be genuine (overridden by
                  * FP_CHECK_RETADDR_PRE_SCAN)
                  */
                 (scanned || TEST(FP_CHECK_RETADDR_PRE_SCAN, op_fp_flags)) &&
                 !is_retaddr(appdata.retaddr))) {
                if (!TEST(FP_STOP_AT_BAD_NONZERO_FRAME, op_fp_flags)) {
                    LOG(4, "find_next_fp b/c hit bad non-zero fp\n");
                    pc = (ptr_uint_t *) find_next_fp(pt, ((app_pc)pc) + sizeof(appdata),
                                                     false/*!top*/, NULL);
                    scanned = true;
                } else {
                    LOG(4, "truncating callstack: bad frame ptr "PFX"\n", next_fp);
                    break;
                }
            } else {
                have_appdata = true;
                pc = (ptr_uint_t *) next_fp;
            }
        }
        if (pc == NULL)
            LOG(4, "truncating callstack: can't find next fp\n");
    }
    if (num == 0 && buf != NULL && print_fps) {
        BUFPRINT(buf, bufsz, *sofar, len,
                 FP_PREFIX"<call stack frame ptr "PFX" unreadable>"NL, pc);
    }
    if (pt != NULL && lowest_frame > pt->stack_lowest_frame)
        pt->stack_lowest_frame = lowest_frame;

    if (buf != NULL) {
        buf[bufsz-2] = '\n';
        buf[bufsz-1] = '\0';
        dr_mutex_unlock(page_buf_lock);
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
#ifdef LINUX
            /* FIXME: haven't tested this */
            if (res == -EINTR)
                continue;
#endif
            ASSERT(false, "dr_write_file failed");
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
print_callstack_to_file(void *drcontext, dr_mcontext_t *mc, app_pc pc, file_t f)
{
    size_t sofar = 0;
    ssize_t len;
    per_thread_t *pt = (per_thread_t *)
        ((drcontext == NULL) ? NULL : dr_get_tls_field(drcontext));
    /* mc and pc will be NULL for startup heap iter */
    if (pt == NULL) {
        LOG(1, "Can't report callstack as pt is NULL\n");
        return;
    }

    BUFPRINT(pt->errbuf, pt->errbufsz, sofar, len, "# 0 ");
    print_address(pt->errbuf, pt->errbufsz, &sofar, pc, NULL, true/*for log*/);
    print_callstack(pt->errbuf, pt->errbufsz, &sofar, mc,
                    true/*incl fp*/, NULL, 1, true);
    print_buffer(f == INVALID_FILE ? pt->f : f, pt->errbuf);
}
#endif /* DEBUG */

/****************************************************************************
 * Binary callstacks for storing callstacks of allocation sites.
 */

/* Used for standalone allocation, rather than printing as part of an error report.
 * Caller must call free_callstack() to free buf_out.
 */
void
packed_callstack_record(packed_callstack_t **pcs_out/*out*/, dr_mcontext_t *mc,
                        app_loc_t *loc)
{
    packed_callstack_t *pcs = (packed_callstack_t *)
        global_alloc(sizeof(*pcs), HEAPSTAT_CALLSTACK);
    size_t sz_out;
    int num_frames_printed = 0;
    ASSERT(pcs_out != NULL, "invalid args");
    memset(pcs, 0, sizeof(*pcs));
    pcs->refcount = 1;
    if (modname_array_end < MAX_MODNAMES_STORED) {
        pcs->is_packed = true;
        pcs->frames.packed = (packed_frame_t *)
            global_alloc(sizeof(*pcs->frames.packed) * op_max_frames, HEAPSTAT_CALLSTACK);
    } else {
        pcs->is_packed = false;
        pcs->frames.full = (full_frame_t *)
            global_alloc(sizeof(*pcs->frames.full) * op_max_frames, HEAPSTAT_CALLSTACK);
    }
    if (loc != NULL) {
        if (loc->type == APP_LOC_SYSCALL) {
            /* For syscalls, we use index 0 and store the syscall # in modoffs */
            /* Store the syscall aux identifier in the addr field (PR 525269).
             * It's supposed to be a string literal and so we can clone it
             * and compare it by just using its address.
             */
            if (pcs->is_packed) {
                pcs->frames.packed[0].loc.syscall_aux = loc->u.syscall.syscall_aux;
                pcs->frames.packed[0].modname_idx = 0;
                ASSERT(loc->u.syscall.sysnum < MAX_MODOFFS_STORED,
                       "sysnum too large to fit in packed_frame_t.modoffs");
                pcs->frames.packed[0].modoffs = loc->u.syscall.sysnum;
            } else {
                pcs->frames.full[0].loc.syscall_aux = loc->u.syscall.syscall_aux;
                pcs->frames.full[0].modname = (modname_info_t *) &MODNAME_INFO_SYSCALL;
                pcs->frames.full[0].modoffs = loc->u.syscall.sysnum;
            }
            pcs->num_frames++;
        } else {
            app_pc pc = loc_to_pc(loc);
            ASSERT(loc->type == APP_LOC_PC, "unknown loc type");
            address_to_frame(NULL, pcs, pc, NULL, false, false, 0);
        }
        num_frames_printed = 1;
    }
    print_callstack(NULL, 0, NULL, mc, false, pcs, num_frames_printed, false);
    if (pcs->is_packed) {
        packed_frame_t *frames_out;
        sz_out = sizeof(*pcs->frames.packed) * pcs->num_frames;
        if (sz_out == 0)
            frames_out = NULL;
        else {
            frames_out = (packed_frame_t *) global_alloc(sz_out, HEAPSTAT_CALLSTACK);
            memcpy(frames_out, pcs->frames.packed, sz_out);
        }
        global_free(pcs->frames.packed, sizeof(*pcs->frames.packed) * op_max_frames,
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
        global_free(pcs->frames.full, sizeof(*pcs->frames.full) * op_max_frames,
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
        if (info == &MODNAME_INFO_SYSCALL)
            return false;
        offs = pcs->frames.full[frame].modoffs;
    } else {
        if (pcs->frames.packed[frame].modname_idx == 0)
            return false;
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

        /* sysnum is stored in modoffs field */
        frame->loc.u.syscall.sysnum =
            (pcs->is_packed ? pcs->frames.packed[idx].modoffs :
             pcs->frames.full[idx].modoffs);
        frame->loc.u.syscall.syscall_aux = PCS_FRAME_LOC(pcs, idx).syscall_aux;

        /* we print the string now so we can compare to suppressions.
         * we use func since modname is too short in windows.
         */
        BUFPRINT(frame->func, MAX_FUNC_LEN, sofar, len, "system call ");
        if (op_get_syscall_name != NULL)
            name = (*op_get_syscall_name)(frame->loc.u.syscall.sysnum);
        /* strip syscall # if have name, to be independent of windows ver */
        ASSERT(name != NULL, "syscall name should not be NULL");
        if (name[0] != '\0' && name[0] != '<' /* "<unknown>" */) {
            BUFPRINT(frame->func, MAX_FUNC_LEN, sofar, len, "%s", name);
        } else {
            BUFPRINT(frame->func, MAX_FUNC_LEN, sofar, len, "%d",
                     frame->loc.u.syscall.sysnum);
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
    ASSERT(pcs != NULL, "invalid args");
    for (i = 0; i < pcs->num_frames && (num_frames == 0 || i < num_frames); i++) {
        packed_frame_to_symbolized(pcs, &frame, i);
        print_frame(&frame, buf, bufsz, sofar, false, 0, 0, prefix);
        if (op_truncate_below != NULL &&
            text_matches_any_pattern((const char *)frame.func, op_truncate_below, false))
            break;
    }
}

void
packed_callstack_to_symbolized(packed_callstack_t *pcs IN,
                               symbolized_callstack_t *scs OUT)
{
    uint i;
    scs->num_frames = pcs->num_frames;
    scs->num_frames_allocated = pcs->num_frames;
    scs->frames = (symbolized_frame_t *)
        global_alloc(sizeof(*scs->frames) * scs->num_frames, HEAPSTAT_CALLSTACK);
    ASSERT(pcs != NULL, "invalid args");
    for (i = 0; i < pcs->num_frames; i++) {
        packed_frame_to_symbolized(pcs, &scs->frames[i], i);
        /* we truncate for real and not just on printing (i#700) */
        if (op_truncate_below != NULL &&
            text_matches_any_pattern((const char *)scs->frames[i].func,
                                     op_truncate_below, false)) {
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
    per_thread_t *pt = (per_thread_t *)
        ((drcontext == NULL) ? NULL : dr_get_tls_field(drcontext));
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

void
packed_callstack_add_ref(packed_callstack_t *pcs)
{
    ASSERT(pcs != NULL, "invalid args");
    ATOMIC_INC32(pcs->refcount);
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
    return dst;
}

uint
packed_callstack_hash(packed_callstack_t *pcs)
{
    uint hash = 0;
    uint i;
    for (i = 0; i < pcs->num_frames; i++) {
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
    if ((pcs1->is_packed && pcs2->is_packed) ||
        (!pcs1->is_packed && !pcs2->is_packed)) {
        return (memcmp(PCS_FRAMES(pcs1), PCS_FRAMES(pcs2),
                       PCS_FRAME_SZ(pcs1)*pcs1->num_frames) == 0);
    }
    /* one is packed, the other is not, so we have to walk the frames */
    for (i = 0; i < pcs1->num_frames; i++) {
        modname_info_t *info1 = NULL, *info2 = NULL;
        size_t offs1 = 0, offs2 = 0;
        bool nonsys1, nonsys2;
        if (PCS_FRAME_LOC(pcs1, i).addr != PCS_FRAME_LOC(pcs2, i).addr ||
            PCS_FRAME_LOC(pcs1, i).syscall_aux != PCS_FRAME_LOC(pcs2, i).syscall_aux)
            return false;
        nonsys1 = packed_callstack_frame_modinfo(pcs1, i, &info1, &offs1);
        nonsys2 = packed_callstack_frame_modinfo(pcs2, i, &info2, &offs2);
        if ((nonsys1 && !nonsys2) || (!nonsys1 && nonsys2))
            return false;
        if (info1 != info2)
            return false;
        if (offs1 != offs2)
            return false;
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


/***************************************************************************
 * SYMBOLIZED CALLSTACKS
 */

void
symbolized_callstack_print(const symbolized_callstack_t *scs IN,
                           char *buf, size_t bufsz, size_t *sofar, const char *prefix)
{
    uint i;
    size_t max_flen = 0;
    ASSERT(scs != NULL, "invalid args");
    if (TEST(PRINT_ALIGN_COLUMNS, op_print_flags)) {
        for (i = 0; i < scs->num_frames; i++) {
            size_t flen = strlen(scs->frames[i].func);
            if (flen > max_flen)
                max_flen = flen;
        }
    }
    for (i = 0; i < scs->num_frames; i++) {
        print_frame(&scs->frames[i], buf, bufsz, sofar, false, 0, max_flen, prefix);
        /* op_truncate_below should have been done when symbolized cstack created.
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

char *
symbolized_callstack_frame_func(const symbolized_callstack_t *scs, uint frame)
{
    ASSERT(scs != NULL, "invalid args");
    if (scs->num_frames <= frame)
        return NULL;
    return scs->frames[frame].func;
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
    static bool has_noname = false;
    size_t sz;
    name = dr_module_preferred_name(info);
    if (name == NULL) {
        name = "";
        /* if multiple w/o names, we lose data */
        ASSERT(!has_noname, "multiple modules w/o name: may lose data");
        has_noname = true;
    }
    LOG(1, "module load event: \"%s\" "PFX"-"PFX" %s\n",
        name, info->start, info->end, info->full_path);

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
        /* we cache this value to avoid re-matching on every frame */
        name_info->hide_modname =
            (op_modname_hide != NULL &&
             text_matches_any_pattern(name_info->name, op_modname_hide, IGNORE_FILE_CASE));
#ifdef DEBUG
        name_info->warned_no_syms = false;
#endif
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
    hashtable_unlock(&modname_table);
    return name_info;
}

static void
modname_info_free(void *p)
{
    modname_info_t *info = (modname_info_t *) p;
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
    ASSERT(node == NULL, "new module overlaps w/ existing");
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

/* For storing binary callstacks we need to store module names in a shared
 * location to save space and handle unloaded and reloaded modules.
 */
void
callstack_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    modname_info_t *name_info = add_new_module(drcontext, info);
    
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
syscall_to_loc(app_loc_t *loc, uint sysnum, const char *aux)
{
    ASSERT(loc != NULL, "invalid param");
    loc->type = APP_LOC_SYSCALL;
    loc->u.syscall.sysnum = sysnum;
    loc->u.syscall.syscall_aux = aux;
}

/* loc_to_pc() and loc_to_print() must be defined by the tool-specific code */
