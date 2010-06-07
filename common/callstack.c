/* **********************************************************
 * Copyright (c) 2008-2009 VMware, Inc.  All rights reserved.
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

/* global options */
static uint op_max_frames;
static uint op_stack_swap_threshold;
static uint op_fp_flags; /* set of flags */
static size_t op_fp_scan_sz;
/* optional: only needed if packed_callstack_record is passed a pc<64K */
static const char * (*op_get_syscall_name)(uint);

/* PR 454536: to avoid races we read a page all at once */
static void *page_buf_lock;
static char page_buf[PAGE_SIZE];

static const char *end_marker = IF_DRSYMS_ELSE("", "\terror end\n");

#ifdef WINDOWS
# define FP_PREFIX ""
# define LINE_PREFIX "    "
#else
# define FP_PREFIX "\t"
#endif

/****************************************************************************
 * Binary callstacks for storing callstacks of allocation sites.
 * Print-format callstacks take up too much room (PR 424179).
 * We do NOT store the frame pointers, to save space.  They are
 * rarely needed in allocation site analysis.
 */
typedef struct _packed_frame_t {
    union {
        app_pc addr;
        /* syscalls store a string identifying param (PR 525269) */
        const char *syscall_aux;
    } loc;
    /* Modules can move around, with the same module being at two
     * different locations, so we must store both the name (which is a
     * pointer into a never-removed-from module name hashtable) and
     * the offset.  We pack further using an array of names so we can
     * store an index here that is a single byte (not going to see >
     * 256 libraries) that shares a dword with the module offset. That 
     * limits the offset to 16MB.  For modules larger than that, we have
     * extra entries that are adjacent in the modname array.  The
     * hashtable holds the index of the first such entry.
     */
    uint modoffs : 24;
    /* For syscalls, we use index 0 and store the syscall # in modoffs */
    uint modname_idx : 8;
} packed_frame_t;

#define MAX_MODOFFS_STORED (0x00ffffff)

struct _packed_callstack_t {
    /* share callstacks to save space (PR 465174) */
    uint refcount;
    /* Variable-length to save space */
    uint num_frames;
    packed_frame_t *frames;
};

/* Array mapping index to name 
 * Hashtable lock synchronizes access
 */
#define MAX_MODNAMES_STORED UCHAR_MAX
typedef struct _modname_info_t {
    /* Both strings are strdup-ed */
    const char *name; /* "preferred" name */
    const char *path; /* name with full path */
} modname_info_t;
static modname_info_t modname_array[MAX_MODNAMES_STORED];
/* Index 0 is reserved to indicate a system call as the top frame of a callstack */
static uint modname_array_end = 1;

/* Hashtable for mapping name to index */
#define MODNAME_TABLE_HASH_BITS 8
static hashtable_t modname_table;

/* PR 473640: our own module region tree */
static rb_tree_t *module_tree;
static void *modtree_lock;
/* We maintain the modules w/ the lowest and highest addresses for quick
 * queries of stack addrs, etc.
 */
static app_pc modtree_min_start;
static app_pc modtree_max_end;

static bool
module_lookup(byte *pc, app_pc *start OUT, size_t *size OUT, int *name_idx OUT);

static bool
is_in_module(byte *pc);

/***************************************************************************/

size_t
max_callstack_size(void)
{
    static const char *max_line = "\tfp=0x12345678 parent=0x12345678 0x12345678 <>"NL;
    size_t max_addr_sym_len = MAX_ADDR_LEN;
    size_t additional_len = strlen(end_marker);
#ifdef USE_DRSYMS
    max_addr_sym_len += 1/*' '*/ + MAX_SYMBOL_LEN + 1/*\n*/ +
        strlen(LINE_PREFIX) + MAX_FILE_LINE_LEN;
    additional_len = 0; /* no end marker */
#endif
    return ((op_max_frames+1)/*for the ... line: over-estimate*/
            *(strlen(max_line)+max_addr_sym_len)) + additional_len + 1/*null*/;
}

void
callstack_init(uint callstack_max_frames, uint stack_swap_threshold, uint flags,
               size_t fp_scan_sz, const char *(*get_syscall_name)(uint))
{
    op_max_frames = callstack_max_frames;
    op_stack_swap_threshold = stack_swap_threshold;
    op_fp_flags = flags;
    op_fp_scan_sz = fp_scan_sz;
    op_get_syscall_name = get_syscall_name;
    page_buf_lock = dr_mutex_create();
    hashtable_init_ex(&modname_table, MODNAME_TABLE_HASH_BITS, HASH_STRING_NOCASE,
                      false/*!str_dup*/, false/*!synch*/, NULL, NULL, NULL);
    modtree_lock = dr_mutex_create();
    module_tree = rb_tree_create(NULL);

#ifdef USE_DRSYMS
    if (drsym_init(NULL) != DRSYM_SUCCESS) {
        LOG(1, "WARNING: unable to initialize symbol translation\n");
    }
#endif
}

void
callstack_exit(void)
{
    int i;
    const char *prev_name = NULL;

    dr_mutex_destroy(page_buf_lock);

    hashtable_delete(&modname_table);
    for (i = 0; i < modname_array_end; i++) {
        /* contiguous entries can share the name string if for a large module */
        if (modname_array[i].name != prev_name) {
            if (modname_array[i].name != NULL) {
                global_free((void *)modname_array[i].name,
                            strlen(modname_array[i].name) + 1, HEAPSTAT_HASHTABLE);
            }
            if (modname_array[i].path != NULL) {
                global_free((void *)modname_array[i].path,
                            strlen(modname_array[i].path) + 1, HEAPSTAT_HASHTABLE);
            }
            prev_name = modname_array[i].name;
        }
    }

    dr_mutex_lock(modtree_lock);
    rb_tree_destroy(module_tree);
    dr_mutex_unlock(modtree_lock);
    dr_mutex_destroy(modtree_lock);

#ifdef USE_DRSYMS
    if (drsym_exit() != DRSYM_SUCCESS) {
        LOG(1, "WARNING: error cleaning up symbol library\n");
    }
#endif
}

void
callstack_thread_init(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    /* PR 456181: we need our error reports to use a single atomic write.
     * We use a thread-private buffer to avoid using stack space or locks.
     */
    pt->errbufsz = MAX_ERROR_INITIAL_LINES + max_callstack_size();
    pt->errbuf = (char *) thread_alloc(drcontext, pt->errbufsz, HEAPSTAT_CALLSTACK);
}

void
callstack_thread_exit(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    thread_free(drcontext, (void *) pt->errbuf, pt->errbufsz, HEAPSTAT_CALLSTACK);
}

/***************************************************************************/

#ifdef USE_DRSYMS
/* Symbol lookup: i#44/PR 243532
 * FIXME: provide options for formatting?
 * - whether to include function name and/or line #
 * - whether to include offs within func and/or within line
 * - whether to use addr2line format "file:line#" or windbg format "file(line#)"
 */
# define MAX_SYM_RESULT (2 * (MAX_SYMBOL_LEN + MAX_FILE_LINE_LEN))

static void
print_func_and_line(char *buf, size_t bufsz, size_t *sofar,
                    const char *modpath, const char *modname, size_t modoffs)
{
    ssize_t len = 0;
    drsym_error_t symres;
    drsym_info_t *sym;
    char sbuf[sizeof(*sym) + MAX_SYM_RESULT];
    ASSERT(modname != NULL, "caller should have replaced with empty string");
    sym = (drsym_info_t *) sbuf;
    sym->struct_size = sizeof(*sym);
    sym->name_size = MAX_SYM_RESULT;
    symres = drsym_lookup_address(modpath, modoffs, sym);
    if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
        /* I like have +0x%x to show offs within func but we'll match addr2line */
        BUFPRINT(buf, bufsz, *sofar, len, " %s!%s"NL, modname, sym->name);
        LOG(4, "symbol %s+"PIFX" => %s+"PIFX" ("PIFX"-"PIFX")\n",
            modpath, modoffs, sym->name, modoffs - sym->start_offs,
            sym->start_offs, sym->end_offs);
        if (symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
            BUFPRINT(buf, bufsz, *sofar, len, LINE_PREFIX"??:0"NL);
        } else {
            /* windbg format is file(line#) but we use addr2line format file:line# */
            /* I like +0x%x sym->line_offs but we'll match addr2line */
            BUFPRINT(buf, bufsz, *sofar, len,
                     LINE_PREFIX"%s:%-"STRINGIFY(MAX_LINENO_DIGITS) UINT64_FORMAT_CODE""NL,
                     sym->file, sym->line);
        }
    } else {
        LOG(1, "WARNING: unable to load symbols for %s\n", modpath);
        BUFPRINT(buf, bufsz, *sofar, len, " %s!?"NL LINE_PREFIX"??:0"NL, modname);
    }
}
#endif

/* Returns whether a new frame was added (won't be if skip_non_module and pc
 * is not in a module)
 * sub1_sym is for PR 543863: subtract one from retaddrs in callstacks
 */
bool
print_address(char *buf, size_t bufsz, size_t *sofar,
              app_pc pc, module_data_t *mod_in /*optional*/, bool modoffs_only,
              bool skip_non_module, packed_callstack_t *pcs,
              bool sub1_sym)
{
    ssize_t len = 0;
    int idx;
    app_pc mod_start;
    ASSERT((buf != NULL && sofar != NULL && pcs == NULL) ||
           (buf == NULL && sofar == NULL && pcs != NULL),
           "print_callstack: can't pass buf and pcs");
    
    if (module_lookup(pc, &mod_start, NULL, &idx)) {
        const char *modname = (idx >= 0) ? modname_array[idx].name : NULL;
        ASSERT(pc >= mod_start, "internal pc-not-in-module error");
        ASSERT(idx >= 0, "module should have index");
        ASSERT(mod_in == NULL || mod_in->start == mod_start, "module mismatch");
        if (pcs != NULL) {
            size_t sz = (pc - mod_start);
            pcs->frames[pcs->num_frames].loc.addr = pc;
            if (idx < 0) { /* handling missing module in release build */
                /* We already asserted above */
                if (sz > MAX_MODOFFS_STORED) /* We lose data here */
                    pcs->frames[pcs->num_frames].modoffs = MAX_MODOFFS_STORED;
                else
                    pcs->frames[pcs->num_frames].modoffs = sz;
                pcs->frames[pcs->num_frames].modname_idx = MAX_MODNAMES_STORED;
            } else {
                while (sz > MAX_MODOFFS_STORED) {
                    sz -= MAX_MODOFFS_STORED;
                    if (idx + 1 == MAX_MODNAMES_STORED)
                        break;
                    idx++;
                    ASSERT(idx < modname_array_end, "large-modname entries truncated");
                    ASSERT(strcmp(modname_array[idx-1].name, modname_array[idx].name) == 0,
                           "not enough large-modname entries");
                }
                pcs->frames[pcs->num_frames].modoffs = sz;
                pcs->frames[pcs->num_frames].modname_idx = idx;
            }
            pcs->num_frames++;
        } else if (modoffs_only) {
            BUFPRINT(buf, bufsz, *sofar, len,
                    "<%." STRINGIFY(MAX_MODULE_LEN) "s+"PIFX">"NL,
                    modname == NULL ? "" : modname, pc - mod_start);
#ifdef USE_DRSYMS
            IF_WINDOWS(BUFPRINT(buf, bufsz, *sofar, len, LINE_PREFIX"??:0"NL);)
#endif
        } else {
            BUFPRINT(buf, bufsz, *sofar, len,
                     PFX" <%." STRINGIFY(MAX_MODULE_LEN) "s+"PIFX">",
                     pc, modname == NULL ? "" : modname, pc - mod_start);
#ifdef USE_DRSYMS
            print_func_and_line(buf, bufsz, sofar, modname_array[idx].path,
                                modname_array[idx].name,
                                pc - mod_start - (sub1_sym ? 1 : 0));
#else
            BUFPRINT(buf, bufsz, *sofar, len, ""NL);
#endif
        }
        return true;
    } else if (!skip_non_module) {
        if (pcs != NULL) {
            pcs->frames[pcs->num_frames].loc.addr = pc;
            pcs->frames[pcs->num_frames].modoffs = MAX_MODOFFS_STORED;
            pcs->frames[pcs->num_frames].modname_idx = MAX_MODNAMES_STORED;
            pcs->num_frames++;
        } else if (modoffs_only)
            BUFPRINT(buf, bufsz, *sofar, len, "<not in a module>"NL);
        else {
            BUFPRINT(buf, bufsz, *sofar, len, PFX" <not in a module>"NL, pc);
#ifdef USE_DRSYMS
            IF_WINDOWS(BUFPRINT(buf, bufsz, *sofar, len, LINE_PREFIX"??:0"NL);)
#endif
        }
        return true;
    }
    return false;
}

/* caller must hold page_buf_lock */
static app_pc
find_next_fp(per_thread_t *pt, app_pc fp, bool top_frame, app_pc *retaddr/*OUT*/)
{
    /* Heuristic: scan stack for fp + retaddr */
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
        fp >= pt->stack_lowest_frame &&
        (fp - pt->stack_lowest_frame) < op_stack_swap_threshold) {
        LOG(4, "find_next_fp: aborting b/c beyond stack_lowest_frame\n");
        return NULL;
    }
    /* PR 454536: dr_memory_is_readable() is racy so we use a safe_read().
     * On Windows safe_read() costs 1 system call: perhaps DR should
     * use try/except there like on Linux?
     * Should we also store the stack bounds and then we know when
     * to stop instead of incurring a fault on every callstack?
     */
    if (safe_read((app_pc)ALIGN_BACKWARD(fp, PAGE_SIZE), PAGE_SIZE, page_buf)) {
        app_pc buf_pg = (app_pc) ALIGN_BACKWARD(fp, PAGE_SIZE);
        app_pc tos = fp;
        app_pc sp;
        app_pc slot0, slot1;
        bool match, match_next_frame;
        /* Scan one page worth and look for potential fp,retaddr pair */
        for (sp = tos; sp - tos < op_fp_scan_sz; sp+=sizeof(app_pc)) {
            match = false;
            match_next_frame = false;
            if (retaddr != NULL)
                *retaddr = NULL;
            ASSERT((app_pc)ALIGN_BACKWARD(sp, PAGE_SIZE) == buf_pg, "buf error");
            slot0 = *((app_pc*)&page_buf[sp - buf_pg]);
            /* Retrieve next page if slot1 will touch it */
            if ((app_pc)ALIGN_BACKWARD(sp + sizeof(app_pc), PAGE_SIZE) != buf_pg) {
                buf_pg = (app_pc) ALIGN_BACKWARD(sp + sizeof(app_pc), PAGE_SIZE);
                if (!safe_read(buf_pg, PAGE_SIZE, page_buf))
                    break;
            }
            if (slot0 > tos && slot0 - tos < op_stack_swap_threshold) {
                slot1 = *((app_pc*)&page_buf[(sp + sizeof(app_pc)) - buf_pg]);
                /* We should only consider retaddr in code section but
                 * let's keep it simple for now.
                 * We ignore DGC: perhaps a dr_is_executable_memory() could
                 * be used instead of checking modules.
                 * OPT: keep all modules in hashtable for quicker check
                 * that doesn't require alloc+free of heap */
                if (is_in_module(slot1))
                    match = true;
#ifdef WINDOWS
                else if (top_frame) {
                    /* PR 475715: msvcr80!malloc pushes ebx and then ebp!  It then
                     * uses ebp as scratch, so we end up here for the top frame
                     * of a leak callstack.
                     */
                    slot1 = *((app_pc*)&page_buf[(sp + 2*sizeof(app_pc)) - buf_pg]);
                    if (is_in_module(slot1)) {
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
                app_pc parent_ret_ptr = slot0 + sizeof(app_pc);
                app_pc parent_ret;
                if (TEST(FP_SEARCH_MATCH_SINGLE_FRAME, op_fp_flags) && !match_next_frame)
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
                if (parent_ret != NULL && is_in_module(parent_ret)) {
                    return sp;
                }
            }
        }
    }
    return NULL;
}

void
print_callstack(char *buf, size_t bufsz, size_t *sofar, dr_mcontext_t *mc, 
                bool modoffs_only, bool print_fps,
                packed_callstack_t *pcs, int num_frames_printed)
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

    ASSERT(num == 0 || num == 1, "only 1 frame can already be printed");
    ASSERT((buf != NULL && sofar != NULL && pcs == NULL) ||
           (buf == NULL && sofar == NULL && pcs != NULL),
           "print_callstack: can't pass buf and pcs");

    /* lock the buffer used by find_next_fp */
    if (buf != NULL)
        dr_mutex_lock(page_buf_lock);

    if (mc != NULL && mc->esp != 0 &&
        (mc->ebp < mc->esp || mc->ebp - mc->esp > op_stack_swap_threshold ||
         !safe_read((byte *)mc->ebp, sizeof(appdata), &appdata))) {
        /* We may start out in the middle of a frameless function that is
         * using ebp for other purposes.  Heuristic: scan stack for fp + retaddr.
         */
        LOG(4, "find_next_fp b/c starting w/ non-fp ebp\n");
        pc = (ptr_uint_t *) find_next_fp(pt, (app_pc)mc->esp, true/*top frame*/,
                                         &custom_retaddr);
    }
    while (pc != NULL) {
        if (!safe_read((byte *)pc, sizeof(appdata), &appdata)) {
            LOG(4, "truncating callstack: can't read "PFX"\n", pc);
            break;
        }
        if (custom_retaddr != NULL) {
            /* Support frames where there's a gap between ebp and retaddr (PR 475715) */
            appdata.retaddr = custom_retaddr;
            custom_retaddr = NULL;
        }
        if (buf != NULL && !modoffs_only) {
            prev_sofar = *sofar;
            BUFPRINT(buf, bufsz, *sofar, len, FP_PREFIX);
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
        if (print_address(buf, bufsz, sofar, appdata.retaddr, NULL, modoffs_only,
                          !TEST(FP_SHOW_NON_MODULE_FRAMES, op_fp_flags), pcs, true)) {
            num++;
        } else if (buf != NULL && !modoffs_only) {
            /* undo the fp= print */
            *sofar = prev_sofar;
        }
        /* pcs->num_frames could be larger if frames were printed before this routine */
        if (num >= op_max_frames || (pcs != NULL && pcs->num_frames >= op_max_frames)) {
            if (buf != NULL && !modoffs_only)
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
                pc = (ptr_uint_t *) find_next_fp(pt, (app_pc)pc, false/*!top*/, NULL);
            } else {
                LOG(4, "truncating callstack: zero frame ptr\n");
                break;
            }
        } else if (appdata.next_fp < (app_pc)pc ||
                   (appdata.next_fp - (app_pc)pc) >= op_stack_swap_threshold) {
            if (!TEST(FP_STOP_AT_BAD_NONZERO_FRAME, op_fp_flags)) {
                LOG(4, "find_next_fp b/c hit bad non-zero fp\n");
                pc = (ptr_uint_t *) find_next_fp(pt, (app_pc)pc, false/*!top*/, NULL);
            } else {
                LOG(4, "truncating callstack: bad frame ptr "PFX"\n", appdata.next_fp);
                break;
            }
        } else
            pc = (ptr_uint_t *) appdata.next_fp;
        if (pc == NULL)
            LOG(4, "truncating callstack: can't find next fp\n");
    }
    if (num == 0 && buf != NULL && print_fps) {
        BUFPRINT(buf, bufsz, *sofar, len,
                 FP_PREFIX"<call stack frame ptr "PFX" unreadable>"NL, pc);
    }
    if (pt != NULL && lowest_frame > pt->stack_lowest_frame)
        pt->stack_lowest_frame = lowest_frame;

    if (buf != NULL && !modoffs_only)
        BUFPRINT(buf, bufsz, *sofar, len, "%s", end_marker);
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
        ASSERT(res == sz, "dr_write_file partial write");
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
    per_thread_t *pt = (per_thread_t *)
        ((drcontext == NULL) ? NULL : dr_get_tls_field(drcontext));
    /* mc and pc will be NULL for startup heap iter */
    if (pt == NULL) {
        LOG(1, "Can't report callstack as pt is NULL\n");
        return;
    }

    print_address(pt->errbuf, pt->errbufsz, &sofar, pc, NULL, false/*print addrs*/,
                  false/*print non-module addr*/, NULL, false);
    print_callstack(pt->errbuf, pt->errbufsz, &sofar, mc, false/*print addrs*/,
                    true/*incl fp*/, NULL, 1);
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
    packed_frame_t *frames_out;
    ASSERT(pcs_out != NULL, "invalid args");
    memset(pcs, 0, sizeof(*pcs));
    pcs->refcount = 1;
    pcs->frames = (packed_frame_t *)
        global_alloc(sizeof(*pcs->frames) * op_max_frames,
                     HEAPSTAT_CALLSTACK);
    if (loc != NULL) {
        if (loc->type == APP_LOC_SYSCALL) {
            /* For syscalls, we use index 0 and store the syscall # in modoffs */
            /* Store the syscall aux identifier in the addr field (PR 525269).
             * It's supposed to be a string literal and so we can clone it
             * and compare it by just using its address.
             */
            pcs->frames[0].loc.syscall_aux = loc->u.syscall.syscall_aux;
            pcs->frames[0].modname_idx = 0;
            pcs->frames[0].modoffs = loc->u.syscall.sysnum;
            pcs->num_frames++;
        } else {
            app_pc pc = loc_to_pc(loc);
            ASSERT(loc->type == APP_LOC_PC, "unknown loc type");
            print_address(NULL, 0, NULL, pc, NULL, false, false, pcs, false);
        }
        num_frames_printed = 1;
    }
    print_callstack(NULL, 0, NULL, mc, false, false, pcs, num_frames_printed);
    sz_out = sizeof(*pcs->frames) * pcs->num_frames;
    if (sz_out == 0)
        frames_out = NULL;
    else {
        frames_out = (packed_frame_t *) global_alloc(sz_out, HEAPSTAT_CALLSTACK);
        memcpy(frames_out, pcs->frames, sz_out);
    }
    global_free(pcs->frames, sizeof(*pcs->frames) * op_max_frames,
                HEAPSTAT_CALLSTACK);
    pcs->frames = frames_out;
    *pcs_out = pcs;
}

/* 0 for num_frames means to print them all prefixed with tabs and
 * absolute addresses, and to print an end marker.
 * otherwise num_frames indicates the number of frames to be printed.
 */
void
packed_callstack_print(packed_callstack_t *pcs, uint num_frames,
                       char *buf, size_t bufsz, size_t *sofar)
{
    uint i;
    size_t len;
    ASSERT(pcs != NULL, "invalid args");
    for (i = 0; i < pcs->num_frames && (num_frames == 0 || i < num_frames); i++) {
        /* FIXME: share code w/ print_address() */
        if (pcs->frames[i].modname_idx == 0) {
            /* modname_idx==0 is the code for a system call */
            const char *name = "<unknown>";
            BUFPRINT(buf, bufsz, *sofar, len, "%ssystem call ",
                     (num_frames == 0) ? FP_PREFIX : "");
            if (op_get_syscall_name != NULL)
                name = (*op_get_syscall_name)(pcs->frames[i].modoffs);
            /* strip syscall # if have name, to be independent of windows ver */
            ASSERT(name != NULL, "syscall name should not be NULL");
            if (name[0] != '\0' && name[0] != '<') {
                BUFPRINT(buf, bufsz, *sofar, len, "%s", name);
            } else {
                BUFPRINT(buf, bufsz, *sofar, len, "%d=%s",
                         pcs->frames[i].modoffs, name);
            }
            if (pcs->frames[i].loc.syscall_aux != NULL) {
                /* syscall aux identifier (PR 525269) */
                BUFPRINT(buf, bufsz, *sofar, len, " %s",
                         pcs->frames[i].loc.syscall_aux);
            }
            BUFPRINT(buf, bufsz, *sofar, len, ""NL);
        } else {
            /* We assume no valid address will have offset 0 */
            if (num_frames == 0) {
                BUFPRINT(buf, bufsz, *sofar, len, FP_PREFIX PFX" ",
                         pcs->frames[i].loc.addr);
            }
            if (pcs->frames[i].modoffs < MAX_MODOFFS_STORED) {
                /* If module is larger than 16M, we need to adjust offset.
                 * The hashtable holds the first index.
                 */
                size_t offs = pcs->frames[i].modoffs;
                int start_idx;
                int idx = pcs->frames[i].modname_idx;
                if (idx < MAX_MODNAMES_STORED) {
                    /* If we hit the max we just don't have info for subsequent modules */
                    hashtable_lock(&modname_table);
                    start_idx = (int) hashtable_lookup(&modname_table,
                                                       (void*)modname_array[idx].name);
                    hashtable_unlock(&modname_table);
                    ASSERT(start_idx != 0, "module in array must be in table");
                    start_idx--; /* table stores +1 */
                    if (start_idx < idx)
                        offs += (idx - start_idx) * MAX_MODOFFS_STORED;
                }
                BUFPRINT(buf, bufsz, *sofar, len,
                         "<%." STRINGIFY(MAX_MODULE_LEN) "s+"PIFX">",
                         idx == MAX_MODNAMES_STORED ? "<unknown module>" :
                         modname_array[idx].name, offs);
#ifdef USE_DRSYMS
                /* PR 543863: subtract one from retaddrs in callstacks so the line#
                 * is for the call and not for the next source code line, but only
                 * for symbol lookup so we still display a valid instr addr.
                 * We assume first frame is not a retaddr.
                 */
                print_func_and_line(buf, bufsz, sofar, modname_array[idx].path,
                                    modname_array[idx].name, (i == 0) ? offs : offs-1);
#else
                BUFPRINT(buf, bufsz, *sofar, len, ""NL);
#endif
            } else {
                BUFPRINT(buf, bufsz, *sofar, len, "<not in a module>"NL);
#ifdef USE_DRSYMS
                IF_WINDOWS(BUFPRINT(buf, bufsz, *sofar, len, LINE_PREFIX"??:0"NL);)
#endif
            }
        }
    }
    if (num_frames == 0)
        BUFPRINT(buf, bufsz, *sofar, len, "%s", end_marker);
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
    packed_callstack_print(pcs, 0, buf, bufsz, &sofar);
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
        if (pcs->frames != NULL) {
            global_free(pcs->frames, sizeof(*pcs->frames)*pcs->num_frames,
                        HEAPSTAT_CALLSTACK);
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
    dst->frames = (packed_frame_t *)
        global_alloc(sizeof(*dst->frames) * src->num_frames,
                     HEAPSTAT_CALLSTACK);
    memcpy(dst->frames, src->frames, sizeof(*dst->frames) * src->num_frames);
    return dst;
}

uint
packed_callstack_hash(packed_callstack_t *pcs)
{
    uint hash = 0;
    uint i;
    for (i = 0; i < pcs->num_frames; i++) {
        hash ^= (ptr_uint_t) pcs->frames[i].loc.addr;
    }
    return hash;
}

bool
packed_callstack_cmp(packed_callstack_t *pcs1, packed_callstack_t *pcs2)
{
    if (pcs1->frames == NULL) {
        if (pcs2->frames != NULL)
            return false;
        return true;
    }
    if (pcs2->frames == NULL)
        return false;
    return (pcs1->num_frames == pcs2->num_frames &&
            memcmp(pcs1->frames, pcs2->frames,
                   sizeof(*pcs1->frames)*pcs1->num_frames) == 0);
}

void
packed_callstack_md5(packed_callstack_t *pcs, byte digest[MD5_RAW_BYTES])
{
    if (pcs->num_frames == 0) {
        memset(digest, 0, sizeof(digest[0])*MD5_RAW_BYTES);
    } else {
        get_md5_for_region((const byte *)pcs->frames,
                           sizeof(*pcs->frames)*pcs->num_frames, digest);
    }
}

void
packed_callstack_crc32(packed_callstack_t *pcs, uint crc[2])
{
    crc32_whole_and_half((const char *)pcs->frames,
                         sizeof(*pcs->frames)*pcs->num_frames, crc);
}

/* For storing binary callstacks we need to store module names in a shared
 * location to save space and handle unloaded and reloaded modules.
 * Returns the index into modname_array, or -1 on error.
 */
static int
add_new_module(void *drcontext, const module_data_t *info)
{
    const char *name;
    static bool has_noname = false;
    char *dup_name;
    char *dup_path;
    size_t sz;
    int res = 0;
    name = dr_module_preferred_name(info);
    if (name == NULL) {
        name = "";
        /* if multiple w/o names, we lose data */
#ifdef VMX86_SERVER
        /* PR 467199: we hit this and know we need to fix it => just warning */
        if (has_noname)
            LOG(0, "ERROR: multiple modules w/o name: may lose data\n");
#else
        ASSERT(!has_noname, "multiple modules w/o name: may lose data");
#endif
        has_noname = true;
    }
    LOG(1, "module load event: \"%s\" "PFX"-"PFX"\n", name, info->start, info->end);

    dup_name = drmem_strdup(name, HEAPSTAT_HASHTABLE);
    dup_path = drmem_strdup(info->full_path, HEAPSTAT_HASHTABLE);

    hashtable_lock(&modname_table);
    res = (int) hashtable_lookup(&modname_table, (void*)name);
    if (res == 0) {
        /* We need an entry for every 16M of module size */
        sz = info->end - info->start;
        while (true) {
            if (modname_array_end >= MAX_MODNAMES_STORED) {
                LOG(0, "ERROR: hit max module count: won't store further names\n");
                ASSERT(false, "hit max module count");
                /* For dup entries we'll just get offset wrong; for first entry
                 * we'll miss in table and print out <unknown module>
                 */
                hashtable_unlock(&modname_table);
                return -1;
            }
            LOG(2, "modname_array %d = %s\n", modname_array_end, name);
            modname_array[modname_array_end].name = dup_name;
            modname_array[modname_array_end].path = dup_path;
            modname_array_end++;
            /* Since we have to use 0 as "not found" in hashtable we store index+1 */
            hashtable_add(&modname_table, (void*)dup_name, (void*)(modname_array_end));
            if (res == 0) /* Return the first index */
                res = modname_array_end;
            if (sz <= MAX_MODOFFS_STORED)
                break;
            sz -= MAX_MODOFFS_STORED;
        }
    }
    hashtable_unlock(&modname_table);
    return res - 1; /* subtract the +1 used in the table */
}

/* Caller must hold modtree_lock */
static void
callstack_module_add_region(app_pc start, app_pc end, int idx)
{
    IF_DEBUG(rb_node_t *node = )
        rb_insert(module_tree, start, (end - start), (void *)idx);
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
    int idx = add_new_module(drcontext, info);
    
    /* PR 473640: maintain our own module tree */
    dr_mutex_lock(modtree_lock);
    ASSERT(info->end > info->start, "invalid mod bounds");
#ifdef WINDOWS
    callstack_module_add_region(info->start, info->end, idx);
#else
    if (info->contiguous)
        callstack_module_add_region(info->start, info->end, idx);
    else {
        /* Add the non-contiguous segments (i#160/PR 562667) */
        app_pc seg_base;
        uint i;
        ASSERT(info->num_segments > 1 && info->segments != NULL, "invalid seg data");
        seg_base = info->segments[0].start;
        for (i = 1; i < info->num_segments; i++) {
            if (info->segments[i].start > info->segments[i - 1].end) {
                callstack_module_add_region(seg_base, info->segments[i - 1].end, idx);
                seg_base = info->segments[i].start;
            } else {
                ASSERT(info->segments[i].start == info->segments[i - 1].end,
                       "module list should be sorted");
            }
        }
        callstack_module_add_region(seg_base, info->segments[i - 1].end, idx);
    }
#endif
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

    dr_mutex_unlock(modtree_lock);
}

static bool
module_lookup(byte *pc, app_pc *start OUT, size_t *size OUT, int *name_idx OUT)
{
    rb_node_t *node;
    bool res = false;
    dr_mutex_lock(modtree_lock);
    node = rb_in_node(module_tree, pc);
    if (node != NULL) {
        res = true;
        rb_node_fields(node, start, size, (void **)name_idx);
    }
    dr_mutex_unlock(modtree_lock);
    return res;
}

static bool
is_in_module(byte *pc)
{
    /* We cache the last page queried for performance */
    static app_pc modtree_last_hit;
    static app_pc modtree_last_miss;
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
        res = (rb_in_node(module_tree, pc) != NULL);
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
