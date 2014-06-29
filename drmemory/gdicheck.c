/* **********************************************************
 * Copyright (c) 2012-2014 Google, Inc.  All rights reserved.
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

/* Additional GDI usage checks beyond initialized and addressable
 * parameter checks.
 * Xref i#752
 *
 * Note that on some platforms at least the GDI impl is robust and
 * handles some of these errors we're detecting: but they still seem
 * to be accepted as "best practices" and programmers like to be
 * reminded of them (and they may fail on older Windows platforms).
 */

#include "dr_api.h"
#include "drwrap.h"
#include "drmemory.h"
#include "callstack.h"
#include "report.h"
#include "gdicheck.h"

#include "../wininc/ntgdihdl.h"

#ifndef WINDOWS
# error WINDOWS-only
#endif

/* For device context (DC) checks we store data per DC */
typedef struct _per_dc_t {
    thread_id_t thread;
    gdi_dc_alloc_t flags;
    bool exited;
    /* count of non-stock selected objects */
    uint non_stock_selected;
    packed_callstack_t *pcs;
} per_dc_t;

/* Table of per_dc_t entries */
#define DC_TABLE_HASH_BITS 6
static hashtable_t dc_table;

/* Table of selected object handles that stores DC selected into */
#define SELECTED_TABLE_HASH_BITS 8
static hashtable_t selected_table;

static void
per_dc_free(void *p)
{
    per_dc_t *pdc = (per_dc_t *) p;
    if (pdc->pcs != NULL)
        packed_callstack_free(pdc->pcs);
    global_free(pdc, sizeof(*pdc), HEAPSTAT_HASHTABLE);
}

static void
gdicheck_module_load(void *drcontext, const module_data_t *info, bool loaded);

void
gdicheck_init(void)
{
    ASSERT(options.check_gdi, "incorrectly called");

    drmgr_register_module_load_event(gdicheck_module_load);

    hashtable_init_ex(&dc_table, DC_TABLE_HASH_BITS, HASH_INTPTR,
                      false/*!str_dup*/, true/*synch*/,
                      per_dc_free, NULL, NULL);
    hashtable_init(&selected_table, SELECTED_TABLE_HASH_BITS, HASH_INTPTR,
                      false/*!str_dup*/);
}

void
gdicheck_exit(void)
{
    ASSERT(options.check_gdi, "incorrectly called");
    hashtable_delete_with_stats(&dc_table, "DC table");
    hashtable_delete_with_stats(&selected_table, "selected object table");
}

void
gdicheck_thread_init(void *drcontext)
{
    ASSERT(options.check_gdi, "incorrectly called");
}

void
gdicheck_thread_exit(void *drcontext)
{
    uint i;
    thread_id_t tid = dr_get_thread_id(drcontext);
    ASSERT(options.check_gdi, "incorrectly called");
    hashtable_lock(&dc_table);
    for (i = 0; i < HASHTABLE_SIZE(dc_table.table_bits); i++) {
        hash_entry_t *he;
        for (he = dc_table.table[i]; he != NULL; he = he->next) {
            per_dc_t *pdc = (per_dc_t *) he->payload;
            if (pdc->thread == tid) {
                /* indicate this DC should not be used */
                pdc->exited = true;
            }
        }
    }
    hashtable_unlock(&dc_table);
}

/***************************************************************************
 * DC CHECKS
 */

#define REPORT_PREFIX "" /* We used to need this when reported as WARNING */
#define REPORT_MAX_SZ 512
#define AUX_MSG_SZ 32

static void
gdicheck_report(app_pc addr, drsys_sysnum_t sysnum, dr_mcontext_t *mc,
                per_dc_t *pdc, const char *msg, ...)
{
    va_list ap;
    app_loc_t loc;
    char buf[REPORT_MAX_SZ];
    char aux_buf[AUX_MSG_SZ];
    char *aux_msg = NULL;
    packed_callstack_t *aux_pcs = NULL;
    ssize_t len;
    if (addr == NULL)
        syscall_to_loc(&loc, sysnum, NULL);
    else
        pc_to_loc(&loc, addr - 1); /* auto -1 is only for later frames */
    va_start(ap, msg);
    /* XXX: perhaps better to have a constant header string describing
     * the type of error, for simpler suppressions, and have auxiliary
     * lines for the extra info and parameters: but then we'd need
     * to expose the line prefix stuff in report.c.
     * So leaving a single line for now.
     * Can be suppressed via wildcards after all.
     */
    len = dr_vsnprintf(buf, BUFFER_SIZE_ELEMENTS(buf), msg, ap);
    ASSERT(len > 0, "GDI report exceeds buffer size");
    NULL_TERMINATE_BUFFER(buf);
    va_end(ap);

    if (pdc != NULL && pdc->pcs != NULL) {
        size_t sofar = 0;
        BUFPRINT(aux_buf, BUFFER_SIZE_ELEMENTS(aux_buf), sofar, len,
                 "%sDC was allocated here:"NL, INFO_PFX);
        aux_pcs = pdc->pcs;
        aux_msg = aux_buf;
    }
    report_gdi_error(&loc, mc, buf, aux_pcs, aux_msg);
}

static inline bool
obj_is_stock(HGDIOBJ obj)
{
    return TEST(GDI_HANDLE_STOCK_MASK, (ptr_uint_t)obj);
}

static inline bool
obj_is_DC(HGDIOBJ obj)
{
    return ((ptr_uint_t)obj & GDI_HANDLE_TYPE_MASK) == GDI_OBJECT_TYPE_DC;
}

static inline bool
obj_is_bitmap(HGDIOBJ obj)
{
    return ((ptr_uint_t)obj & GDI_HANDLE_TYPE_MASK) == GDI_OBJECT_TYPE_BITMAP;
}

static inline bool
obj_is_drawing_object(HGDIOBJ obj)
{
    ptr_uint_t type = ((ptr_uint_t)obj & GDI_HANDLE_TYPE_MASK);
    return (type == GDI_OBJECT_TYPE_BRUSH ||
            type == GDI_OBJECT_TYPE_DIRECTDRAW ||
            type == GDI_OBJECT_TYPE_PEN ||
            type == GDI_OBJECT_TYPE_EXTPEN);
}

void
gdicheck_dc_alloc(HDC hdc, gdi_dc_alloc_t flags, drsys_sysnum_t sysnum,
                  dr_mcontext_t *mc, app_loc_t *loc)
{
    per_dc_t *pdc;
    bool exists;
    LOG(2, "GDI DC alloc "PFX" %s%s\n", hdc,
        TEST(GDI_DC_ALLOC_CREATE, flags) ? "create" : "",
        TEST(GDI_DC_ALLOC_GET, flags) ? "get" : "");
    if (hdc == NULL)
        return;
    pdc = (per_dc_t *) global_alloc(sizeof(*pdc), HEAPSTAT_HASHTABLE);
    pdc->thread = dr_get_thread_id(dr_get_current_drcontext());
    pdc->flags = flags;
    pdc->exited = false;
    pdc->non_stock_selected = 0;
    packed_callstack_record(&pdc->pcs, mc, loc, options.callstack_max_frames);
    if (!hashtable_add(&dc_table, (void *)hdc, (void *)pdc)) {
        per_dc_free((void *)pdc);
        /* Note that we don't report an error for calling GetDC again without
         * calling ReleaseDC first b/c this is not uncommon esp for
         * hwnd=NULL.  Plus, a private or class DC does not need ReleaseDC
         * to be called at all.
         */
    }
}

void
gdicheck_dc_free(HDC hdc, bool create, drsys_sysnum_t sysnum, dr_mcontext_t *mc)
{
    per_dc_t *pdc = (per_dc_t *) hashtable_lookup(&dc_table, (void *)hdc);
    IF_DEBUG(bool found;)
    LOG(2, "GDI DC free "PFX" %s\n", hdc, create ? "create" : "get");
    if (pdc == NULL) {
        ASSERT(hdc != NULL, "DC tracking error on free");
        return;
    }
    /* Check: Proper pairing GetDC|ReleaseDC and CreateDC|DeleteDC */
    if ((TEST(GDI_DC_ALLOC_GET, pdc->flags) && create) ||
        (TEST(GDI_DC_ALLOC_CREATE, pdc->flags) && !create)) {
        gdicheck_report(NULL, sysnum, mc, pdc, REPORT_PREFIX
                        "free mismatch for DC "PFX": use ReleaseDC only for GetDC "
                        "and DeleteDC only for CreateDC", hdc);
    }
    /* Check: ReleaseDC called from the same thread that called GetDC */
    if (TEST(GDI_DC_ALLOC_GET, pdc->flags) &&
        pdc->thread != dr_get_thread_id(dr_get_current_drcontext())) {
        gdicheck_report(NULL, sysnum, mc, pdc, REPORT_PREFIX
                        "ReleaseDC for DC "PFX" called from different thread "TIDFMT" "
                        "than the%s thread "TIDFMT" that called GetDC", hdc,
                        dr_get_thread_id(dr_get_current_drcontext()),
                        pdc->exited ? " now-exited" : "", pdc->thread);
    }
    /* Check: No non-default objects are selected in a DC being deleted */
    if (pdc->non_stock_selected > 0) {
        gdicheck_report(NULL, sysnum, mc, pdc, REPORT_PREFIX
                        "DC "PFX" that contains selected object being deleted", hdc);
    }
    IF_DEBUG(found = )
        hashtable_remove(&dc_table, (void *)hdc);
    ASSERT(found, "DC tracking error");
}

void
gdicheck_obj_free(HANDLE obj, drsys_sysnum_t sysnum, dr_mcontext_t *mc)
{
    LOG(2, "GDI obj free "PFX"\n", obj);
    if (obj == NULL)
        return;
    else if (obj_is_DC(obj))
        gdicheck_dc_free((HDC)obj, true/*Create not Get*/, sysnum, mc);
    else if (obj_is_stock(obj)) {
        /* While Petzold says not to delete stock objects, MSDN explicitly
         * says it is not an error.
         */
    } else {
        HDC hdc = hashtable_lookup(&selected_table, (void *)obj);
        if (hdc != NULL) {
            per_dc_t *pdc;
            pdc = (per_dc_t *) hashtable_lookup(&dc_table, (void *)hdc);
            /* Check: an HGDIOBJ being deleted is selected in any DC
             * While Petzold says not to delete any GDI object while it's selected,
             * MSDN explicitly says it's only bad to delete a pen or brush (i#899).
             */
            if (obj_is_drawing_object(obj)) {
                gdicheck_report(NULL, sysnum, mc, pdc, REPORT_PREFIX
                                "deleting a drawing object "PFX
                                " that is selected into DC", obj);
            }
            /* XXX: could be a race: but threads aren't supposed to share GDI objs.
             * One solution is for hashtable_remove() to return the key.
             */
            hashtable_remove(&selected_table, (void *)obj);
            /* Don't count as selected now that object is deleted: in fact on win7
             * GDI impl seems to do the right thing and it handles the delete
             * gracefully.
             */
            if (pdc != NULL)
                pdc->non_stock_selected--;
        }
    }
}

static void
gdicheck_dc_select_obj(HDC hdc, HGDIOBJ prior_obj, HGDIOBJ new_obj,
                       app_pc addr, dr_mcontext_t *mc)
{
    drsys_sysnum_t sysnum = {0,0}; /* not specifying */
    per_dc_t *pdc = (per_dc_t *) hashtable_lookup(&dc_table, (void *)hdc);
    LOG(2, "GDI obj select prior="PFX" new="PFX" hdc="PFX"\n", prior_obj, new_obj, hdc);
    if (pdc != NULL) {
        LOG(3, "\thdc="PFX" non_stock_sel=%d\n", hdc, pdc->non_stock_selected);
        /* Check: CreateCompatibleDC is not used after creating thread exits.
         * MSDN says a DC created by CreateCompatibleDC(NULL) is owned by the
         * creating thread and is invalid after it exits.
         *
         * XXX: Given the admonitions to not use DC's across threads,
         * should we do this check for any DC as a "best programming
         * practices" check?  Though there won't be any races once the
         * other thread is dead, in general DC's are supposed to be
         * local objects that are created, used, and then destroyed.
         */
        if (TEST(GDI_DC_ALLOC_DUP_NULL, pdc->flags) && pdc->exited) {
            gdicheck_report(addr, sysnum, mc, pdc, REPORT_PREFIX
                            "DC "PFX" used for select was created by now-exited thread "
                            "%d by duplicating NULL, which makes it a thread-private DC",
                            hdc, pdc->thread);
        }
        /* Check: do not operate on a single DC from two different threads
         * XXX i#1192: disabling this by default (under -check_gdi_multithread)
         * as user32!ghdcBits2 violates it!
         *
         * XXX: should check on other DC operations beyond selecting
         * XXX: also, once the creating thread exits we currently don't complain
         * and assume the DC was transferred to another thread, but we subsequently
         * don't ensure just one thread operates on it.  see also comment above
         * questioning how serious this is.
         */
        else if (options.check_gdi_multithread &&
                 !pdc->exited &&
                 pdc->thread != dr_get_thread_id(dr_get_current_drcontext())) {
            gdicheck_report(addr, sysnum, mc, pdc, REPORT_PREFIX
                            "DC created by one thread "TIDFMT" and used by another "
                            TIDFMT,
                            pdc->thread, dr_get_thread_id(dr_get_current_drcontext()));
        }
        if (prior_obj == NULL || prior_obj == HGDI_ERROR) {
            /* call failed */
            HDC curdc = (HDC) hashtable_lookup(&selected_table, (void *)new_obj);
            /* Check: do not select the same bitmap into two different DC's */
            if (curdc != NULL && obj_is_bitmap(new_obj) && curdc != hdc) {
                gdicheck_report(addr, sysnum, mc, NULL, REPORT_PREFIX
                                "same bitmap "PFX" selected into two different DC's "
                                PFX" and "PFX, new_obj, hdc, curdc);
            }
        } else  {
            if (!obj_is_stock(prior_obj)) {
                /* can already be zero of prior_obj was deleted */
                if (pdc->non_stock_selected > 0)
                    pdc->non_stock_selected--;
                LOG(3, "\thdc="PFX" now has non_stock_sel=%d\n",
                    hdc, pdc->non_stock_selected);
                hashtable_remove(&selected_table, (void *)prior_obj);
            }
            if (!obj_is_stock(new_obj)) {
                HDC curdc;
                pdc->non_stock_selected++;
                LOG(3, "\thdc="PFX" now has non_stock_sel=%d\n",
                    hdc, pdc->non_stock_selected);
                curdc = hashtable_add_replace(&selected_table, (void *)new_obj,
                                              (void *)hdc);
                /* Check: do not select the same bitmap into two different DC's */
                if (curdc != NULL && obj_is_bitmap(new_obj) && curdc != hdc) {
                    gdicheck_report(addr, sysnum, mc, NULL, REPORT_PREFIX
                                    "same bitmap "PFX" selected into two different DC's "
                                    PFX" and "PFX, new_obj, hdc, curdc);
                }
            }
        }
    } else {
        /* w/o early injection we end up not seeing creation of DC's like
         * USER32!ghdcBits2
         */
    }
}

/***************************************************************************
 * WRAPPING GDI32 LIBRARY ROUTINES
 *
 * i#764: for pen and brush (and sometimes font?), not making it to select
 * syscall on pre-win7 or when there's no interactive user
 * => need to intercept gdi32!SelectObject library routine.
 * we go ahead and ignore the NtGdi*Select* syscalls then to avoid
 * duplicate handling (NtGdiExtSelectClipRgn, NtGdiSelectBrush,
 * NtGdiSelectPen, NtGdiSelectBitmap, NtGdiSelectFont).
 */

typedef struct _select_args_t {
    HDC hdc;
    HGDIOBJ new_obj;
} select_args_t;

static void
gdicheck_wrap_pre_SelectObject(void *wrapcxt, void OUT **user_data)
{
    select_args_t *args = (select_args_t *) global_alloc(sizeof(*args), HEAPSTAT_MISC);
    args->hdc = (HDC) drwrap_get_arg(wrapcxt, 0);
    args->new_obj = (HANDLE) drwrap_get_arg(wrapcxt, 1);
    *user_data = (void *) args;
}

static void
gdicheck_wrap_post_SelectObject(void *wrapcxt, void *user_data)
{
    select_args_t *args = (select_args_t *) user_data;
    void *drcontext = dr_get_current_drcontext();
    dr_mcontext_t *mc = drwrap_get_mcontext_ex
        (wrapcxt, DR_MC_INTEGER|DR_MC_CONTROL); /* don't need xmm */
    HANDLE old_obj = (HANDLE) drwrap_get_retval(wrapcxt);
    /* to report selecting one bitmap into two DC's we need to call even
     * on failure (on win7 at least, GDI detects this)
     */
    gdicheck_dc_select_obj(args->hdc, old_obj, args->new_obj,
                           drwrap_get_retaddr(wrapcxt), mc);
    global_free(args, sizeof(*args), HEAPSTAT_MISC);
}

static void
gdicheck_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    const char *modname = dr_module_preferred_name(info);
    if (modname != NULL && strcasecmp(modname, "gdi32.dll") == 0) {
        app_pc addr = (app_pc) dr_get_proc_address(info->handle, "SelectObject");
        ASSERT(addr != NULL, "can't find gdi32!SelectObject");
        if (addr == NULL || !drwrap_wrap(addr, gdicheck_wrap_pre_SelectObject,
                                         gdicheck_wrap_post_SelectObject))
            ASSERT(false, "failed to wrap gdi32!SelectObject");
    }
}

