/* **********************************************************
 * Copyright (c) 2011-2014 Google, Inc.  All rights reserved.
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

/* Need this defined and to the latest to get the latest defines and types */
#define _WIN32_WINNT 0x0601 /* == _WIN32_WINNT_WIN7 */
#define WINVER _WIN32_WINNT

#include "dr_api.h"
#include "drmemory.h"
#include "syscall.h"
#include "syscall_os.h"
#include "syscall_windows.h"
#include "slowpath.h"
#include "shadow.h"
#include "gdicheck.h"
#include <stddef.h> /* offsetof */

#include "../wininc/ntuser.h" /* LARGE_STRING */

static drsys_sysnum_t sysnum_GdiCreateDIBSection = {-1,0};

static drsys_sysnum_t sysnum_UserGetDC = {-1,0};
static drsys_sysnum_t sysnum_UserGetDCEx = {-1,0};
static drsys_sysnum_t sysnum_UserGetWindowDC = {-1,0};
static drsys_sysnum_t sysnum_UserBeginPaint = {-1,0};
static drsys_sysnum_t sysnum_UserEndPaint = {-1,0};
static drsys_sysnum_t sysnum_UserReleaseDC = {-1,0};
static drsys_sysnum_t sysnum_GdiGetDCforBitmap = {-1,0};
static drsys_sysnum_t sysnum_GdiDdGetDC = {-1,0};
static drsys_sysnum_t sysnum_GdiDeleteObjectApp = {-1,0};
static drsys_sysnum_t sysnum_GdiCreateMetafileDC = {-1,0};
static drsys_sysnum_t sysnum_GdiCreateCompatibleDC = {-1,0};
static drsys_sysnum_t sysnum_GdiOpenDCW = {-1,0};

void
syscall_wingdi_init(void *drcontext, app_pc ntdll_base)
{
    get_sysnum("NtGdiCreateDIBSection", &sysnum_GdiCreateDIBSection,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);

    get_sysnum("NtUserGetDC", &sysnum_UserGetDC, false/*reqd*/);
    get_sysnum("NtUserGetDCEx", &sysnum_UserGetDCEx, false/*reqd*/);
    get_sysnum("NtUserGetWindowDC", &sysnum_UserGetWindowDC, false/*reqd*/);
    get_sysnum("NtUserBeginPaint", &sysnum_UserBeginPaint, false/*reqd*/);
    get_sysnum("NtUserEndPaint", &sysnum_UserEndPaint, false/*reqd*/);
    get_sysnum("ReleaseDC", &sysnum_UserReleaseDC,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    get_sysnum("NtGdiGetDCforBitmap", &sysnum_GdiGetDCforBitmap,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    get_sysnum("NtGdiDdGetDC", &sysnum_GdiDdGetDC,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    get_sysnum("NtGdiDeleteObjectApp", &sysnum_GdiDeleteObjectApp,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    get_sysnum("NtGdiCreateMetafileDC", &sysnum_GdiCreateMetafileDC,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    get_sysnum("NtGdiCreateCompatibleDC", &sysnum_GdiCreateCompatibleDC,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    get_sysnum("NtGdiOpenDCW", &sysnum_GdiOpenDCW,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);

    if (options.check_gdi)
        gdicheck_init();
}

void
syscall_wingdi_exit(void)
{
    if (options.check_gdi)
        gdicheck_exit();
}

void
syscall_wingdi_thread_init(void *drcontext)
{
    if (options.check_gdi)
        gdicheck_thread_init(drcontext);
}

void
syscall_wingdi_thread_exit(void *drcontext)
{
    if (options.check_gdi)
        gdicheck_thread_exit(drcontext);
}

/***************************************************************************
 * Shadow handling
 */

bool
wingdi_process_syscall_arg(drsys_arg_t *arg)
{
    if (arg->containing_type == DRSYS_TYPE_LARGE_STRING) {
        /* i#489: LARGE_STRING.MaximumLength and LARGE_STRING.bAnsi end
         * up initialized by a series of bit manips that fool us.
         */
        LARGE_STRING ls;
        if (strcmp(arg->arg_name, "LARGE_STRING.MaximumLength") == 0) {
            /* can't take offseof bitfield so we assume no padding */
            byte *start = ((byte*) arg->start_addr) - sizeof(ls.Length) -
                offsetof(LARGE_STRING, Length);
            ASSERT(arg->pre, "LARGE_STRING non-buffer fields are always IN");
            if (safe_read((void*) start, sizeof(ls), &ls)) {
                LOG(SYSCALL_VERBOSE,
                    "LARGE_STRING Buffer="PFX" Length=%d MaximumLength=%d\n",
                    (byte *)ls.Buffer, ls.Length, ls.MaximumLength);
                /* Check for undef if looks "suspicious": weak,
                 * but simpler and more efficient than pattern match on every bb.
                 */
                if (ls.MaximumLength > ls.Length &&
                    ls.MaximumLength > 1024 /* suspicious */) {
                    check_sysmem(MEMREF_CHECK_DEFINEDNESS, arg->sysnum, arg->start_addr,
                                 sizeof(ULONG/*+bAnsi*/), arg->mc, arg->arg_name);
                } else {
                    shadow_set_range(arg->start_addr, (byte *)arg->start_addr +
                                     sizeof(ULONG), SHADOW_DEFINED);
                }
            } else
                WARN("WARNING: unable to read syscall param\n");
            return true; /* handled */
        }
    }
    return false; /* not handled */
}

/***************************************************************************
 * General (non-shadow/memory checking) system call handling
 */

static bool
handle_GdiCreateDIBSection(bool pre, void *drcontext, cls_syscall_t *pt)
{
    byte *dib;
    if (pre)
        return true;
    if (safe_read((byte *) syscall_get_param(drcontext, 8), sizeof(dib), &dib)) {
        /* XXX: move this into common/alloc.c since that's currently
         * driving all the known allocs, heap and otherwise
         */
        byte *dib_base;
        size_t dib_size;
        if (dr_query_memory(dib, &dib_base, &dib_size, NULL)) {
            LOG(SYSCALL_VERBOSE, "NtGdiCreateDIBSection created "PFX"-"PFX"\n",
                dib_base, dib_base+dib_size);
            client_handle_mmap(drcontext, dib_base, dib_size,
                               /* XXX: may not be file-backed but treating as
                                * all-defined and non-heap which is what this param
                                * does today.  could do dr_virtual_query().
                                */
                               true/*file-backed*/);
        } else
            WARN("WARNING: unable to query DIB section "PFX"\n", dib);
    } else
        WARN("WARNING: unable to read NtGdiCreateDIBSection param\n");
    /* When passed-in section pointer is NULL, the return value is
     * HBITMAP but doesn't seem to be a real memory address, which is
     * odd, b/c presumably when a section is used it would be a real
     * memory address, right?  The value is typically large so clearly
     * not just a table index.  Xref i#539.
     */
    return true;
}

/* Caller should check for success and only call if syscall is successful (for !pre) */
static void
syscall_check_gdi(bool pre, void *drcontext, drsys_sysnum_t sysnum, cls_syscall_t *pt,
                  dr_mcontext_t *mc)
{
    app_loc_t loc;
    ASSERT(options.check_gdi, "shouldn't be called");
    if (drsys_sysnums_equal(&sysnum, &sysnum_UserGetDC) ||
        drsys_sysnums_equal(&sysnum, &sysnum_UserGetDCEx) ||
        drsys_sysnums_equal(&sysnum, &sysnum_UserGetWindowDC) ||
        drsys_sysnums_equal(&sysnum, &sysnum_UserBeginPaint) ||
        drsys_sysnums_equal(&sysnum, &sysnum_GdiGetDCforBitmap) ||
        drsys_sysnums_equal(&sysnum, &sysnum_GdiDdGetDC)) {
        if (!pre) {
            HDC hdc = (HDC) dr_syscall_get_result(drcontext);
            /* i#1192: NtGdiGetDCforBitmap does not allocate a new DC
             * that needs to be freed.  We leave it enabled as an
             * "allocation" to have more DC's in our table (presumably
             * adding in those created before we took over).
             */
            uint flags = 0;
            if (!drsys_sysnums_equal(&sysnum, &sysnum_GdiGetDCforBitmap))
                flags |= GDI_DC_ALLOC_GET;
            syscall_to_loc(&loc, sysnum, "");
            gdicheck_dc_alloc(hdc, flags, sysnum, mc, &loc);
            if (drsys_sysnums_equal(&sysnum, &sysnum_UserBeginPaint)) {
                /* we store the hdc for access in EndPaint */
                pt->paintDC = hdc;
            }
        }
    } else if (drsys_sysnums_equal(&sysnum, &sysnum_GdiCreateMetafileDC) ||
               drsys_sysnums_equal(&sysnum, &sysnum_GdiCreateCompatibleDC) ||
               drsys_sysnums_equal(&sysnum, &sysnum_GdiOpenDCW)) {
        if (!pre) {
            HDC hdc = (HDC) dr_syscall_get_result(drcontext);
            uint flags = GDI_DC_ALLOC_CREATE;
            if (drsys_sysnums_equal(&sysnum, &sysnum_GdiCreateCompatibleDC) &&
                syscall_get_param(drcontext, 0) == 0)
                flags |= GDI_DC_ALLOC_DUP_NULL;
            syscall_to_loc(&loc, sysnum, "");
            gdicheck_dc_alloc(hdc, flags, sysnum, mc, &loc);
        }
    } else if (drsys_sysnums_equal(&sysnum, &sysnum_UserReleaseDC) ||
               drsys_sysnums_equal(&sysnum, &sysnum_UserEndPaint)) {
        if (pre) {
            HDC hdc;
            if (drsys_sysnums_equal(&sysnum, &sysnum_UserReleaseDC))
                hdc = (HDC)syscall_get_param(drcontext, 0);
            else {
                hdc = pt->paintDC;
                pt->paintDC = NULL;
            }
            gdicheck_dc_free(hdc, false/*Get not Create*/, sysnum, mc);
        }
    } else if (drsys_sysnums_equal(&sysnum, &sysnum_GdiDeleteObjectApp)) {
        if (pre)
            gdicheck_obj_free((HANDLE)syscall_get_param(drcontext, 0), sysnum, mc);
    }
}

bool
wingdi_shared_process_syscall(bool pre, void *drcontext, drsys_sysnum_t sysnum,
                              cls_syscall_t *pt, dr_mcontext_t *mc,
                              drsys_syscall_t *syscall)
{
    /* handlers here do not check for success so we check up front */
    if (!pre) {
        bool success;
        if (drsys_cur_syscall_result(drcontext, &success, NULL, NULL)
            != DRMF_SUCCESS || !success)
            return true;
    }

    if (sysnum.number == sysnum_GdiCreateDIBSection.number)
        return handle_GdiCreateDIBSection(pre, drcontext, pt);

    if (options.check_gdi) {
        syscall_check_gdi(pre, drcontext, sysnum, pt, mc);
    }

    return true; /* execute syscall */
}

