/* **********************************************************
 * Copyright (c) 2012-2013 Google, Inc.  All rights reserved.
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

#ifndef _GDICHECK_H_
#define _GDICHECK_H_ 1

typedef enum {
    /* If neither of these two, we didn't see it created: */
    GDI_DC_ALLOC_CREATE    = 0x0001, /* Create or Dup */
    GDI_DC_ALLOC_GET       = 0x0002, /* Get */
    /* Dup of NULL HDC? */
    GDI_DC_ALLOC_DUP_NULL  = 0x0004,
} gdi_dc_alloc_t;

void
gdicheck_init(void);

void
gdicheck_exit(void);

void
gdicheck_thread_init(void *drcontext);

void
gdicheck_thread_exit(void *drcontext);

void
gdicheck_dc_alloc(HDC hdc, gdi_dc_alloc_t flags, drsys_sysnum_t sysnum,
                  dr_mcontext_t *mc, app_loc_t *loc);

void
gdicheck_dc_free(HDC hdc, bool create, drsys_sysnum_t sysnum, dr_mcontext_t *mc);

#endif /* _GDICHECK_H_ */
