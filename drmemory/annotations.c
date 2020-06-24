/* **********************************************************
 * Copyright (c) 2011-2020 Google, Inc.  All rights reserved.
 * **********************************************************/

/* Dr. Memory: the memory debugger
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License, and no later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/***************************************************************************
 * annotations.c: Support for application annotations.
 *
 * FIXME: This is a quick implementation of Valgrind client requests.  There are
 * many more things we should do:
 * - i#573: Provide additional annotations, ie support for JITs flushing the
 *   code cache.
 * - i#61: Implement AmIRunningUnderDrMemory() or RunningUnderValgrind().
 * - i#311: Annotate which part of the subprogram is running, for mapping
 *   allocation sites to test cases.
 */

#include "dr_api.h"
#include "drmgr.h"
#include "drmemory.h"
#include "annotations.h"
#include "utils.h"
#include "shadow.h"
#include "options.h"
#ifdef TOOL_DR_MEMORY
# include "alloc_drmem.h"
# include "memlayout.h"
#else
extern void check_reachability(bool at_exit);
#endif

#ifndef ARM /* FIXME DRi#1672: add ARM annotation support to DR */
static ptr_uint_t
handle_make_mem_defined_if_addressable(dr_vg_client_request_t *request)
{
# ifdef TOOL_DR_MEMORY
    app_pc start = (app_pc)request->args[0];
    ptr_uint_t len = request->args[1];
    LOG(2, "%s: "PFX"-"PFX"\n", __FUNCTION__, start, start + len);

    /* No-op if we're not tracking definedness. */
    if (!options.shadowing || !options.check_uninitialized)
        return 1;

    shadow_set_non_matching_range(start, len, SHADOW_DEFINED,
                                  SHADOW_UNADDRESSABLE);
# endif

    /* XXX: Not sure what the proper return code is for this request, and most
     * apps don't care.
     */
    return 1;
}

static ptr_uint_t
handle_do_leak_check(dr_vg_client_request_t *request)
{
    LOG(2, "%s\n", __FUNCTION__);
    check_reachability(false/*!at_exit*/);
    return 0;
}

void handle_dump_memory_layout(void)
{
# ifdef TOOL_DR_MEMORY
    app_pc pc = (app_pc) dr_read_saved_reg(dr_get_current_drcontext(), SPILL_SLOT_2);
    memlayout_dump_layout(pc);
# endif
}
#endif

void
annotate_init(void)
{
    /* Valgrind annotations are not available for 64-bit Windows */
#if !(defined(WINDOWS) && defined(X64))
# ifndef ARM /* FIXME DRi#1672: add ARM annotation support to DR */
    dr_annotation_register_valgrind(DR_VG_ID__MAKE_MEM_DEFINED_IF_ADDRESSABLE,
                                    handle_make_mem_defined_if_addressable);
    dr_annotation_register_valgrind(DR_VG_ID__DO_LEAK_CHECK,
                                    handle_do_leak_check);
# endif
#endif

#ifndef ARM /* FIXME DRi#1672: add ARM annotation support to DR */
    const char *dumpmem_name = "drmemory_dump_memory_layout";
    if (!dr_annotation_register_call(dumpmem_name,
                                     handle_dump_memory_layout, false, 0,
                                     DR_ANNOTATION_CALL_TYPE_FASTCALL)) {
        NOTIFY_ERROR("ERROR: Failed to register annotations"NL);
        dr_abort();
    }
    dr_annotation_pass_pc(dumpmem_name);
#endif
}

void
annotate_exit(void)
{
}
