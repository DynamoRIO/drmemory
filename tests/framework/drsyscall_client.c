/* **********************************************************
 * Copyright (c) 2012 Google, Inc.  All rights reserved.
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

/* Test of the Dr. Syscall Extension */

#include "dr_api.h"
#include "drmgr.h"
#include "drsyscall.h"
#include <string.h>
#ifdef WINDOWS
# include <windows.h>
#endif

#undef ASSERT /* we don't want msgbox */
#define ASSERT(cond, msg) \
    ((void)((!(cond)) ? \
     (dr_fprintf(STDERR, "ASSERT FAILURE: %s:%d: %s (%s)", \
                 __FILE__,  __LINE__, #cond, msg), \
      dr_abort(), 0) : 0))

static void
check_mcontext(void *drcontext)
{
    dr_mcontext_t *mc;
    dr_mcontext_t mc_DR;

    if (drsys_get_mcontext(drcontext, &mc) != DRMF_SUCCESS)
        ASSERT(false, "drsys_get_mcontext failed");
    mc_DR.size = sizeof(mc_DR);
    mc_DR.flags = DR_MC_INTEGER|DR_MC_CONTROL;
    dr_get_mcontext(drcontext, &mc_DR);
    ASSERT(mc->xdi == mc_DR.xdi, "mc check");
    ASSERT(mc->xsi == mc_DR.xsi, "mc check");
    ASSERT(mc->xbp == mc_DR.xbp, "mc check");
    ASSERT(mc->xsp == mc_DR.xsp, "mc check");
    ASSERT(mc->xbx == mc_DR.xbx, "mc check");
    ASSERT(mc->xdx == mc_DR.xdx, "mc check");
    ASSERT(mc->xcx == mc_DR.xcx, "mc check");
    ASSERT(mc->xax == mc_DR.xax, "mc check");
    ASSERT(mc->xflags == mc_DR.xflags, "mc check");
}

static bool
drsys_iter_memarg_cb(drsys_arg_t *arg, void *user_data)
{
    ASSERT(arg->valid, "no args should be invalid in this app");
    ASSERT(arg->mc != NULL, "mc check");
    ASSERT(arg->drcontext == dr_get_current_drcontext(), "dc check");

    return true; /* keep going */
}

static bool
drsys_iter_arg_cb(drsys_arg_t *arg, void *user_data)
{
    ptr_uint_t val;

    ASSERT(arg->valid, "no args should be invalid in this app");
    ASSERT(arg->mc != NULL, "mc check");
    ASSERT(arg->drcontext == dr_get_current_drcontext(), "dc check");

    if (arg->reg == DR_REG_NULL) {
        ASSERT((byte *)arg->start_addr >= (byte *)arg->mc->xsp &&
               (byte *)arg->start_addr < (byte *)arg->mc->xsp + PAGE_SIZE,
               "mem args should be on stack");
    }

    if (drsys_pre_syscall_arg(arg->drcontext, arg->ordinal, &val) != DRMF_SUCCESS)
        ASSERT(false, "drsys_pre_syscall_arg failed");
    ASSERT(val == arg->value, "values do not match");

    return true; /* keep going */
}

static bool
event_pre_syscall(void *drcontext, int sysnum)
{
    drsys_sysnum_t sysnum_full;
    bool known;

    if (drsys_get_sysnum(drcontext, &sysnum_full) != DRMF_SUCCESS)
        ASSERT(false, "drsys_get_sysnum failed");
    ASSERT(sysnum == sysnum_full.number, "primary should match DR's num");

    check_mcontext(drcontext);

    if (drsys_cur_syscall_is_known(drcontext, &known) != DRMF_SUCCESS || !known)
        ASSERT(false, "no syscalls in this app should be unknown");

    if (drsys_iterate_args(drcontext, drsys_iter_arg_cb, NULL) != DRMF_SUCCESS)
        ASSERT(false, "drsys_iterate_args failed");
    if (drsys_iterate_memargs(drcontext, drsys_iter_memarg_cb, NULL) != DRMF_SUCCESS)
        ASSERT(false, "drsys_iterate_memargs failed");

    return true;
}

static void
event_post_syscall(void *drcontext, int sysnum)
{
    drsys_sysnum_t sysnum_full;
    bool success = false;

    if (drsys_get_sysnum(drcontext, &sysnum_full) != DRMF_SUCCESS)
        ASSERT(false, "drsys_get_sysnum failed");
    ASSERT(sysnum == sysnum_full.number, "primary should match DR's num");

    check_mcontext(drcontext);

    if (drsys_iterate_args(drcontext, drsys_iter_arg_cb, NULL) != DRMF_SUCCESS)
        ASSERT(false, "drsys_iterate_args failed");

    if (drsys_cur_syscall_succeeded(drcontext, &success) != DRMF_SUCCESS || !success) {
        ASSERT(false, "no syscalls in this app should fail");
    } else {
        if (drsys_iterate_memargs(drcontext, drsys_iter_memarg_cb, NULL) != DRMF_SUCCESS)
            ASSERT(false, "drsys_iterate_memargs failed");
    }
}

static bool
event_filter_syscall(void *drcontext, int sysnum)
{
    return true; /* intercept everything */
}

static void
test_static_queries(void)
{
    drsys_sysnum_t num = {4,4};
    drmf_status_t res;
    bool known;
    drsys_syscall_type_t type;
    const char *name = "bogus";

#ifdef WINDOWS
    res = drsys_name_to_number("NtContinue", &num);
#else
    res = drsys_name_to_number("fstatfs", &num);
#endif
    ASSERT(res == DRMF_SUCCESS && num.secondary == 0, "drsys_name_to_number failed");
    if (drsys_syscall_is_known(num, &known) != DRMF_SUCCESS || !known)
        ASSERT(false, "syscall should be known");
    if (drsys_syscall_type(num, &type) != DRMF_SUCCESS ||
        type != DRSYS_SYSCALL_TYPE_KERNEL)
        ASSERT(false, "syscall type wrong");

#ifdef WINDOWS
    /* test Zw variant */
    num.secondary = 4;
    res = drsys_name_to_number("ZwContinue", &num);
    ASSERT(res == DRMF_SUCCESS && num.secondary == 0, "drsys_name_to_number failed");
    /* test not found */
    res = drsys_name_to_number("NtContinueBogus", &num);
    ASSERT(res == DRMF_ERROR_NOT_FOUND, "drsys_name_to_number should have failed");
#else
    /* test not found */
    res = drsys_name_to_number("fstatfr", &num);
    ASSERT(res == DRMF_ERROR_NOT_FOUND, "drsys_name_to_number should have failed");
#endif

    /* test number to name */
    num.number = 0;
    num.secondary = 0;
    res = drsys_number_to_name(num, &name);
    ASSERT(res == DRMF_SUCCESS && name != NULL, "drsys_number_to_name failed");
}

static
void exit_event(void)
{
    if (drsys_exit() != DRMF_SUCCESS)
        ASSERT(false, "drsys failed to exit");
    dr_fprintf(STDERR, "TEST PASSED\n");
    drmgr_exit();
}

DR_EXPORT
void dr_init(client_id_t id)
{
    drsys_options_t ops = { sizeof(ops), 0, };
    drmgr_init();
    if (drsys_init(id, &ops) != DRMF_SUCCESS)
        ASSERT(false, "drsys failed to init");
    dr_register_exit_event(exit_event);

    dr_register_filter_syscall_event(event_filter_syscall);
    drmgr_register_pre_syscall_event(event_pre_syscall);
    drmgr_register_post_syscall_event(event_post_syscall);
    if (drsys_filter_all_syscalls() != DRMF_SUCCESS)
        ASSERT(false, "drsys_filter_all_syscalls should never fail");

    test_static_queries();

    /* XXX: it would be nice to do deeper tests:
     * + drsys_filter_syscall() and have an app that makes both filtered
     *   and unfiltered syscalls
     * + have app make specific syscall w/ specific args and ensure
     *   they match up
     */

    /* XXX: test static iterator once it's implemented.
     * Also test drsys_handle_is_current_process() once we have HANDLE
     * types in the static iterator.
     */
}
