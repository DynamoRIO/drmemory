/* **********************************************************
 * Copyright (c) 2012-2017 Google, Inc.  All rights reserved.
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
#else
# include <sys/types.h>
# include <sys/socket.h>
#endif

#define TEST(mask, var) (((mask) & (var)) != 0)

#undef ASSERT /* we don't want msgbox */
#define ASSERT(cond, msg) \
    ((void)((!(cond)) ? \
     (dr_fprintf(STDERR, "ASSERT FAILURE: %s:%d: %s (%s)", \
                 __FILE__,  __LINE__, #cond, msg), \
      dr_abort(), 0) : 0))

static bool verbose;

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
    ASSERT(mc->IF_ARM_ELSE(r7,xdi) == mc_DR.IF_ARM_ELSE(r7,xdi), "mc check");
    ASSERT(mc->IF_ARM_ELSE(r6,xsi) == mc_DR.IF_ARM_ELSE(r6,xsi), "mc check");
    ASSERT(mc->IF_ARM_ELSE(r5,xbp) == mc_DR.IF_ARM_ELSE(r5,xbp), "mc check");
    ASSERT(mc->IF_ARM_ELSE(r4,xsp) == mc_DR.IF_ARM_ELSE(r4,xsp), "mc check");
    ASSERT(mc->IF_ARM_ELSE(r3,xbx) == mc_DR.IF_ARM_ELSE(r3,xbx), "mc check");
    ASSERT(mc->IF_ARM_ELSE(r2,xdx) == mc_DR.IF_ARM_ELSE(r2,xdx), "mc check");
    ASSERT(mc->IF_ARM_ELSE(r1,xcx) == mc_DR.IF_ARM_ELSE(r1,xcx), "mc check");
    ASSERT(mc->IF_ARM_ELSE(r0,xax) == mc_DR.IF_ARM_ELSE(r0,xax), "mc check");
    ASSERT(mc->xflags == mc_DR.xflags, "mc check");
}

static bool
drsys_iter_memarg_cb(drsys_arg_t *arg, void *user_data)
{
    ASSERT(arg->valid, "no args should be invalid in this app");
    ASSERT(arg->mc != NULL, "mc check");
    ASSERT(arg->drcontext == dr_get_current_drcontext(), "dc check");

#ifdef UNIX
    /* the app deliberately trips i#1119 w/ a too-small sockaddr */
    if (arg->type == DRSYS_TYPE_SOCKADDR && !arg->pre) {
        static bool first = true;
        ASSERT(!first || arg->size == sizeof(struct sockaddr)/2, "i#1119 test");
        first = false;
    }
#endif

    return true; /* keep going */
}

static uint64
truncate_int_to_size(uint64 val, uint size)
{
    if (size == 1)
        val &= 0xff;
    else if (size == 2)
        val &= 0xffff;
    else if (size == 4)
        val &= 0xffffffff;
    return val;
}

static bool
drsys_iter_arg_cb(drsys_arg_t *arg, void *user_data)
{
    ptr_uint_t val;
    uint64 val64;

    ASSERT(arg->valid, "no args should be invalid in this app");
    ASSERT(arg->mc != NULL, "mc check");
    ASSERT(arg->drcontext == dr_get_current_drcontext(), "dc check");

    if (arg->reg == DR_REG_NULL && !TEST(DRSYS_PARAM_RETVAL, arg->mode)) {
        ASSERT((byte *)arg->start_addr >= (byte *)arg->mc->xsp &&
               (byte *)arg->start_addr < (byte *)arg->mc->xsp + PAGE_SIZE,
               "mem args should be on stack");
    }

    if (TEST(DRSYS_PARAM_RETVAL, arg->mode)) {
        ASSERT(arg->pre ||
               arg->value == dr_syscall_get_result(dr_get_current_drcontext()),
               "return val wrong");
    } else {
        if (drsys_pre_syscall_arg(arg->drcontext, arg->ordinal, &val) != DRMF_SUCCESS)
            ASSERT(false, "drsys_pre_syscall_arg failed");
        if (drsys_pre_syscall_arg64(arg->drcontext, arg->ordinal, &val64) != DRMF_SUCCESS)
            ASSERT(false, "drsys_pre_syscall_arg64 failed");
        if (arg->size < sizeof(val)) {
            val = truncate_int_to_size(val, arg->size);
            val64 = truncate_int_to_size(val64, arg->size);
        }
        ASSERT(val == arg->value, "values do not match");
        ASSERT(val64 == arg->value64, "values do not match");
    }

    /* We could test drsys_handle_is_current_process() but we'd have to
     * locate syscalls operating on processes.  Currently drsyscall.c
     * already tests this call.
     */

    return true; /* keep going */
}

static bool
event_pre_syscall(void *drcontext, int sysnum)
{
    drsys_syscall_t *syscall;
    drsys_sysnum_t sysnum_full;
    bool known;
    drsys_param_type_t ret_type;

    if (drsys_cur_syscall(drcontext, &syscall) != DRMF_SUCCESS)
        ASSERT(false, "drsys_cur_syscall failed");
    if (drsys_syscall_number(syscall, &sysnum_full) != DRMF_SUCCESS)
        ASSERT(false, "drsys_get_sysnum failed");
    ASSERT(sysnum == sysnum_full.number, "primary should match DR's num");

    if (verbose) {
        const char *name;
        drmf_status_t res = drsys_syscall_name(syscall, &name);
        ASSERT(res == DRMF_SUCCESS && name != NULL, "drsys_syscall_name failed");
        dr_fprintf(STDERR, "syscall %d.%d = %s\n", sysnum_full.number,
                   sysnum_full.secondary, name);
    }

    check_mcontext(drcontext);

    if (drsys_syscall_return_type(syscall, &ret_type) != DRMF_SUCCESS ||
        ret_type == DRSYS_TYPE_INVALID || ret_type == DRSYS_TYPE_UNKNOWN)
        ASSERT(false, "failed to get syscall return type");

    if (drsys_syscall_is_known(syscall, &known) != DRMF_SUCCESS || !known)
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
    drsys_syscall_t *syscall;
    drsys_sysnum_t sysnum_full;
    bool success = false;
    const char *name;

    if (drsys_cur_syscall(drcontext, &syscall) != DRMF_SUCCESS)
        ASSERT(false, "drsys_cur_syscall failed");
    if (drsys_syscall_number(syscall, &sysnum_full) != DRMF_SUCCESS)
        ASSERT(false, "drsys_get_sysnum failed");
    ASSERT(sysnum == sysnum_full.number, "primary should match DR's num");
    if (drsys_syscall_name(syscall, &name) != DRMF_SUCCESS)
        ASSERT(false, "drsys_syscall_name failed");

    check_mcontext(drcontext);

    if (drsys_iterate_args(drcontext, drsys_iter_arg_cb, NULL) != DRMF_SUCCESS)
        ASSERT(false, "drsys_iterate_args failed");

    if (drsys_cur_syscall_result(drcontext, &success, NULL, NULL) !=
        DRMF_SUCCESS || !success) {
        /* With the new early injector on Linux, we see access, open, + stat64 fail */
#ifdef WINDOWS
        /* On win10, NtQueryValueKey fails */
        ASSERT(strcmp(name, "NtQueryValueKey") == 0,
               "syscalls in this app shouldn't fail");
#endif
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
    drsys_syscall_t *syscall;
    drsys_sysnum_t num = {4,4};
    drmf_status_t res;
    bool known;
    drsys_syscall_type_t type;
    drsys_param_type_t ret_type;
    const char *name = "bogus";

#ifdef WINDOWS
    res = drsys_name_to_syscall("NtContinue", &syscall);
#else
    res = drsys_name_to_syscall("fstatfs", &syscall);
#endif
    ASSERT(res == DRMF_SUCCESS, "drsys_name_to_syscall failed");
    res = drsys_syscall_number(syscall, &num);
    ASSERT(res == DRMF_SUCCESS && num.secondary == 0, "drsys_syscall_number failed");
    if (drsys_syscall_is_known(syscall, &known) != DRMF_SUCCESS || !known)
        ASSERT(false, "syscall should be known");
    if (drsys_syscall_type(syscall, &type) != DRMF_SUCCESS ||
        type != DRSYS_SYSCALL_TYPE_KERNEL)
        ASSERT(false, "syscall type wrong");
    if (drsys_syscall_return_type(syscall, &ret_type) != DRMF_SUCCESS ||
        ret_type == DRSYS_TYPE_INVALID || ret_type == DRSYS_TYPE_UNKNOWN)
        ASSERT(false, "failed to get syscall return type");

#ifdef WINDOWS
    /* test Zw variant */
    num.secondary = 4;
    if (drsys_name_to_syscall("ZwContinue", &syscall) != DRMF_SUCCESS)
        ASSERT(false, "drsys_name_to_syscall failed");
    res = drsys_syscall_number(syscall, &num);
    ASSERT(res == DRMF_SUCCESS && num.secondary == 0, "drsys_name_to_syscall failed");
    /* test not found */
    res = drsys_name_to_syscall("NtContinueBogus", &syscall);
    ASSERT(res == DRMF_ERROR_NOT_FOUND, "drsys_name_to_syscall should have failed");
    /* test secondary */
    if (drsys_name_to_syscall("NtUserCallOneParam.MESSAGEBEEP", &syscall) != DRMF_SUCCESS)
        ASSERT(false, "drsys_name_to_syscall failed");
    res = drsys_syscall_number(syscall, &num);
    ASSERT(res == DRMF_SUCCESS && num.secondary > 0, "drsys_syscall_number failed");
    if (drsys_name_to_syscall("MESSAGEBEEP", &syscall) != DRMF_SUCCESS)
        ASSERT(false, "drsys_name_to_syscall failed");
    res = drsys_syscall_number(syscall, &num);
    ASSERT(res == DRMF_SUCCESS && num.secondary > 0, "drsys_syscall_number failed");
#else
    /* test not found */
    res = drsys_name_to_syscall("fstatfr", &syscall);
    ASSERT(res == DRMF_ERROR_NOT_FOUND, "drsys_name_to_syscall should have failed");
#endif

    /* Test number to name.
     * i#1692/i#1669: We choose syscall 16 because on WOW64 syscall 0 has some upper
     * bits set, and other low numbers are not present on various platforms.
     */
    num.number = 16;
    num.secondary = 0;
    if (drsys_number_to_syscall(num, &syscall) != DRMF_SUCCESS)
        ASSERT(false, "drsys_number_to_syscall failed");
    res = drsys_syscall_name(syscall, &name);
    ASSERT(res == DRMF_SUCCESS && name != NULL, "drsys_syscall_name failed");

#ifdef WINDOWS
    /* test secondary number to name, in particular where secondary==0 */
    if (drsys_name_to_syscall("NtUserCallNoParam.CREATEMENU", &syscall) != DRMF_SUCCESS)
        ASSERT(false, "drsys_name_to_syscall failed");
    res = drsys_syscall_number(syscall, &num);
    ASSERT(res == DRMF_SUCCESS && num.secondary == 0, "drsys_syscall_number failed");
    if (drsys_number_to_syscall(num, &syscall) != DRMF_SUCCESS)
        ASSERT(false, "drsys_number_to_syscall failed");
    res = drsys_syscall_name(syscall, &name);
    ASSERT(res == DRMF_SUCCESS && strcmp(name, "NtUserCallNoParam.CREATEMENU") == 0,
           "drsys_syscall_name failed");
#endif
}

static bool
static_iter_arg_cb(drsys_arg_t *arg, void *user_data)
{
    ASSERT(!arg->valid, "no arg vals should be valid statically");
    ASSERT(arg->mc == NULL, "mc should be invalid");
    ASSERT(arg->drcontext == dr_get_current_drcontext(), "dc check");

    return true; /* keep going */
}

static bool
static_iter_cb(drsys_sysnum_t num, drsys_syscall_t *syscall, void *user_data)
{
    const char *name;
    drmf_status_t res = drsys_syscall_name(syscall, &name);
    ASSERT(res == DRMF_SUCCESS && name != NULL, "drsys_syscall_name failed");

    if (verbose) {
        dr_fprintf(STDERR, "static syscall %d.%d = %s\n", num.number, num.secondary,
                   name);
    }

    if (drsys_iterate_arg_types(syscall, static_iter_arg_cb, NULL) !=
        DRMF_SUCCESS)
        ASSERT(false, "drsys_iterate_arg_types failed");
    return true; /* keep going */
}

static void
test_static_iterator(void)
{
    if (drsys_iterate_syscalls(static_iter_cb, NULL) != DRMF_SUCCESS)
        ASSERT(false, "drsys_iterate_syscalls failed");
}

static void
exit_event(void)
{
    drsys_gateway_t gateway;
    if (drsys_syscall_gateway(&gateway) != DRMF_SUCCESS ||
        gateway == DRSYS_GATEWAY_UNKNOWN)
        ASSERT(false, "drsys failed to determine syscall gateway");
    if (drsys_exit() != DRMF_SUCCESS)
        ASSERT(false, "drsys failed to exit");
    dr_fprintf(STDERR, "TEST PASSED\n");
    drmgr_exit();
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
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

    test_static_iterator();

    /* XXX: it would be nice to do deeper tests:
     * + drsys_filter_syscall() and have an app that makes both filtered
     *   and unfiltered syscalls
     * + have app make specific syscall w/ specific args and ensure
     *   they match up
     */
}
