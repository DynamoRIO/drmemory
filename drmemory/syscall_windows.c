/* **********************************************************
 * Copyright (c) 2011-2012 Google, Inc.  All rights reserved.
 * Copyright (c) 2007-2010 VMware, Inc.  All rights reserved.
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

#include "dr_api.h"
#include "drmemory.h"
#include "syscall.h"
#include "syscall_os.h"
#include "syscall_windows.h"
#include "readwrite.h"
#include "frontend.h"
#include <stddef.h> /* offsetof */
#include "handlecheck.h"
#include "drsyscall.h"

#include "../wininc/ndk_dbgktypes.h"
#include "../wininc/ndk_iotypes.h"
#include "../wininc/ndk_extypes.h"
#include "../wininc/afd_shared.h"
#include "../wininc/msafdlib.h"
#include "../wininc/winioctl.h"
#include "../wininc/tcpioctl.h"
#include "../wininc/iptypes_undocumented.h"
#include "../wininc/ntalpctyp.h"

static int
syscall_handle_type(drsys_syscall_type_t drsys_type);

/***************************************************************************
 * SYSTEM CALLS FOR WINDOWS
 */

/* Syscalls that need special processing.  The address of each is kept
 * in the syscall_info_t entry so we don't need separate lookup.
 */
static drsys_sysnum_t sysnum_CreateThread = {-1,0};
static drsys_sysnum_t sysnum_CreateThreadEx = {-1,0};
static drsys_sysnum_t sysnum_TerminateProcess = {-1,0};

/* For handle leak checking */
static drsys_sysnum_t sysnum_Close = {-1,0};
static drsys_sysnum_t sysnum_UserDestroyAcceleratorTable = {-1,0};
static drsys_sysnum_t sysnum_UserDestroyCursor = {-1,0};
static drsys_sysnum_t sysnum_UserDestroyInputContext = {-1,0};
static drsys_sysnum_t sysnum_UserDestroyMenu = {-1,0};
static drsys_sysnum_t sysnum_UserDestroyWindow = {-1,0};
static drsys_sysnum_t sysnum_UserCallOneParam_RELEASEDC = {-1,0};
static drsys_sysnum_t sysnum_GdiDeleteObjectApp = {-1,0};

static bool
opc_is_in_syscall_wrapper(uint opc)
{
    return (opc == OP_mov_imm || opc == OP_lea || opc == OP_xor /*wow64*/ ||
            opc == OP_int || opc == OP_call_ind ||
            /* 64-bit Windows:
             * ntdll!NtMapViewOfSection:
             * 77941590 4c8bd1          mov     r10,rcx
             * 77941593 b825000000      mov     eax,25h
             * 77941598 0f05            syscall
             */
            IF_X64(opc == OP_mov_ld ||)
            /* w/ DR Ki hooks before dr_init we have to walk over the
             * native_exec_syscall hooks */
            opc == OP_jmp);
}

/* takes in any Nt syscall wrapper entry point */
byte *
vsyscall_pc(void *drcontext, byte *entry)
{
    byte *vpc = NULL;
    byte *pc = entry;
    uint opc;
    instr_t instr;
    ASSERT(entry != NULL, "invalid entry");
    instr_init(drcontext, &instr);
    do {
        instr_reset(drcontext, &instr);
        pc = decode(drcontext, pc, &instr);
        ASSERT(instr_valid(&instr), "unknown system call sequence");
        opc = instr_get_opcode(&instr);
        ASSERT(opc_is_in_syscall_wrapper(opc), "unknown system call sequence");
        /* safety check: should only get 11 or 12 bytes in */
        if (pc - entry > 20) {
            ASSERT(false, "unknown system call sequence");
            instr_free(drcontext, &instr);
            return NULL;
        }
        if (opc == OP_mov_imm && opnd_is_reg(instr_get_dst(&instr, 0)) &&
            opnd_get_reg(instr_get_dst(&instr, 0)) == REG_EDX) {
            ASSERT(opnd_is_immed_int(instr_get_src(&instr, 0)), "internal error");
            vpc = (byte *) opnd_get_immed_int(instr_get_src(&instr, 0));
        }
        /* stop at call to vsyscall or at int itself */
    } while (opc != OP_call_ind && opc != OP_int);
    /* vpc should only exist if have call* */
    ASSERT(vpc == NULL || opc == OP_call_ind, "internal error");
    instr_free(drcontext, &instr);
    return vpc;
}

void
syscall_os_init(void *drcontext, app_pc ntdll_base)
{
    get_sysnum("NtCreateThread", &sysnum_CreateThread, false/*reqd*/);
    get_sysnum("NtCreateThreadEx", &sysnum_CreateThreadEx, true/*added in vista*/);
    get_sysnum("NtTerminateProcess", &sysnum_TerminateProcess, false/*reqd*/);
    get_sysnum("NtClose", &sysnum_Close, false/*reqd*/);
    get_sysnum("NtUserDestroyAcceleratorTable", &sysnum_UserDestroyAcceleratorTable,
               false/*reqd*/);
    get_sysnum("NtUserDestroyCursor", &sysnum_UserDestroyCursor, false/*reqd*/);
    get_sysnum("NtUserDestroyInputContext", &sysnum_UserDestroyInputContext,
               false/*reqd*/);
    get_sysnum("NtUserDestroyMenu", &sysnum_UserDestroyMenu, false/*reqd*/);
    get_sysnum("NtUserDestroyWindow", &sysnum_UserDestroyWindow, false/*reqd*/);
    get_sysnum("NtUserCallOneParam.RELEASEDC", &sysnum_UserCallOneParam_RELEASEDC,
               false/*reqd*/);
    get_sysnum("NtGdiDeleteObjectApp", &sysnum_GdiDeleteObjectApp, false/*reqd*/);

    syscall_wingdi_init(drcontext, ntdll_base);

    if (options.check_handle_leaks)
        handlecheck_init();
}

void
syscall_os_exit(void)
{
    /* must be called before systable delete */
    if (options.check_handle_leaks)
        handlecheck_exit();
    syscall_wingdi_exit();
}

void
syscall_os_thread_init(void *drcontext)
{
    syscall_wingdi_thread_init(drcontext);
}

void
syscall_os_thread_exit(void *drcontext)
{
    syscall_wingdi_thread_exit(drcontext);
}

void
syscall_os_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
}

static void
handle_post_CreateThread(void *drcontext, drsys_sysnum_t sysnum, cls_syscall_t *pt,
                         dr_mcontext_t *mc)
{
    if (options.shadowing && NT_SUCCESS(dr_syscall_get_result(drcontext))) {
        /* Even on XP+ where csrss frees the stack, the stack alloc happens
         * in-process and we see it.  The TEB alloc, however, is done by
         * the kernel, and kernel32!CreateRemoteThread writes to the TEB
         * prior to the thread resuming, so we handle it here.
         * We also process the TEB in set_thread_initial_structures() in
         * case someone creates a thread remotely, or in-process but custom
         * so it's not suspended at this point.
         */
        HANDLE thread_handle;
        /* If not suspended, let set_thread_initial_structures() handle it to
         * avoid races: though since setting as defined the only race would be
         * the thread exiting
         */
        if (syscall_get_param(drcontext, 7)/*bool suspended*/ &&
            is_current_process((HANDLE)syscall_get_param(drcontext, 3)) &&
            safe_read((byte *)syscall_get_param(drcontext, 0), sizeof(thread_handle),
                      &thread_handle)) {
            TEB *teb = get_TEB_from_handle(thread_handle);
            LOG(1, "TEB for new thread: "PFX"\n", teb);
            set_teb_initial_shadow(teb);
        }
    }
}

static void
handle_post_CreateThreadEx(void *drcontext, drsys_sysnum_t sysnum, cls_syscall_t *pt,
                           dr_mcontext_t *mc)
{
    if (options.shadowing &&
        is_current_process((HANDLE)syscall_get_param(drcontext, 3)) &&
        NT_SUCCESS(dr_syscall_get_result(drcontext))) {
        HANDLE thread_handle;
        create_thread_info_t info;
        /* See notes in handle_post_CreateThread() */
        if (syscall_get_param(drcontext, 6)/*bool suspended*/ &&
            safe_read((byte *)syscall_get_param(drcontext, 0), sizeof(thread_handle),
                      &thread_handle)) {
            TEB *teb = get_TEB_from_handle(thread_handle);
            LOG(1, "TEB for new thread: "PFX"\n", teb);
            set_teb_initial_shadow(teb);
        }
    }
}

static bool
post_syscall_iter_arg_cb(drsys_arg_t *arg, void *user_data)
{
    if (options.check_handle_leaks && !arg->pre && arg->type == DRSYS_TYPE_HANDLE) {
        drsys_syscall_type_t syscall_type = DRSYS_SYSCALL_TYPE_KERNEL;
        if (drsys_syscall_type(arg->syscall, &syscall_type) != DRMF_SUCCESS)
            WARN("WARNING: failed to get syscall type\n");
        if (arg->mode == DRSYS_PARAM_OUT) {
            HANDLE handle;
            if (safe_read((void *)arg->value, sizeof(HANDLE), &handle)) {
                /* assuming any handle arg written by the syscall
                 * is newly created.
                 */
                handlecheck_create_handle(arg->drcontext, handle,
                                          syscall_handle_type(syscall_type),
                                          arg->sysnum, NULL, arg->mc);
            } else {
                DODEBUG({
                    const char *sysname = "<unknown>";
                    drsys_syscall_name(arg->syscall, &sysname);
                    LOG(SYSCALL_VERBOSE,
                        "fail to read handle from syscall %x.%x %s",
                        arg->sysnum.number, arg->sysnum.secondary, sysname);
                });
            }
        } else if (arg->mode == DRSYS_PARAM_RETVAL) {
            /* handle is in return which we assume is newly created */
            handlecheck_create_handle(arg->drcontext, (HANDLE)arg->value,
                                      syscall_handle_type(syscall_type),
                                      arg->sysnum, NULL, arg->mc);

        }
    }
    return true; /* keep going */
}

static bool
syscall_deletes_handle(drsys_sysnum_t sysnum)
{
    return (drsys_sysnums_equal(&sysnum, &sysnum_Close) ||
            drsys_sysnums_equal(&sysnum, &sysnum_UserDestroyAcceleratorTable) ||
            drsys_sysnums_equal(&sysnum, &sysnum_UserDestroyCursor) ||
            drsys_sysnums_equal(&sysnum, &sysnum_UserDestroyInputContext) ||
            drsys_sysnums_equal(&sysnum, &sysnum_UserDestroyMenu) ||
            drsys_sysnums_equal(&sysnum, &sysnum_UserDestroyWindow) ||
            drsys_sysnums_equal(&sysnum, &sysnum_UserCallOneParam_RELEASEDC) ||
            drsys_sysnums_equal(&sysnum, &sysnum_GdiDeleteObjectApp));
}

bool
os_shared_pre_syscall(void *drcontext, cls_syscall_t *pt, drsys_sysnum_t sysnum,
                      dr_mcontext_t *mc, drsys_syscall_t *syscall)
{
    /* i#544: give child processes a chance for clean exit for leak scan
     * and option summary and symbol and code cache generation.
     *
     * XXX: a child under DR but not DrMem will be left alive: but that's
     * a risk we can live with.
     */
    if (drsys_sysnums_equal(&sysnum, &sysnum_TerminateProcess) && options.soft_kills) {
        HANDLE proc = (HANDLE) syscall_get_param(drcontext, 0);
        process_id_t pid = dr_convert_handle_to_pid(proc);
        if (pid != INVALID_PROCESS_ID && pid != dr_get_process_id()) {
            dr_config_status_t res =
                dr_nudge_client_ex(pid, client_id, NUDGE_TERMINATE,
                                   /*preserve exit code*/syscall_get_param(drcontext, 1));
            LOG(1, "TerminateProcess => nudge pid=%d res=%d\n", pid, res);
            if (res == DR_SUCCESS) {
                /* skip syscall since target will terminate itself */
                dr_syscall_set_result(drcontext, 0/*success*/);
                return false;
            }
            /* else failed b/c target not under DR control or maybe some other error:
             * let syscall go through
             */
        }
    }
    if (options.check_handle_leaks) {
        if (syscall_deletes_handle(sysnum)) {
            /* assuming the handle to be deleted is at the first arg */
            /* i#974: multiple threads may create/delete handles in parallel,
             * so we remove the handle from table at pre-syscall by simply
             * assuming the syscall will success, and add it back if fail.
             */
            drsys_syscall_type_t syscall_type = DRSYS_SYSCALL_TYPE_KERNEL;
            if (drsys_syscall_type(syscall, &syscall_type) != DRMF_SUCCESS)
                WARN("WARNING: failed to get syscall type\n");
            pt->handle_info =
                handlecheck_delete_handle(drcontext,
                                          (HANDLE)syscall_get_param(drcontext, 0),
                                          syscall_handle_type(syscall_type),
                                          sysnum, NULL, mc);
        }
    }
    return wingdi_shared_process_syscall(true/*pre*/, drcontext, sysnum, pt, mc, syscall);
}

void
os_shared_post_syscall(void *drcontext, cls_syscall_t *pt, drsys_sysnum_t sysnum,
                       dr_mcontext_t *mc, drsys_syscall_t *syscall)
{
    /* FIXME PR 456501: watch CreateProcess, CreateProcessEx, and
     * CreateUserProcess.  Convert process handle to pid and section
     * handle to file path, and write both as a FORKEXEC line in
     * f_fork.
     */
    if (drsys_sysnums_equal(&sysnum, &sysnum_CreateThread) ||
        drsys_sysnums_equal(&sysnum, &sysnum_CreateThreadEx)) {
        if (NT_SUCCESS(dr_syscall_get_result(drcontext)) &&
            is_current_process((HANDLE)syscall_get_param(drcontext, 3)/*3rd for both*/)) {
            HANDLE thread_handle;
            thread_id_t child = INVALID_THREAD_ID;
            if (safe_read((byte *)syscall_get_param(drcontext, 0), sizeof(thread_handle),
                          &thread_handle))
                child = get_tid_from_handle(thread_handle);
            if (child != INVALID_THREAD_ID)
                report_child_thread(drcontext, child);
            else
                WARN("WARNING: unable to determine child thread it\n");
        }
        if (drsys_sysnums_equal(&sysnum, &sysnum_CreateThread))
            handle_post_CreateThread(drcontext, sysnum, pt, mc);
        else if (drsys_sysnums_equal(&sysnum, &sysnum_CreateThreadEx))
            handle_post_CreateThreadEx(drcontext, sysnum, pt, mc);
    }
    /* for handle leak checks */
    if (options.check_handle_leaks) {
        reg_t res = dr_syscall_get_result(drcontext);
        drsys_syscall_type_t syscall_type = DRSYS_SYSCALL_TYPE_KERNEL;
        bool success = false;
        if (drsys_syscall_succeeded(syscall, res, &success) != DRMF_SUCCESS)
            WARN("WARNING: failed to get syscall success\n");
        if (drsys_syscall_type(syscall, &syscall_type) != DRMF_SUCCESS)
            WARN("WARNING: failed to get syscall type\n");
        if (syscall_deletes_handle(sysnum)) {
            /* XXX: really we should iterate the args and look for the handle,
             * but for now I'm keeping the prior code that assumes 1st param.
             */
            handlecheck_delete_handle_post_syscall
                (drcontext, (HANDLE)syscall_get_param(drcontext, 0),
                 syscall_handle_type(syscall_type), pt->handle_info, success);
            pt->handle_info = NULL;
        }
        /* find the OUT params, including return value */
        if (drsys_iterate_args(drcontext, post_syscall_iter_arg_cb, NULL) != DRMF_SUCCESS)
            LOG(1, "unknown system call args for #%d\n", sysnum.number);
    }
    wingdi_shared_process_syscall(false/*!pre*/, drcontext, sysnum, pt, mc, syscall);
}

bool
os_process_syscall_memarg(drsys_arg_t *arg)
{
    return wingdi_process_syscall_arg(arg);
}

/***************************************************************************
 * handle check related system call routines
 */

static int
syscall_handle_type(drsys_syscall_type_t drsys_type)
{
    if (drsys_type == DRSYS_SYSCALL_TYPE_USER)
        return HANDLE_TYPE_USER;
    else if (drsys_type == DRSYS_SYSCALL_TYPE_GRAPHICS)
        return HANDLE_TYPE_GDI;
    else
        return HANDLE_TYPE_KERNEL;
}

