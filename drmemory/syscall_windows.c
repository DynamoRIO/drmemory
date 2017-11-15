/* **********************************************************
 * Copyright (c) 2011-2017 Google, Inc.  All rights reserved.
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
#include "slowpath.h"
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
syscall_handle_type(drsys_syscall_type_t drsys_type, drsys_sysnum_t sysnum);

/***************************************************************************
 * SYSTEM CALLS FOR WINDOWS
 */

/* Syscalls that need special processing.  The address of each is kept
 * in the syscall_info_t entry so we don't need separate lookup.
 */
static drsys_sysnum_t sysnum_CreateThread = {-1,0};
static drsys_sysnum_t sysnum_CreateThreadEx = {-1,0};

/* For handle leak checking */
static drsys_sysnum_t sysnum_Close = {-1,0};
static drsys_sysnum_t sysnum_UserDestroyAcceleratorTable = {-1,0};
static drsys_sysnum_t sysnum_UserDestroyCursor = {-1,0};
static drsys_sysnum_t sysnum_UserDestroyInputContext = {-1,0};
static drsys_sysnum_t sysnum_UserDestroyMenu = {-1,0};
static drsys_sysnum_t sysnum_UserDestroyWindow = {-1,0};
static drsys_sysnum_t sysnum_UserReleaseDC = {-1,0};
static drsys_sysnum_t sysnum_GdiDeleteObjectApp = {-1,0};
static drsys_sysnum_t sysnum_GdiDeleteColorSpace = {-1,0};
static drsys_sysnum_t sysnum_GdiDeleteColorTransform = {-1,0};
static drsys_sysnum_t sysnum_GdiDeleteClientObj = {-1,0};
static drsys_sysnum_t sysnum_GdiDdReleaseDC= {-1, 0};
/* i#1112: NtDuplicateObject may delete a handle */
static drsys_sysnum_t sysnum_DuplicateObject = {-1, 0};
/* i#988: system calls that return existing handles */
static drsys_sysnum_t sysnum_UserSetClipboardData = {-1, 0};
static drsys_sysnum_t sysnum_UserRemoveProp = {-1, 0};
static drsys_sysnum_t sysnum_UserFindExistingCursorIcon = {-1, 0};
static drsys_sysnum_t sysnum_UserGetThreadDesktop = {-1, 0};
static drsys_sysnum_t sysnum_GetThreadDesktop = {-1, 0}; /* i#487 */
static drsys_sysnum_t sysnum_UserGetAncestor = {-1, 0};
static drsys_sysnum_t sysnum_GdiExtSelectClipRgn = {-1, 0};
static drsys_sysnum_t sysnum_GdiSelectBrush = {-1, 0};
static drsys_sysnum_t sysnum_GdiSelectPen = {-1, 0};
static drsys_sysnum_t sysnum_GdiSelectBitmap = {-1, 0};
static drsys_sysnum_t sysnum_GdiSelectFont = {-1, 0};
/* i#1386: mismatch between system call type and handle type */
/* syscall added above:
 * sysnum_UserReleaseDC
 * sysnum_UserGetThreadDesktop
 */
/* To support handle usage check in the future, we may want to record
 * the type information of an handle used as a syscall argument,
 * e.g., the user syscall NtUserCloseWindowStation takes in kernel handle.
 */
static drsys_sysnum_t sysnum_UserGetDC = {-1, 0};
static drsys_sysnum_t sysnum_UserGetProcessWindowStation = {-1, 0};
static drsys_sysnum_t sysnum_UserCreateWindowStation = {-1, 0};
static drsys_sysnum_t sysnum_UserOpenWindowStation = {-1, 0};
static drsys_sysnum_t sysnum_UserCloseWindowStation = {-1, 0};
static drsys_sysnum_t sysnum_UserGetWindowDC = {-1, 0};
static drsys_sysnum_t sysnum_UserCloseDesktop = {-1, 0};
static drsys_sysnum_t sysnum_UserCreateDesktop = {-1, 0};
static drsys_sysnum_t sysnum_UserCreateDesktopEx = {-1, 0};
static drsys_sysnum_t sysnum_UserOpenDesktop = {-1, 0};
static drsys_sysnum_t sysnum_UserOpenInputDesktop = {-1, 0};
static drsys_sysnum_t sysnum_UserOpenThreadDesktop = {-1, 0};

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
            /* 64-bit Windows 10 TH2 has a jne:
             * 00007ff8`34e763c8 f604250803fe7f01 test    byte ptr [SharedUserData+0x308 (00000000`7ffe0308)],1
             * 00007ff8`34e763d0 7503            jne     ntdll!NtAllocateVirtualMemory+0x15 (00007ff8`34e763d5)
             * 00007ff8`34e763d2 0f05            syscall
             * 00007ff8`34e763d4 c3              ret
             * 00007ff8`34e763d5 cd2e            int     2Eh
             * 00007ff8`34e763d7 c3              ret
             */
            IF_X64(opc == OP_mov_ld || opc == OP_test || opc == OP_jne_short ||)
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
        /* stop at call to vsyscall, at syscall instruction itself,
         * or at Windows8+ co-located sysenter callee (i#1367)
         */
        if (opc == OP_call_ind || opc == OP_call || instr_is_syscall(&instr))
            break;
        ASSERT(opc_is_in_syscall_wrapper(opc), "unknown system call sequence");
        /* safety check: should only get 11 or 12 bytes in */
        if (pc - entry > 20) {
            ASSERT(false, "unknown system call sequence");
            instr_free(drcontext, &instr);
            return NULL;
        }
        if (opc == OP_mov_imm && opnd_is_reg(instr_get_dst(&instr, 0)) &&
            opnd_get_reg(instr_get_dst(&instr, 0)) == REG_EDX &&
            /* win10 wow64 also has call* edx: exclude it */
            !is_wow64_process()) {
            ASSERT(opnd_is_immed_int(instr_get_src(&instr, 0)), "internal error");
            vpc = (byte *) opnd_get_immed_int(instr_get_src(&instr, 0));
        }
        /* stop at call to vsyscall or at int/sysenter/syscall itself */
    } while (true);
    /* vpc should only exist if have call* */
    ASSERT(vpc == NULL || opc == OP_call_ind, "internal error");
    instr_free(drcontext, &instr);
    return vpc;
}

void
syscall_os_init(void *drcontext, app_pc ntdll_base)
{
    get_sysnum("NtCreateThread", &sysnum_CreateThread, false/*reqd*/);
    get_sysnum("NtCreateThreadEx", &sysnum_CreateThreadEx,
               get_windows_version() <= DR_WINDOWS_VERSION_2003);
    get_sysnum("NtClose", &sysnum_Close, false/*reqd*/);
    get_sysnum("NtUserDestroyAcceleratorTable",
               &sysnum_UserDestroyAcceleratorTable,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    get_sysnum("NtUserDestroyCursor", &sysnum_UserDestroyCursor,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    get_sysnum("NtUserDestroyInputContext", &sysnum_UserDestroyInputContext,
               false/*reqd*/);
    get_sysnum("NtUserDestroyMenu", &sysnum_UserDestroyMenu, false/*reqd*/);
    get_sysnum("NtUserDestroyWindow", &sysnum_UserDestroyWindow, false/*reqd*/);
    if (!get_sysnum("NtUserCallOneParam.RELEASEDC",
                    &sysnum_UserReleaseDC,
                    get_windows_version() <= DR_WINDOWS_VERSION_2000 ||
                    get_windows_version() > DR_WINDOWS_VERSION_10_1703)) {
        get_sysnum("NtUserReleaseDC", &sysnum_UserReleaseDC,
                   get_windows_version() <= DR_WINDOWS_VERSION_10_1703);
    }
    get_sysnum("NtGdiDeleteObjectApp", &sysnum_GdiDeleteObjectApp,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    get_sysnum("NtGdiDeleteColorSpace", &sysnum_GdiDeleteColorSpace,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    get_sysnum("NtGdiDeleteColorTransform", &sysnum_GdiDeleteColorTransform,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    get_sysnum("NtGdiDeleteClientObj", &sysnum_GdiDeleteClientObj,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    get_sysnum("NtGdiDdReleaseDC", &sysnum_GdiDdReleaseDC,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    get_sysnum("NtDuplicateObject", &sysnum_DuplicateObject, false/*reqd*/);
    /* i#988: system calls that return existing handles */
    get_sysnum("NtUserSetClipboardData", &sysnum_UserSetClipboardData,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    get_sysnum("NtUserRemoveProp", &sysnum_UserRemoveProp,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    get_sysnum("NtUserFindExistingCursorIcon",
               &sysnum_UserFindExistingCursorIcon,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    get_sysnum("NtUserGetThreadDesktop", &sysnum_UserGetThreadDesktop,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    get_sysnum("GetThreadDesktop", &sysnum_GetThreadDesktop, true/*ok to fail*/);
    get_sysnum("NtUserGetAncestor", &sysnum_UserGetAncestor, false/*reqd*/);
    get_sysnum("NtGdiExtSelectClipRgn", &sysnum_GdiExtSelectClipRgn,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    get_sysnum("NtGdiSelectBrush", &sysnum_GdiSelectBrush, true/*ok to fail*/);
    get_sysnum("NtGdiSelectPen", &sysnum_GdiSelectPen,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    get_sysnum("NtGdiSelectBitmap", &sysnum_GdiSelectBitmap,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    get_sysnum("NtGdiSelectFont", &sysnum_GdiSelectFont,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    /* i#1386: mismatch between system call type and handle type */
    get_sysnum("NtUserGetDC", &sysnum_UserGetDC, false/*reqd*/);
    get_sysnum("NtUserGetProcessWindowStation", &sysnum_UserGetProcessWindowStation,
               false/*reqd*/);
    get_sysnum("NtUserCreateWindowStation", &sysnum_UserCreateWindowStation,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    get_sysnum("NtUserOpenWindowStation", &sysnum_UserOpenWindowStation,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    get_sysnum("NtUserCloseWindowStation", &sysnum_UserCloseWindowStation,
               false/*reqd*/);
    get_sysnum("NtUserGetWindowDC", &sysnum_UserGetWindowDC, false/*reqd*/);
    get_sysnum("NtUserCloseDesktop", &sysnum_UserCloseDesktop, false/*reqd*/);
    get_sysnum("NtUserCreateDesktop", &sysnum_UserCreateDesktop,
               true/*ok to fail*/);
    get_sysnum("NtUserCreateDesktopEx", &sysnum_UserCreateDesktopEx,
               true/*ok to fail*/);
    get_sysnum("NtUserOpenDesktop", &sysnum_UserOpenDesktop,
               get_windows_version() <= DR_WINDOWS_VERSION_2000);
    get_sysnum("NtUserOpenInputDesktop", &sysnum_UserOpenInputDesktop,
               false/*reqd*/);
    get_sysnum("NtUserOpenThreadDesktop", &sysnum_UserOpenThreadDesktop,
               true/*ok to faile*/);

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
syscall_could_leak_handle(drsys_sysnum_t sysnum)
{
    if (drsys_sysnums_equal(&sysnum, &sysnum_DuplicateObject))
        return true;
    return false;
}

static HANDLE
syscall_get_src_proc_handle(void *drcontext, drsys_sysnum_t sysnum)
{
    if (drsys_sysnums_equal(&sysnum, &sysnum_DuplicateObject))
        return (HANDLE) syscall_get_param(drcontext, 0);
    return NT_CURRENT_PROCESS;
}

static HANDLE
syscall_get_tgt_proc_handle(void *drcontext, drsys_sysnum_t sysnum)
{
    if (drsys_sysnums_equal(&sysnum, &sysnum_DuplicateObject))
        return (HANDLE) syscall_get_param(drcontext, 2);
    return NT_CURRENT_PROCESS;
}

/* This is only called from os_shared_post_syscall with check_handle_leaks
 * on successful system calls.
 * If we add any arg iteration w/o check_handle_leaks or failed system call,
 * we must change os_shared_post_syscall too.
 */
static bool
post_syscall_iter_arg_cb(drsys_arg_t *arg, void *user_data)
{
    ASSERT(!arg->pre, "we only iterate on post-syscall");
    if (options.check_handle_leaks && arg->type == DRSYS_TYPE_HANDLE) {
        drsys_syscall_type_t syscall_type = DRSYS_SYSCALL_TYPE_KERNEL;
        if (drsys_syscall_type(arg->syscall, &syscall_type) != DRMF_SUCCESS)
            WARN("WARNING: failed to get syscall type\n");
        if (arg->mode == DRSYS_PARAM_OUT) {
            HANDLE handle;
            if (arg->value == (ptr_uint_t)NULL &&
                syscall_could_leak_handle(arg->sysnum)) {
                handlecheck_report_leak_on_syscall
                    ((dr_mcontext_t *)user_data, arg,
                     syscall_get_tgt_proc_handle(arg->drcontext, arg->sysnum));
            } else if (safe_read((void *)arg->value, sizeof(HANDLE), &handle)) {
                /* assuming any handle arg written by the syscall
                 * is newly created.
                 */
                handlecheck_create_handle
                    (arg->drcontext,
                     syscall_get_tgt_proc_handle(arg->drcontext, arg->sysnum),
                     handle,
                     syscall_handle_type(syscall_type, arg->sysnum),
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
        } else if (TEST(DRSYS_PARAM_RETVAL, arg->mode)) {
            /* i#988-c#7,c#8: handle in return may not be newly created,
             * in which case, we won't iterate the args.
             */
            handlecheck_create_handle
                (arg->drcontext,
                 syscall_get_tgt_proc_handle(arg->drcontext, arg->sysnum),
                 (HANDLE)arg->value,
                 syscall_handle_type(syscall_type, arg->sysnum),
                 arg->sysnum, NULL, arg->mc);

        }
    }
    return true; /* keep going */
}

/* i#1112: DuplicateHandle can close a handle created by DuplicateHandle by
 * setting the following parameters:
 * - Set arg0 hSourceProcessHandle to the target process from the
 *   DuplicateHandle call that created the handle.
 * - Set arg1 hSourceHandle to the duplicated handle to close.
 * - Set arg3 lpTargetHandle to NULL.
 * - Set arg6 dwOptions to DUPLICATE_CLOSE_SOURCE.
 * here we check arg6 to see if the syscall closes the handle.
 */
static bool
syscall_duplicate_handle_deletes_handle(void *drcontext,
                                        drsys_sysnum_t sysnum)
{
    ptr_uint_t arg6;
    ASSERT(drsys_sysnums_equal(&sysnum, &sysnum_DuplicateObject),
           "syscall is not NtDuplicateObject");
    if (drsys_pre_syscall_arg(drcontext, 6, &arg6) == DRMF_SUCCESS &&
        TEST(DUPLICATE_CLOSE_SOURCE, arg6))
        return true;
    return false;
}

/* Checks whether a syscall deletes a handle.
 * Returns which arg holds the handle for deletion.
 * Returns -1 if the syscall does not delete a handle.
 * It must be called from pre/post syscall event where syscall
 * arguments are available for query.
 */
static int
syscall_deletes_handle(void *drcontext, drsys_sysnum_t sysnum)
{
    if (drsys_sysnums_equal(&sysnum, &sysnum_Close) ||
        drsys_sysnums_equal(&sysnum, &sysnum_UserDestroyAcceleratorTable) ||
        drsys_sysnums_equal(&sysnum, &sysnum_UserDestroyCursor) ||
        drsys_sysnums_equal(&sysnum, &sysnum_UserDestroyInputContext) ||
        drsys_sysnums_equal(&sysnum, &sysnum_UserDestroyMenu) ||
        drsys_sysnums_equal(&sysnum, &sysnum_UserDestroyWindow) ||
        drsys_sysnums_equal(&sysnum, &sysnum_UserReleaseDC) ||
        drsys_sysnums_equal(&sysnum, &sysnum_UserCloseDesktop) ||
        drsys_sysnums_equal(&sysnum, &sysnum_UserCloseWindowStation) ||
        drsys_sysnums_equal(&sysnum, &sysnum_GdiDeleteObjectApp) ||
        drsys_sysnums_equal(&sysnum, &sysnum_GdiDeleteColorSpace) ||
        drsys_sysnums_equal(&sysnum, &sysnum_GdiDeleteColorTransform) ||
        drsys_sysnums_equal(&sysnum, &sysnum_GdiDeleteClientObj) ||
        drsys_sysnums_equal(&sysnum, &sysnum_GdiDdReleaseDC))
        return 0;
    if (drsys_sysnums_equal(&sysnum, &sysnum_DuplicateObject) &&
        syscall_duplicate_handle_deletes_handle(drcontext, sysnum))
        return 1;
    return -1;
}

/* Checks whether a system call creates a new handle.
 * It must be called from pre/post syscall event where syscall
 * arguments are available for query.
 */
static bool
syscall_creates_handle(void *drcontext, drsys_sysnum_t sysnum)
{
    ptr_uint_t arg;
    /* i#988: syscalls return existing handles */
    if (drsys_sysnums_equal(&sysnum, &sysnum_UserRemoveProp) ||
        drsys_sysnums_equal(&sysnum, &sysnum_UserFindExistingCursorIcon) ||
        drsys_sysnums_equal(&sysnum, &sysnum_UserGetAncestor) ||
        drsys_sysnums_equal(&sysnum, &sysnum_GetThreadDesktop) ||
        drsys_sysnums_equal(&sysnum, &sysnum_UserGetThreadDesktop) ||
        /* i#988-c#12: GdiSelect* system calls return existing handles */
        drsys_sysnums_equal(&sysnum, &sysnum_GdiExtSelectClipRgn) ||
        drsys_sysnums_equal(&sysnum, &sysnum_GdiSelectBrush) ||
        drsys_sysnums_equal(&sysnum, &sysnum_GdiSelectPen) ||
        drsys_sysnums_equal(&sysnum, &sysnum_GdiSelectBitmap) ||
        drsys_sysnums_equal(&sysnum, &sysnum_GdiSelectFont))
        return false;
    /* i#988-c#7: If the arg1 hMem is not NULL and the function succeeds,
     * the return value is the handle to the data passed in, so it does
     * not really create a new handle.
     */
    if (drsys_sysnums_equal(&sysnum, &sysnum_UserSetClipboardData) &&
        drsys_pre_syscall_arg(drcontext, 1, &arg) == DRMF_SUCCESS &&
        arg != (ptr_uint_t)NULL)
        return false;
    return true;
}

/***************************************************************************
 * TOP LEVEL
 */

bool
os_shared_pre_syscall(void *drcontext, cls_syscall_t *pt, drsys_sysnum_t sysnum,
                      dr_mcontext_t *mc, drsys_syscall_t *syscall)
{
    if (options.check_handle_leaks) {
        int idx = syscall_deletes_handle(drcontext, sysnum);
        if (idx != -1) {
            /* i#974: multiple threads may create/delete handles in parallel,
             * so we remove the handle from table at pre-syscall by simply
             * assuming the syscall will succeed, and add it back if it fails.
             */
            drsys_syscall_type_t syscall_type = DRSYS_SYSCALL_TYPE_KERNEL;
            if (drsys_syscall_type(syscall, &syscall_type) != DRMF_SUCCESS)
                WARN("WARNING: failed to get syscall type\n");
            pt->handle_info =
                handlecheck_delete_handle(drcontext,
                                          syscall_get_src_proc_handle(drcontext, sysnum),
                                          (HANDLE) syscall_get_param(drcontext, idx),
                                          syscall_handle_type(syscall_type, sysnum),
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
        drsys_syscall_type_t syscall_type = DRSYS_SYSCALL_TYPE_KERNEL;
        bool success = false;
        int  idx;
        if (drsys_cur_syscall_result(drcontext, &success, NULL, NULL) != DRMF_SUCCESS)
            WARN("WARNING: failed to get syscall success\n");
        if (drsys_syscall_type(syscall, &syscall_type) != DRMF_SUCCESS)
            WARN("WARNING: failed to get syscall type\n");
        idx = syscall_deletes_handle(drcontext, sysnum);
        if (idx != -1) {
            /* i#1112: NtDuplicateObject closes the source handle when
             * DUPLICATE_CLOSE_SOURCE is set, regardless of any error
             * status returned
             */
            bool res;
            res = (drsys_sysnums_equal(&sysnum, &sysnum_DuplicateObject) &&
                   syscall_duplicate_handle_deletes_handle(drcontext, sysnum)) ?
                true : success;
            /* XXX: really we should iterate the args and look for the handle,
             * but for now I'm keeping the prior code.
             */
            handlecheck_delete_handle_post_syscall
                (drcontext, (HANDLE)syscall_get_param(drcontext, idx),
		 sysnum, mc,
                 syscall_handle_type(syscall_type, sysnum), pt->handle_info, res);
            pt->handle_info = NULL;
        }
        /* find the OUT params, including return value */
        if (success &&
            syscall_creates_handle(drcontext, sysnum) &&
            drsys_iterate_args(drcontext, post_syscall_iter_arg_cb, mc) !=
            DRMF_SUCCESS)
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
syscall_handle_type(drsys_syscall_type_t drsys_type, drsys_sysnum_t sysnum)
{
    if (drsys_type == DRSYS_SYSCALL_TYPE_USER) {
        if (drsys_sysnums_equal(&sysnum, &sysnum_UserGetDC) ||
            drsys_sysnums_equal(&sysnum, &sysnum_UserReleaseDC) ||
            drsys_sysnums_equal(&sysnum, &sysnum_UserGetWindowDC))
            return HANDLE_TYPE_GDI;
        if (drsys_sysnums_equal(&sysnum, &sysnum_UserGetProcessWindowStation) ||
            drsys_sysnums_equal(&sysnum, &sysnum_UserCreateWindowStation) ||
            drsys_sysnums_equal(&sysnum, &sysnum_UserOpenWindowStation) ||
            drsys_sysnums_equal(&sysnum, &sysnum_UserCloseWindowStation) ||
            drsys_sysnums_equal(&sysnum, &sysnum_UserCloseDesktop) ||
            drsys_sysnums_equal(&sysnum, &sysnum_UserCreateDesktop) ||
            drsys_sysnums_equal(&sysnum, &sysnum_UserCreateDesktopEx) ||
            drsys_sysnums_equal(&sysnum, &sysnum_UserOpenDesktop) ||
            drsys_sysnums_equal(&sysnum, &sysnum_UserOpenInputDesktop) ||
            drsys_sysnums_equal(&sysnum, &sysnum_UserOpenThreadDesktop) ||
            drsys_sysnums_equal(&sysnum, &sysnum_GetThreadDesktop) ||
            drsys_sysnums_equal(&sysnum, &sysnum_UserGetThreadDesktop))
            return HANDLE_TYPE_KERNEL;
        return HANDLE_TYPE_USER;
    }
    else if (drsys_type == DRSYS_SYSCALL_TYPE_GRAPHICS)
        return HANDLE_TYPE_GDI;
    else
        return HANDLE_TYPE_KERNEL;
}

