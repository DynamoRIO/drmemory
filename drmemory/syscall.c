/* **********************************************************
 * Copyright (c) 2007-2009 VMware, Inc.  All rights reserved.
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
#include "utils.h"
#include "syscall.h"
#include "shadow.h"
#include "readwrite.h"
#include "syscall_os.h"
#include "alloc.h"
#ifdef LINUX
# include "sysnum_linux.h"
#endif

/***************************************************************************
 * SYSTEM CALLS
 */

typedef enum {
    SYSCALL_GATEWAY_UNKNOWN,
    SYSCALL_GATEWAY_INT,
    SYSCALL_GATEWAY_SYSENTER,
    SYSCALL_GATEWAY_SYSCALL,
#ifdef WINDOWS
    SYSCALL_GATEWAY_WOW64,
#endif
} syscall_gateway_t;

static syscall_gateway_t syscall_gateway = SYSCALL_GATEWAY_UNKNOWN;

#ifdef STATISTICS
int syscall_invoked[MAX_SYSNUM];
#endif

bool
is_using_sysenter(void)
{
    return (syscall_gateway == SYSCALL_GATEWAY_SYSENTER);
}

/* we assume 1st syscall reflects primary gateway */
bool
is_using_sysint(void)
{
    return (syscall_gateway == SYSCALL_GATEWAY_INT);
}

void
check_syscall_gateway(instr_t *inst)
{
    if (instr_get_opcode(inst) == OP_sysenter) {
        if (syscall_gateway == SYSCALL_GATEWAY_UNKNOWN
            /* some syscalls use int, but consider sysenter the primary */
            IF_LINUX(|| syscall_gateway == SYSCALL_GATEWAY_INT))
            syscall_gateway = SYSCALL_GATEWAY_SYSENTER;
        else {
            ASSERT(syscall_gateway == SYSCALL_GATEWAY_SYSENTER,
                   "multiple system call gateways not supported");
        }
    } else if (instr_get_opcode(inst) == OP_syscall) {
        if (syscall_gateway == SYSCALL_GATEWAY_UNKNOWN)
            syscall_gateway = SYSCALL_GATEWAY_SYSCALL;
        else {
            ASSERT(syscall_gateway == SYSCALL_GATEWAY_SYSCALL
                   /* some syscalls use int */
                   IF_LINUX(|| syscall_gateway == SYSCALL_GATEWAY_INT),
                   "multiple system call gateways not supported");
        }
    } else if (instr_get_opcode(inst) == OP_int) {
        if (syscall_gateway == SYSCALL_GATEWAY_UNKNOWN)
            syscall_gateway = SYSCALL_GATEWAY_INT;
        else {
            ASSERT(syscall_gateway == SYSCALL_GATEWAY_INT
                   IF_LINUX(|| syscall_gateway == SYSCALL_GATEWAY_SYSENTER
                            || syscall_gateway == SYSCALL_GATEWAY_SYSCALL),
                   "multiple system call gateways not supported");
        }
#ifdef WINDOWS
    } else if (instr_is_wow64_syscall(inst)) {
        if (syscall_gateway == SYSCALL_GATEWAY_UNKNOWN)
            syscall_gateway = SYSCALL_GATEWAY_WOW64;
        else {
            ASSERT(syscall_gateway == SYSCALL_GATEWAY_WOW64,
                   "multiple system call gateways not supported");
        }
#endif
    } else
        ASSERT(false, "unknown system call gateway");
}

const char *
get_syscall_name(uint num)
{
    syscall_info_t *sysinfo = syscall_lookup(num);
    if (sysinfo != NULL)
        return sysinfo->name;
    else
        return "<unknown>";
}

/* For syscall we do not have specific parameter info for, we do a
 * memory comparison to find what has been written.
 * We will not catch passing undefined values in that are read, of course.
 */
static void
handle_pre_unknown_syscall(void *drcontext, int sysnum, dr_mcontext_t *mc,
                           per_thread_t *pt)
{
    client_per_thread_t *cpt = (client_per_thread_t *) pt->client_data;
    app_pc start;
    int i, j;
    LOG(2, "ignoring system call #"PIFX"\n", sysnum);
    if (options.verbose >= 2) {
        ELOGF(0, f_global, "WARNING: unhandled system call #"PIFX"\n", sysnum);
    } else {
        /* PR 484069: reduce global logfile size */
        DO_ONCE(ELOGF(0, f_global, "WARNING: unhandled system calls found\n"));
    }
    for (i=0; i<SYSCALL_NUM_ARG_TRACK; i++) {
        cpt->sysarg_ptr[i] = NULL;
        if (get_sysparam_shadow_val(i, mc) == SHADOW_DEFINED) {
            start = (app_pc) dr_syscall_get_param(drcontext, i);
            LOG(3, "pre-unknown-syscall #"PIFX": param %d == "PFX"\n", sysnum, i, start);
            if (ALIGNED(start, 4) && shadow_get_byte(start) != SHADOW_UNADDRESSABLE) {
                /* FIXME: not all OUT params have starting bytes undefined; some
                 * are IN/OUT w/ flags fields, etc.  For now though we try to
                 * limit false writes by only looking at the 1st N undefined bytes.
                 */
                for (j=0; j<SYSCALL_ARG_TRACK_MAX_SZ; j++) {
                    if (shadow_get_byte(start + j) != SHADOW_UNDEFINED)
                        break;
                }
                /* We examine in dword units, which could result in false
                 * negatives w/ string operands, but removes many false
                 * positives w/ struct operands
                 */
                j = ALIGN_BACKWARD(j, 4);
                if (j > 0) {
                    LOG(2, "pre-unknown-syscall #"PIFX": param %d == "PFX" %d bytes\n",
                        sysnum, i, start, j);
                    /* Dynamically allocated since some params are large
                     * (NtGdiGetWidthTable() param 4 is 616 bytes in gui-inject.exe)
                     */
                    if (j > cpt->sysarg_val_bytes[i]) {
                        if (cpt->sysarg_val_bytes[i] > 0) {
                            thread_free(drcontext, cpt->sysarg_val[i],
                                        cpt->sysarg_val_bytes[i], HEAPSTAT_MISC);
                        } else
                            ASSERT(cpt->sysarg_val[i] == NULL, "leak");
                        cpt->sysarg_val_bytes[i] = ALIGN_FORWARD(j, 64);
                        cpt->sysarg_val[i] =
                            thread_alloc(drcontext, cpt->sysarg_val_bytes[i],
                                         HEAPSTAT_MISC);
                    }
                    if (safe_read(start, j, cpt->sysarg_val[i])) {
                        cpt->sysarg_ptr[i] = start;
                        cpt->sysarg_sz[i] = j;
                    }
                }
            }
        }
    }
}

static void
handle_post_unknown_syscall(void *drcontext, int sysnum, per_thread_t *pt)
{
    client_per_thread_t *cpt = (client_per_thread_t *) pt->client_data;
    int i, j;
    app_pc w_at = NULL;
    uint post_val[SYSCALL_ARG_TRACK_MAX_SZ/sizeof(uint)];
    for (i=0; i<SYSCALL_NUM_ARG_TRACK; i++) {
        if (cpt->sysarg_ptr[i] != NULL) {
            if (safe_read(cpt->sysarg_ptr[i], cpt->sysarg_sz[i], post_val)) {
                for (j=0; j<cpt->sysarg_sz[i]/sizeof(uint); j++) {
                    /* We check for changes on a dword basis since individual
                     * bytes often appear unchanged and nearly everything is aligned
                     * to dword (strings are the exception and there it's possible
                     * we'll mark beyond their length as defined...)
                     */
                    if (cpt->sysarg_val[i][j] != post_val[j]
                        /* Mark a 0 dword as defined.  Yes, I am worried about
                         * false negatives from this.  I put it in b/c
                         * gui-inject.exe has a 0 dword in the middle of the
                         * output from 0x10ce=GDI32!NtGdiGetTextMetricsW that (a
                         * few rep movs copies later) shows up as an
                         * uninitialized read if we don't mark it defined.  I
                         * don't want to limit to having changes after the 0
                         * dword b/c there could be structs with tails that are
                         * 0 that happened to be 0 uninitialized?
                         */
                        || post_val[j] == 0) {
                        app_pc pc = cpt->sysarg_ptr[i] + j*sizeof(uint);
                        if (w_at == NULL)
                            w_at = pc;
                        /* I would assert that this is still marked undefined, to
                         * see if we hit any races, but we have overlapping syscall
                         * args and I don't want to check for them
                         */
                        ASSERT(shadow_get_byte(pc + 0) != SHADOW_UNADDRESSABLE, "");
                        ASSERT(shadow_get_byte(pc + 1) != SHADOW_UNADDRESSABLE, "");
                        ASSERT(shadow_get_byte(pc + 2) != SHADOW_UNADDRESSABLE, "");
                        ASSERT(shadow_get_byte(pc + 3) != SHADOW_UNADDRESSABLE, "");
                        shadow_set_byte(pc + 0, SHADOW_DEFINED);
                        shadow_set_byte(pc + 1, SHADOW_DEFINED);
                        shadow_set_byte(pc + 2, SHADOW_DEFINED);
                        shadow_set_byte(pc + 3, SHADOW_DEFINED);
                    } else if (w_at != NULL) {
                        LOG(2, "unknown-syscall #"PIFX": param %d written "PFX" %d bytes\n",
                            sysnum, i, w_at,
                            (cpt->sysarg_ptr[i] + j*sizeof(uint)) - w_at);
                        w_at = NULL;
                    }
                }
                if (w_at != NULL) {
                    LOG(2, "unknown-syscall #"PIFX": param %d written "PFX" %d bytes\n",
                        sysnum, i, w_at, (cpt->sysarg_ptr[i] + j*sizeof(uint)) - w_at);
                    w_at = NULL;
                }
            }
        }
    }
}

void
check_sysmem(uint flags, int sysnum, app_pc ptr, size_t sz, dr_mcontext_t *mc,
             const char *id)
{
    /* Don't trigger asserts in handle_mem_ref(): syscall will probably fail
     * or it's an optional arg
     */
    ASSERT(!options.leaks_only && options.shadowing, "shadowing disabled");
    if (ptr != NULL && sz > 0) {
        app_loc_t loc;
        syscall_to_loc(&loc, sysnum, id);
        handle_mem_ref(flags, &loc, ptr, sz, mc, NULL);
    }
}

static void
process_syscall_reads_and_writes(void *drcontext, int sysnum, dr_mcontext_t *mc,
                                 syscall_info_t *sysinfo)
{
    app_pc start;
    uint size, num_args;
    int i, last_param = -1;
    LOG(2, "processing system call #%d %s\n", sysnum, sysinfo->name);
    num_args = IF_WINDOWS_ELSE(sysinfo->args_size/sizeof(reg_t),
                               sysinfo->args_size);
    /* Treat all parameters as IN.
     * There are no inlined OUT params anyway: have to at least set
     * to NULL, unless truly ignored based on another parameter.
     */
    for (i=0; i<num_args; i++) {
        size_t argsz = sizeof(reg_t);
        if (TEST(SYSARG_INLINED_BOOLEAN, sysinfo->arg[i].flags)) {
            /* BOOLEAN is only 1 byte so ok if only lsb is defined */
            argsz = 1;
        }
        check_sysparam_defined(sysnum, i, mc, argsz);
    }
    for (i=0; i<num_args; i++) {
        if (sysinfo->arg[i].param == 0 &&
            sysinfo->arg[i].size == 0 &&
            sysinfo->arg[i].flags == 0)
            break;
        if (sysinfo->arg[i].param == last_param) {
            /* FIXME PR 408536: the length written may not match that
             * requested: we should check whether addressable at
             * pre-syscall point but only mark
             * as defined (i.e., commit the write) at post-syscall when know
             * true length.  We would handle all writes this way, as it would
             * wait to determine syscall success before committing,
             * but it opens up more possibilities for races so we
             * instead plan to only do so for user-set sizes.  We
             * indicate what the post-syscall write size is via a
             * second entry w/ the same param#.
             */
            continue;
        }
        last_param = sysinfo->arg[i].param;
        if (TEST(SYSARG_INLINED_BOOLEAN, sysinfo->arg[i].flags))
            continue;
        start = (app_pc) dr_syscall_get_param(drcontext, sysinfo->arg[i].param);
        if (sysinfo->arg[i].size == SYSARG_SIZE_CSTRING) {
            /* FIXME PR 408539: check addressability and definedness of each
             * byte prior to deref and find end.  (We only need this
             * on syscall since in user code we'll see the individual
             * refs (or rep cmps)).
             */
            size = 0; /* for now */
        } else {
            size = (sysinfo->arg[i].size > 0) ? sysinfo->arg[i].size :
                ((uint) dr_syscall_get_param(drcontext, -sysinfo->arg[i].size));
            if (TEST(SYSARG_LENGTH_INOUT, sysinfo->arg[i].flags)) {
                safe_read((void *)size, sizeof(size), &size);
            }
        }
        /* FIXME PR 406355: we don't record which params are optional 
         * FIXME: some OUT params may not be written if the IN is bogus:
         * we should check here since harder to undo post-syscall on failure.
         */
        if (start != NULL && size > 0) {
#ifdef WINDOWS
            if (TEST(SYSARG_PORT_MESSAGE, sysinfo->arg[i].flags)) {
                /* variable-length */
                PORT_MESSAGE *pm = (PORT_MESSAGE *) start;
                /* guess which side of union is used */
                if (pm->u1.s1.DataLength != 0)
                    size = pm->u1.s1.TotalLength;
                else
                    size = pm->u1.Length;
                if (size < sizeof(*pm))
                    size = sizeof(*pm);
                LOG(2, "total size of PORT_MESSAGE arg %d is %d\n", i, size);
            }
#endif
            /* pass syscall # as pc for reporting purposes */
            /* we treat in-out read-and-write as simply read, since if
             * not defined we'll report and then mark as defined anyway.
             */
            /* FIXME PR 408536: for write, check addressability here and do not
             * commit the write until post-syscall
             */
            check_sysmem((TEST(SYSARG_WRITE, sysinfo->arg[i].flags) ?
                          MEMREF_WRITE : MEMREF_CHECK_DEFINEDNESS),
                         sysnum, start, size, mc, NULL);
        }
    }
}

static bool
event_pre_syscall(void *drcontext, int sysnum)
{
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    syscall_info_t *sysinfo;
    dr_mcontext_t mc;
    int i;
    bool res = true;
    dr_get_mcontext(drcontext, &mc, NULL);

#ifdef STATISTICS
    if (sysnum >= MAX_SYSNUM-1) {
        ATOMIC_INC32(syscall_invoked[MAX_SYSNUM-1]);
    } else {
        ATOMIC_INC32(syscall_invoked[sysnum]);
    }
#endif

    /* save params for post-syscall access 
     * FIXME: it's possible for a pathological app to crash us here
     * by setting up stack so that our blind reading of SYSCALL_NUM_ARG_STORE
     * params will hit unreadable page.
     */
    for (i = 0; i < SYSCALL_NUM_ARG_STORE; i++)
        pt->sysarg[i] = dr_syscall_get_param(drcontext, i);

    sysinfo = syscall_lookup(sysnum);
    if (sysinfo != NULL) {
        if (!options.leaks_only && options.shadowing)
            process_syscall_reads_and_writes(drcontext, sysnum, &mc, sysinfo);
        /* now do the syscall-specific handling we need */
        handle_pre_alloc_syscall(drcontext, sysnum, &mc, pt);
    } else {
        if (!options.leaks_only && options.shadowing)
            handle_pre_unknown_syscall(drcontext, sysnum, &mc, pt);
    }
    /* give os-specific-code chance to do further processing */
    res = os_shared_pre_syscall(drcontext, sysnum);
    if (!options.leaks_only && options.shadowing)
        res = os_shadow_pre_syscall(drcontext, sysnum) && res;
    return res;
}

static void
event_post_syscall(void *drcontext, int sysnum)
{
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    syscall_info_t *sysinfo = syscall_lookup(sysnum);

    /* post-syscall, eax is defined */
    if (!options.leaks_only && options.shadowing)
        register_shadow_set_dword(REG_XAX, SHADOW_DWORD_DEFINED);

    if (sysinfo != NULL) {
        dr_mcontext_t mc;
        dr_get_mcontext(drcontext, &mc, NULL);
        handle_post_alloc_syscall(drcontext, sysnum, &mc, pt);
        if (dr_syscall_get_result(drcontext) < 0) {
            /* FIXME PR 408540: the shadow writes we enacted in
             * event_pre_syscall() should be considered to have NOT happened.
             * We can detect some with checks
             * on known IN args that will cause failure (NULL, etc.).
             * How handle races though?  Xref all the discussion over malloc/free
             * failure races, possibility of locking, and whether better to
             * undo or delay.
             */
            LOG(1, "WARNING: system call %i %s failed\n", sysnum,
                (sysinfo != NULL) ? sysinfo->name : "<unknown>");
        }
        /* FIXME PR 408536: even when successful, the # of bytes written may not
         * match that requested by the IN args (e.g., when reading from a file).
         * See notes in pre-syscall.
         */
    } else if (!options.leaks_only && options.shadowing) {
        handle_post_unknown_syscall(drcontext, sysnum, pt);
    }
    os_shared_post_syscall(drcontext, sysnum);
    if (!options.leaks_only && options.shadowing)
        os_shadow_post_syscall(drcontext, sysnum);
}

static bool
event_filter_syscall(void *drcontext, int sysnum)
{
    return true; /* intercept everything */
}

void
syscall_thread_init(void *drcontext)
{
    /* we lazily initialize sysarg_ arrays */
}

void
syscall_reset_per_thread(void *drcontext, per_thread_t *pt)
{
    client_per_thread_t *cpt = (client_per_thread_t *) pt->client_data;
    int i;
    for (i=0; i<SYSCALL_NUM_ARG_TRACK; i++) {
        if (cpt->sysarg_val_bytes[i] > 0) {
            ASSERT(cpt->sysarg_val[i] != NULL, "sysarg alloc error");
            thread_free(drcontext, cpt->sysarg_val[i], cpt->sysarg_val_bytes[i],
                        HEAPSTAT_MISC);
        } else {
            ASSERT(cpt->sysarg_val[i] == NULL, "sysarg alloc error");
        }
    }
}

void
syscall_thread_exit(void *drcontext, per_thread_t *pt)
{
    syscall_reset_per_thread(drcontext, pt);
}

void
syscall_init(void *drcontext _IF_WINDOWS(app_pc ntdll_base))
{
    syscall_os_init(drcontext _IF_WINDOWS(ntdll_base));

    /* We used to handle all the gory details of Windows pre- and
     * post-syscall hooking ourselves, including system call parameter
     * bases varying by syscall type, and post-syscall hook complexity.
     * Old notes to highlight some of the past issues:
     *
     *   Since we aren't allowed to add code after a syscall instr, we have to
     *   find the post-syscall app instr: but for vsyscall sysenter, that ret
     *   is executed natively, so we have to step one level out to the wrapper.
     *   Simpler to set a flag and assume next bb is the one rather than
     *   identify the vsyscall call up front.
     *
     *   We used to also do pre-syscall via the wrapper, to avoid
     *   worrying about system call numbers or differences in where the parameters are
     *   located between int and sysenter, but now that we're checking syscall args at
     *   the syscall point itself anyway we do our pre-syscall checks there and only
     *   use these to find the post-syscall wrapper points.  Eventually we'll do
     *   post-syscall checks after the syscall point instead of using the wrappers and
     *   then we'll get rid of all of this and will properly handle hand-rolled system
     *   calls.
     *
     * But now that DR 1.3 has syscall events we use those, which also makes it
     * easier to port to Linux.
     */
    dr_register_filter_syscall_event(event_filter_syscall);
    dr_register_pre_syscall_event(event_pre_syscall);
    dr_register_post_syscall_event(event_post_syscall);
}

void
syscall_exit(void)
{
    syscall_os_exit();
}

