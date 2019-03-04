/* **********************************************************
 * Copyright (c) 2010-2019 Google, Inc.  All rights reserved.
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
#include "drsyscall.h"
#include "drmemory.h"
#include "utils.h"
#include "syscall.h"
#include "shadow.h"
#include "slowpath.h"
#include "syscall_os.h"
#include "alloc.h"
#include "perturb.h"
#ifdef UNIX
# include "sysnum_linux.h"
#endif
#include "report.h"

#ifdef SYSCALL_DRIVER
# include "syscall_driver.h"
#endif

int cls_idx_syscall = -1;

#ifdef STATISTICS
int syscall_invoked[MAX_SYSNUM];
#endif

/***************************************************************************
 * AUXILIARY LIBRARY
 */

static dr_auxlib_handle_t auxlib;
static byte *auxlib_start, *auxlib_end;

/* We want function pointers, not static functions */
/* These function pointers are all in .data so will be read-only after init */
#define DYNAMIC_INTERFACE 1
#include "syscall_aux.h"

/* local should be a char * and is meant to record which bind failed */
#define BINDFUNC(lib, local, name) \
    (local = #name, name = (void *) dr_lookup_aux_library_routine(lib, #name))

#define SYSAUXLIB_MIN_VERSION_USED 1

static bool
syscall_load_auxlib(const char *name)
{
    char auxpath[MAXIMUM_PATH];
    char *buf = auxpath;
    size_t bufsz = BUFFER_SIZE_ELEMENTS(auxpath);
    ssize_t len = 0;
    size_t sofar = 0;
    const char *path = dr_get_client_path(client_id);
    const char *sep = path;
    char *func;
    int *drauxlib_ver_compat, *drauxlib_ver_cur;

    /* basename is passed in: use client path */
    while (*sep != '\0')
        sep++;
    while (sep > path && *sep != DIRSEP IF_WINDOWS(&& *sep != ALT_DIRSEP))
        sep--;
    BUFPRINT(buf, bufsz, sofar, len, "%.*s", (sep - path), path);
    BUFPRINT(buf, bufsz, sofar, len, "/%s", name);
    auxlib = dr_load_aux_library(auxpath, &auxlib_start, &auxlib_end);
    if (auxlib == NULL) {
        NOTIFY_ERROR("Error loading auxiliary library %s"NL, auxpath);
        goto auxlib_load_error;
    }

    /* version check */
    drauxlib_ver_compat = (int *)
        dr_lookup_aux_library_routine(auxlib, SYSAUXLIB_VERSION_COMPAT_NAME);
    drauxlib_ver_cur = (int *)
        dr_lookup_aux_library_routine(auxlib, SYSAUXLIB_VERSION_CUR_NAME);
    if (drauxlib_ver_compat == NULL || drauxlib_ver_cur == NULL ||
        *drauxlib_ver_compat > SYSAUXLIB_MIN_VERSION_USED ||
        *drauxlib_ver_cur < SYSAUXLIB_MIN_VERSION_USED) {
        NOTIFY_ERROR("Version %d mismatch with aux library %s version %d-%d"NL,
                     SYSAUXLIB_MIN_VERSION_USED, auxpath,
                     (drauxlib_ver_compat == NULL) ? -1 : *drauxlib_ver_cur,
                     (drauxlib_ver_compat == NULL) ? -1 : *drauxlib_ver_cur);
        goto auxlib_load_error;
    }
    LOG(1, "loaded aux lib %s at "PFX"-"PFX" ver=%d-%d\n",
        auxpath, auxlib_start, auxlib_end, *drauxlib_ver_compat, *drauxlib_ver_cur);

    /* required import binding */
    if (BINDFUNC(auxlib, func, sysauxlib_init) == NULL ||
        BINDFUNC(auxlib, func, sysauxlib_syscall_name) == NULL ||
        BINDFUNC(auxlib, func, sysauxlib_save_params) == NULL ||
        BINDFUNC(auxlib, func, sysauxlib_free_params) == NULL ||
        BINDFUNC(auxlib, func, sysauxlib_syscall_successful) == NULL ||
        BINDFUNC(auxlib, func, sysauxlib_num_reg_params) == NULL ||
        BINDFUNC(auxlib, func, sysauxlib_reg_param_info) == NULL ||
        BINDFUNC(auxlib, func, sysauxlib_num_mem_params) == NULL ||
        BINDFUNC(auxlib, func, sysauxlib_mem_param_info) == NULL ||
        BINDFUNC(auxlib, func, sysauxlib_is_fork) == NULL ||
        BINDFUNC(auxlib, func, sysauxlib_is_exec) == NULL) {
        NOTIFY_ERROR("Required export %s missing from aux library %s"NL,
                     func, auxpath);
        goto auxlib_load_error;
    }
    if (!sysauxlib_init()) {
        NOTIFY_ERROR("aux library init failed: do you have the latest version?"NL);
        goto auxlib_load_error;
    }
    return true;

 auxlib_load_error:
    dr_abort();
    ASSERT(false, "shouldn't get here");
    if (auxlib != NULL)
        dr_unload_aux_library(auxlib);
    auxlib = NULL;
    return false;
}

byte *
syscall_auxlib_start(void)
{
    return auxlib_start;
}

byte *
syscall_auxlib_end(void)
{
    return auxlib_end;
}

static const char *
auxlib_syscall_name(int sysnum)
{
    if (auxlib == NULL || sysauxlib_syscall_name == NULL)
        return NULL;
    return sysauxlib_syscall_name(sysnum);
}

static bool
auxlib_known_syscall(int sysnum)
{
    return (auxlib_syscall_name(sysnum) != NULL);
}

/* checking syscall param in pre-syscall only.
 * params in memory slots have to be treated as normal param handling
 * and won't be handled by this routine.
 */
static void
auxlib_check_sysparam(void *drcontext, uint sysnum, uint argnum,
                      dr_mcontext_t *mc, size_t argsz)
{
    cls_syscall_t *cpt;
    app_loc_t loc;
    reg_id_t reg;
    drsys_sysnum_t sysnum_full = {sysnum,0};
    if (CHECK_UNINITS())
        return;
    ASSERT(options.shadowing, "shadowing disabled");
    cpt = (cls_syscall_t *) drmgr_get_cls_field(drcontext, cls_idx_syscall);
    reg = sysauxlib_reg_param_info(drcontext, cpt->sysaux_params, argnum);
    syscall_to_loc(&loc, sysnum_full, NULL);
    check_register_defined(drcontext, reg, &loc, argsz, mc, NULL);
}

static bool
auxlib_shared_pre_syscall(void *drcontext, int sysnum, dr_mcontext_t *mc)
{
    cls_syscall_t *cpt = (cls_syscall_t *) drmgr_get_cls_field(drcontext, cls_idx_syscall);
#ifndef USE_DRSYMS
    char path[MAXIMUM_PATH];
#endif
    cpt->sysaux_params = sysauxlib_save_params(drcontext);
#ifdef UNIX
    if (sysauxlib_is_fork(drcontext, cpt->sysaux_params, NULL)) {
        if (options.perturb)
            perturb_pre_fork();
    }
# ifndef USE_DRSYMS
    else if (sysauxlib_is_exec(drcontext, cpt->sysaux_params,
                               path, BUFFER_SIZE_BYTES(path)))
        ELOGF(0, f_fork, "EXEC path=%s\n", path);
# endif
#endif
    return true;
}

static void
auxlib_shared_post_syscall(void *drcontext, int sysnum, dr_mcontext_t *mc)
{
#if defined(UNIX) && !defined(USE_DRSYMS)
    cls_syscall_t *cpt = (cls_syscall_t *) drmgr_get_cls_field(drcontext, cls_idx_syscall);
    char path[MAXIMUM_PATH];
    process_id_t child;
    ASSERT(cpt->sysaux_params != NULL, "params should already be saved");
    if (sysauxlib_is_fork(drcontext, cpt->sysaux_params, &child)) {
       /* PR 453867: tell postprocess.pl to watch for child logdir and
         * then fork a new copy.
         */
        if (sysauxlib_is_exec(drcontext, cpt->sysaux_params,
                              path, BUFFER_SIZE_BYTES(path))) {
            ELOGF(0, f_fork, "FORKEXEC child=%d path=%s\n", child, path);
        } else {
            ELOGF(0, f_fork, "FORK child=%d\n", child);
        }
    }
#endif
}

static bool
auxlib_shadow_pre_syscall(void *drcontext, int sysnum, dr_mcontext_t *mc)
{
    cls_syscall_t *cpt = (cls_syscall_t *) drmgr_get_cls_field(drcontext, cls_idx_syscall);
    int i;
    drsys_sysnum_t sysnum_full = {sysnum,0};
    if (auxlib == NULL || !auxlib_known_syscall(sysnum))
        return true;
    ASSERT(cpt->sysaux_params != NULL, "params should already be saved");
    for (i=0; i<sysauxlib_num_reg_params(drcontext, cpt->sysaux_params); i++)
        auxlib_check_sysparam(drcontext, sysnum, i, mc, sizeof(reg_t));
    for (i=0; i<sysauxlib_num_mem_params(drcontext, cpt->sysaux_params); i++) {
        byte *start;
        size_t len_in, len_out;
        sysauxlib_param_t type;
        const char *name;
        if (sysauxlib_mem_param_info(drcontext, cpt->sysaux_params, i, &name,
                                     &start, &len_in, &len_out, &type)) {
            LOG(3, "sysauxlib syscall %d mem param %d %s: "PFX" "PIFX" "PIFX" %d\n",
                sysnum, i, name, start, len_in, len_out, type);
            if (type == SYSAUXLIB_PARAM_STRING ||
                type == SYSAUXLIB_PARAM_STRARRAY) {
                /* FIXME PR 408539: check addressability and definedness
                 * of each byte prior to deref and find end.
                 */
            }
            if (len_in > 0) {
                check_sysmem((type == SYSAUXLIB_PARAM_STRING) ?
                             /* capacity should be addr, until NULL defined */
                             MEMREF_CHECK_ADDRESSABLE :
                             MEMREF_CHECK_DEFINEDNESS,
                             sysnum_full, start, len_in, mc, name);
            }
            if (len_out > 0) {
                check_sysmem(MEMREF_CHECK_ADDRESSABLE,
                             sysnum_full, start, len_out, mc, name);
            }
        } else {
            LOG(1, "WARNING: unable to retrieve sysauxlib syscall %d param %d\n",
                sysnum, i);
        }
    }
    return true;
}

static void
auxlib_shadow_post_syscall(void *drcontext, int sysnum, dr_mcontext_t *mc)
{
    cls_syscall_t *cpt = (cls_syscall_t *) drmgr_get_cls_field(drcontext, cls_idx_syscall);
    drsys_sysnum_t sysnum_full = {sysnum,0};
    if (auxlib == NULL || !auxlib_known_syscall(sysnum))
        return;
    ASSERT(cpt->sysaux_params != NULL, "params should already be saved");
    if (sysauxlib_syscall_successful(drcontext, cpt->sysaux_params)) {
        int i;
        for (i=0; i<sysauxlib_num_mem_params(drcontext, cpt->sysaux_params); i++) {
            byte *start;
            size_t len_in, len_out;
            sysauxlib_param_t type;
            const char *name;
            if (sysauxlib_mem_param_info(drcontext, cpt->sysaux_params, i,
                                         &name, &start, &len_in, &len_out, &type)) {
                if (len_out > 0) {
                    if (type == SYSAUXLIB_PARAM_STRING ||
                        type == SYSAUXLIB_PARAM_STRARRAY) {
                        /* FIXME PR 408539: mark defined until end */
                    }
                    check_sysmem(MEMREF_WRITE, sysnum_full, start, len_out, mc, name);
                }
            } else {
                LOG(1, "WARNING: unable to retrieve sysauxlib syscall %d param %s\n",
                    sysnum, name);
            }
        }
    }
    sysauxlib_free_params(drcontext, cpt->sysaux_params);
    cpt->sysaux_params = NULL;
}

/***************************************************************************
 * SYSCALL HANDLING
 */

const char *
get_syscall_name(drsys_sysnum_t num)
{
    const char *name;
    drsys_syscall_t *syscall;
    if (drsys_number_to_syscall(num, &syscall) == DRMF_SUCCESS &&
        drsys_syscall_name(syscall, &name) == DRMF_SUCCESS)
        return name;
    else {
        name = auxlib_syscall_name(num.number);
        if (name != NULL)
            return name;
        return "<unknown>";
    }
}

bool
syscall_is_known(drsys_sysnum_t num)
{
    bool known = false;
    drsys_syscall_t *syscall;
    if (drsys_number_to_syscall(num, &syscall) != DRMF_SUCCESS ||
        drsys_syscall_is_known(syscall, &known) != DRMF_SUCCESS)
        known = auxlib_known_syscall(num.number);
    return known;
}

void
check_sysmem(uint flags, drsys_sysnum_t sysnum, app_pc ptr, size_t sz, dr_mcontext_t *mc,
             const char *id)
{
    /* Don't trigger asserts in handle_mem_ref(): syscall will probably fail
     * or it's an optional arg
     */
    ASSERT(INSTRUMENT_MEMREFS(), "memory reference checking disabled");
    if (!options.check_uninitialized && flags != MEMREF_CHECK_ADDRESSABLE)
        return;
    if (ptr != NULL && sz > 0 && flags != 0) {
        app_loc_t loc;
        syscall_to_loc(&loc, sysnum, id);
        DOLOG(SYSCALL_VERBOSE, {
            if (flags == MEMREF_WRITE) {
                LOG(SYSCALL_VERBOSE, "\t  marking "PIFX"-"PIFX" written %s\n",
                    ptr, ptr + sz, (id == NULL) ? "" : id);
            }
        });
        /* i#556: for uninitialized random values passed as sizes to syscalls, we
         * don't want to walk huge sections of memory, so we stop checking after
         * the first erroneous word is found.  The reported error may not have
         * an intuitive size, but it's not clear how else to handle it since there's
         * no magic threshold that's bigger than any valid size, and any separate
         * error within the same region will today be reported as a dup (i#581).
         */
        if (sz > 64*1024)
            flags |= MEMREF_ABORT_AFTER_UNADDR;
        handle_mem_ref(flags, &loc, ptr, sz, mc);
    }
}

static bool
drsys_iter_memarg_cb(drsys_arg_t *arg, void *user_data)
{
    uint flags = 0;
    LOG(SYSCALL_VERBOSE, "\t  memarg iter %s param %d %s "PIFX"-"PIFX" %s%s%s%s%s\n",
        arg->pre ? "pre" : "post", arg->ordinal,
        arg->arg_name == NULL ? "" : arg->arg_name,
        arg->start_addr, (byte *)arg->start_addr + arg->size,
        arg->valid ? "" : "invalid ",
        TEST(DRSYS_PARAM_RETVAL, arg->mode) ? "ret" : "",
        TEST(DRSYS_PARAM_BOUNDS, arg->mode) ? "bounds" : "",
        TEST(DRSYS_PARAM_IN, arg->mode) ? "r" : "",
        TEST(DRSYS_PARAM_OUT, arg->mode) ? "w" : "");
    if (!arg->valid)
        return true; /* keep going */
    if (os_process_syscall_memarg(arg))
        return true; /* keep going */
    if (!options.shadowing)
        return true; /* keep going: current use case is -check_handle_leaks */
    if (arg->pre) {
        /* DRSYS_PARAM_BOUNDS => MEMREF_CHECK_ADDRESSABLE */
        flags = (CHECK_UNINITS() && TEST(DRSYS_PARAM_IN, arg->mode)) ?
            MEMREF_CHECK_DEFINEDNESS : MEMREF_CHECK_ADDRESSABLE;
        if (flags == MEMREF_CHECK_ADDRESSABLE && arg->start_addr != NULL) {
            /* Extra check for buffers allocated on the heap to help find
             * errors in syscall handling.
             */
            ssize_t heap_size = malloc_chunk_size(arg->start_addr);
            if (heap_size >= 0 && (size_t)heap_size != arg->size) {
                WARN("WARNING: heap buffer at "PFX" is of size %d bytes, "
                     "which does not match the sysarg %s size of %d bytes.\n",
                     arg->start_addr, heap_size,
                     arg->arg_name == NULL ? "" : arg->arg_name, arg->size);
            }
        }
    } else {
        ASSERT(TEST(DRSYS_PARAM_OUT, arg->mode), "shouldn't see IN params in post");
        flags = MEMREF_WRITE;
    }
    check_sysmem(flags, arg->sysnum, arg->start_addr, arg->size, arg->mc, arg->arg_name);
    return true; /* keep going */
}

static bool
drsys_iter_arg_cb(drsys_arg_t *arg, void *user_data)
{
    /* indicate which syscall arg (i#510) */
    /* FIXME i#888: this stack-allocated string could be pointed at by a callstack
     * after this function returns!
     */
    char idmsg[32];
    IF_DEBUG(int res = )
        dr_snprintf(idmsg, BUFFER_SIZE_ELEMENTS(idmsg),
                    "parameter value #%d", arg->ordinal);
    ASSERT(res > 0 && res < BUFFER_SIZE_ELEMENTS(idmsg), "message buffer too small");
    NULL_TERMINATE_BUFFER(idmsg);

    ASSERT(INSTRUMENT_MEMREFS(), "memory reference checking disabled");
    ASSERT(arg->pre, "we only iterate non-mem args in pre-syscall");

    if (TEST(DRSYS_PARAM_RETVAL, arg->mode)) {
        /* nothing */
    } else if (arg->reg == DR_REG_NULL) {
        check_sysmem(CHECK_UNINITS() ?
                     MEMREF_CHECK_DEFINEDNESS : MEMREF_CHECK_ADDRESSABLE,
                     arg->sysnum, arg->start_addr, arg->size, arg->mc, idmsg);
    } else if (CHECK_UNINITS()){
        app_loc_t loc;
        syscall_to_loc(&loc, arg->sysnum, idmsg);
        check_register_defined(arg->drcontext, arg->reg, &loc, arg->size, arg->mc, NULL);
    }
    return true; /* keep going */
}

static bool
event_pre_syscall(void *drcontext, int sysnum)
{
    cls_syscall_t *pt = (cls_syscall_t *) drmgr_get_cls_field(drcontext, cls_idx_syscall);
    drsys_sysnum_t sysnum_full;
    dr_mcontext_t *mc;
    bool res = true;
    drsys_syscall_t *syscall;
    if (drsys_cur_syscall(drcontext, &syscall) != DRMF_SUCCESS)
        ASSERT(false, "shouldn't fail");

    if (drsys_syscall_number(syscall, &sysnum_full) != DRMF_SUCCESS)
        ASSERT(false, "drsys_get_sysnum failed");
    ASSERT(sysnum == sysnum_full.number, "stats expect primary==DR's num");
    if (drsys_get_mcontext(drcontext, &mc) != DRMF_SUCCESS)
        ASSERT(false, "drsys_get_mcontext failed");

#ifdef STATISTICS
    /* XXX: we could dynamically allocate entries and separate secondary syscalls */
    if (sysnum >= MAX_SYSNUM-1) {
        ATOMIC_INC32(syscall_invoked[MAX_SYSNUM-1]);
    } else {
        ATOMIC_INC32(syscall_invoked[sysnum]);
    }
#endif

    LOG(SYSCALL_VERBOSE, "system call #%d==%d.%d %s\n", sysnum,
        sysnum_full.number, sysnum_full.secondary, get_syscall_name(sysnum_full));
    DOLOG(SYSCALL_VERBOSE, {
        /* for sysenter, pc is at vsyscall and there's no frame for wrapper.
         * simplest soln: skip to wrapper now.
         */
        app_pc tmp = mc->pc;
        app_pc parent;
        if (safe_read((void *)mc->xsp, sizeof(parent), &parent))
            mc->pc = parent;
        report_callstack(drcontext, mc);
        mc->pc = tmp;
    });

    /* give os-specific-code chance to do non-shadow processing */
    res = os_shared_pre_syscall(drcontext, pt, sysnum_full, mc, syscall);
    if (auxlib_known_syscall(sysnum))
        res = auxlib_shared_pre_syscall(drcontext, sysnum, mc) && res;

    /* FIXME: i#750 need enable system call parameter checks in pattern mode. */
    if (options.shadowing) {
        if (drsys_iterate_args(drcontext, drsys_iter_arg_cb, NULL) != DRMF_SUCCESS)
            LOG(1, "unknown system call args for #%d\n", sysnum_full.number);
        if (drsys_iterate_memargs(drcontext, drsys_iter_memarg_cb, NULL) != DRMF_SUCCESS)
            LOG(1, "unknown system call memargs for #%d\n", sysnum_full.number);
        /* there may be overlap between our table and auxlib: e.g., SYS_ioctl */
        if (auxlib_known_syscall(sysnum))
            res = auxlib_shadow_pre_syscall(drcontext, sysnum, mc) && res;
    }

    /* syscall-specific handling we ourselves need, which must come after
     * shadow handling for proper NtContinue handling and proper
     * NtCallbackReturn handling
     */
    res = handle_pre_alloc_syscall(drcontext, sysnum, mc) && res;

    if (options.perturb)
        res = perturb_pre_syscall(drcontext, sysnum) && res;

    return res;
}

static void
event_post_syscall(void *drcontext, int sysnum)
{
    cls_syscall_t *pt = (cls_syscall_t *) drmgr_get_cls_field(drcontext, cls_idx_syscall);
    drsys_sysnum_t sysnum_full;
    dr_mcontext_t *mc;
    drsys_syscall_t *syscall;
    bool success = false;
    uint errno;
    uint64 ret_val;
    if (drsys_cur_syscall(drcontext, &syscall) != DRMF_SUCCESS)
        ASSERT(false, "shouldn't fail");

    if (drsys_syscall_number(syscall, &sysnum_full) != DRMF_SUCCESS)
        ASSERT(false, "drsys_get_sysnum failed");
    ASSERT(sysnum == sysnum_full.number, "stats expect primary==DR's num");
    if (drsys_get_mcontext(drcontext, &mc) != DRMF_SUCCESS)
        ASSERT(false, "drsys_get_mcontext failed");

    LOG(SYSCALL_VERBOSE, "system call #%d==%d.%d %s ", sysnum,
        sysnum_full.number, sysnum_full.secondary, get_syscall_name(sysnum_full));
    if (drsys_cur_syscall_result(drcontext, &success, &ret_val, &errno)
        != DRMF_SUCCESS || !success) {
        LOG(SYSCALL_VERBOSE, "failed with error "PIFX"\n", errno);
    } else {
        LOG(SYSCALL_VERBOSE, "succeeded with return value "PIFX"\n", ret_val);
    }

    handle_post_alloc_syscall(drcontext, sysnum, mc);
    os_shared_post_syscall(drcontext, pt, sysnum_full, mc, syscall);
    if (auxlib_known_syscall(sysnum))
        auxlib_shared_post_syscall(drcontext, sysnum, mc);

    if (options.shadowing) {
        /* post-syscall, eax is defined */
        register_shadow_set_ptrsz(DR_REG_PTR_RETURN, SHADOW_PTRSZ_DEFINED);
        if (success) {
            /* commit the writes via MEMREF_WRITE */
            if (drsys_iterate_memargs(drcontext, drsys_iter_memarg_cb, NULL) !=
                DRMF_SUCCESS)
                ASSERT(false, "drsys_iterate_memargs failed");
        }
        if (auxlib_known_syscall(sysnum))
            auxlib_shadow_post_syscall(drcontext, sysnum, mc);
    }
}

static bool
event_filter_syscall(void *drcontext, int sysnum)
{
    return true; /* intercept everything */
}

static void
syscall_reset_per_thread(void *drcontext, cls_syscall_t *cpt)
{
    /* nothing to free anymore */
}

static void
syscall_context_init(void *drcontext, bool new_depth)
{
    cls_syscall_t *cpt;
    if (new_depth) {
        cpt = (cls_syscall_t *) thread_alloc(drcontext, sizeof(*cpt), HEAPSTAT_MISC);
        drmgr_set_cls_field(drcontext, cls_idx_syscall, cpt);
    } else {
        cpt = (cls_syscall_t *) drmgr_get_cls_field(drcontext, cls_idx_syscall);
        syscall_reset_per_thread(drcontext, cpt);
    }
    memset(cpt, 0, sizeof(*cpt));
}

static void
syscall_context_exit(void *drcontext, bool thread_exit)
{
    if (thread_exit) {
        cls_syscall_t *cpt = (cls_syscall_t *)
            drmgr_get_cls_field(drcontext, cls_idx_syscall);
        syscall_reset_per_thread(drcontext, cpt);
        thread_free(drcontext, cpt, sizeof(*cpt), HEAPSTAT_MISC);
    }
    /* else, nothing to do: we leave the struct for re-use on next callback */
}

void
syscall_thread_init(void *drcontext)
{
    /* we lazily initialize sysarg_ arrays */

#ifdef SYSCALL_DRIVER
    if (options.syscall_driver)
        driver_thread_init(drcontext);
#endif

    syscall_os_thread_init(drcontext);
}

void
syscall_thread_exit(void *drcontext)
{
    syscall_os_thread_exit(drcontext);

#ifdef SYSCALL_DRIVER
    if (options.syscall_driver)
        driver_thread_exit(drcontext);
#endif
}

static bool
is_byte_addressable(byte *addr)
{
    umbra_shadow_memory_info_t info;
    umbra_shadow_memory_info_init(&info);
    return shadow_get_byte(&info, addr) != SHADOW_UNADDRESSABLE;
}

static bool
is_byte_defined(byte *addr)
{
    umbra_shadow_memory_info_t info;
    umbra_shadow_memory_info_init(&info);
    return shadow_get_byte(&info, addr) == SHADOW_DEFINED;
}

static bool
is_register_defined(reg_id_t reg)
{
    return is_shadow_register_defined(get_shadow_register(reg));
}

void
syscall_init(void *drcontext _IF_WINDOWS(app_pc ntdll_base))
{
    drsys_options_t ops = { sizeof(ops), 0, };
    drmf_status_t res;
#ifdef WINDOWS
    const char *sysnum_fname = is_wow64_process() ? SYSNUM_FILE_WOW64 : SYSNUM_FILE;
#endif
    ops.analyze_unknown_syscalls = options.analyze_unknown_syscalls;
    ops.syscall_dword_granularity = options.syscall_dword_granularity;
    ops.syscall_sentinels = options.syscall_sentinels;
    ops.verify_sysnums = options.verify_sysnums;
    ops.lookup_internal_symbol = lookup_internal_symbol;
#ifdef SYSCALL_DRIVER
    ops.syscall_driver = options.syscall_driver;
#endif
    if (options.shadowing) {
        ops.is_byte_addressable = is_byte_addressable;
        if (options.check_uninitialized) {
            ops.is_byte_defined = is_byte_defined;
            ops.is_register_defined = is_register_defined;
        }
    }

#ifdef WINDOWS
    /* i#1908: we support loading numbers from a file */
    char sysnum_path[MAXIMUM_PATH];
    if (options.syscall_number_path[0] != '\0') {
        _snprintf(sysnum_path, BUFFER_SIZE_ELEMENTS(sysnum_path), "%s%c%s",
                  options.syscall_number_path, DIRSEP, sysnum_fname);
    } else {
        _snprintf(sysnum_path, BUFFER_SIZE_ELEMENTS(sysnum_path), "%s%c%s",
                  options.symcache_dir, DIRSEP, sysnum_fname);
    }
    NULL_TERMINATE_BUFFER(sysnum_path);
    ops.sysnum_file = sysnum_path;
    if (!dr_file_exists(sysnum_path)) {
        /* We don't do a full fallback: we won't fall back on a privilege error
         * or something, but if there's no logs/symbols/ file at all we'll
         * try bin/ which is where prior releases put them and asked users to
         * put manually downloaded files.
         */
        if (!obtain_configfile_path(sysnum_path, BUFFER_SIZE_ELEMENTS(sysnum_path),
                                    sysnum_fname) ||
            !dr_file_exists(sysnum_path)) {
            ops.sysnum_file = NULL;
        }
    }
    if (ops.sysnum_file != NULL)
        NOTIFY("Using system call file %s" NL, ops.sysnum_file);
    ops.skip_internal_tables = !options.use_syscall_tables;
#endif
    res = drsys_init(client_id, &ops);
#ifdef WINDOWS
    if (res == DRMF_WARNING_UNSUPPORTED_KERNEL) {
        char os_ver[96];
        get_windows_version_string(os_ver, BUFFER_SIZE_ELEMENTS(os_ver));
        NOTIFY_ERROR("Running on an unsupported operating system version: %s."
                     "%s" NL, os_ver,
                     options.ignore_kernel ? "" :
                     " Exiting to trigger auto-generation of system call information."
                     " Re-run with -ignore_kernel to attempt to continue instead.");
        if (options.ignore_kernel)
            res = DRMF_SUCCESS;
        else
            dr_abort_with_code(STATUS_INVALID_KERNEL_INFO_VERSION);
    }
#endif
    if (res != DRMF_SUCCESS) {
        NOTIFY_ERROR("A fatal error identifying system call information occurred." NL);
        drmemory_abort();
    }

    cls_idx_syscall =
        drmgr_register_cls_field(syscall_context_init, syscall_context_exit);
    ASSERT(cls_idx_syscall > -1, "unable to reserve CLS field");

    syscall_os_init(drcontext _IF_WINDOWS(ntdll_base));

    /* We register our own filter to be independent of
     * drsys_filter_all_syscalls() for our own syscall tracking needs.
     */
    dr_register_filter_syscall_event(event_filter_syscall);
    drmgr_register_pre_syscall_event(event_pre_syscall);
    drmgr_register_post_syscall_event(event_post_syscall);
    if (drsys_filter_all_syscalls() != DRMF_SUCCESS)
        ASSERT(false, "drsys_filter_all_syscalls should never fail");

    /* We support additional system call handling via a separate shared library */
    if (options.auxlib[0] != '\0')
        syscall_load_auxlib(options.auxlib);
}

void
syscall_exit(void)
{
    if (auxlib != NULL && !dr_unload_aux_library(auxlib))
        LOG(1, "WARNING: unable to unload auxlib\n");

    syscall_os_exit();

    if (drsys_exit() != DRMF_SUCCESS)
        ASSERT(false, "drsys failed to exit");

    drmgr_unregister_cls_field(syscall_context_init, syscall_context_exit,
                               cls_idx_syscall);
}

void
syscall_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    syscall_os_module_load(drcontext, info, loaded);
}

void
syscall_handle_callback(void *drcontext)
{
    /* note that this is not quite the same as syscall_context_init() b/c
     * that includes thread init (no callback)
     */
    /* nothing anymore */
}

void
syscall_handle_cbret(void *drcontext)
{
    /* nothing anymore */
}
