/* **********************************************************
 * Copyright (c) 2010-2012 Google, Inc.  All rights reserved.
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
#include "utils.h"
#include "syscall.h"
#include "shadow.h"
#include "readwrite.h"
#include "syscall_os.h"
#include "alloc.h"
#include "perturb.h"
#ifdef LINUX
# include "sysnum_linux.h"
#endif
#include "report.h"

#ifdef SYSCALL_DRIVER
# include "syscall_driver.h"
#endif

int cls_idx_syscall = -1;

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
    while (sep > path && *sep != '/' IF_WINDOWS(&& *sep != '\\'))
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

static void
auxlib_check_sysparam_defined(void *drcontext, uint sysnum, uint argnum,
                              dr_mcontext_t *mc, size_t argsz)
{
    cls_syscall_t *cpt = (cls_syscall_t *) drmgr_get_cls_field(drcontext, cls_idx_syscall);
    app_loc_t loc;
    reg_id_t reg = sysauxlib_reg_param_info(drcontext, cpt->sysaux_params, argnum);
    ASSERT(options.shadowing, "shadowing disabled");
    syscall_to_loc(&loc, sysnum, NULL);
    check_register_defined(drcontext, reg, &loc, argsz, mc, NULL);
}

static bool
auxlib_shared_pre_syscall(void *drcontext, int sysnum, dr_mcontext_t *mc)
{
    cls_syscall_t *cpt = (cls_syscall_t *) drmgr_get_cls_field(drcontext, cls_idx_syscall);
    char path[MAXIMUM_PATH];
    cpt->sysaux_params = sysauxlib_save_params(drcontext);
#ifdef LINUX
    if (sysauxlib_is_fork(drcontext, cpt->sysaux_params, NULL)) {
        if (options.perturb)
            perturb_pre_fork();
    } else if (sysauxlib_is_exec(drcontext, cpt->sysaux_params,
                                 path, BUFFER_SIZE_BYTES(path)))
        ELOGF(0, f_fork, "EXEC path=%s\n", path);
#endif
    return true;
}

static void
auxlib_shared_post_syscall(void *drcontext, int sysnum, dr_mcontext_t *mc)
{
    cls_syscall_t *cpt = (cls_syscall_t *) drmgr_get_cls_field(drcontext, cls_idx_syscall);
    char path[MAXIMUM_PATH];
    process_id_t child;
    ASSERT(cpt->sysaux_params != NULL, "params should already be saved");
#ifdef LINUX
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
    if (auxlib == NULL || !auxlib_known_syscall(sysnum))
        return true;
    ASSERT(cpt->sysaux_params != NULL, "params should already be saved");
    for (i=0; i<sysauxlib_num_reg_params(drcontext, cpt->sysaux_params); i++)
        auxlib_check_sysparam_defined(drcontext, sysnum, i, mc, sizeof(reg_t));
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
                             sysnum, start, len_in, mc, name);
            }
            if (len_out > 0) {
                check_sysmem(MEMREF_CHECK_ADDRESSABLE,
                             sysnum, start, len_out, mc, name);
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
                    check_sysmem(MEMREF_WRITE, sysnum, start, len_out, mc, name);
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
get_syscall_name(uint num)
{
    syscall_info_t *sysinfo = syscall_lookup(num);
    if (sysinfo != NULL)
        return sysinfo->name;
    else {
        const char *name = auxlib_syscall_name(num);
        if (name != NULL)
            return name;
        else {
            name = os_syscall_get_name(num);
            if (name != NULL)
                return name;
        }
        return "<unknown>";
    }
}

#ifdef WINDOWS
/* uses tables and other sources not available to sysnum_from_name() */
/* will not locate secondary syscalls */
int
get_syscall_num(void *drcontext, const module_data_t *info, const char *name)
{
    return os_syscall_get_num(drcontext, info, name);
}
#endif

bool
syscall_is_known(uint num)
{
    bool known = false;
    syscall_info_t *sysinfo = syscall_lookup(num);
    if (sysinfo != NULL)
        known = TEST(SYSINFO_ALL_PARAMS_KNOWN, sysinfo->flags);
    else
        known = auxlib_known_syscall(num);
    return known;
}


static const byte UNKNOWN_SYSVAL_SENTINEL = 0xab;

/* For syscall we do not have specific parameter info for, we do a
 * memory comparison to find what has been written.
 * We will not catch passing undefined values in that are read, of course.
 */
static void
handle_pre_unknown_syscall(void *drcontext, int sysnum, dr_mcontext_t *mc,
                           cls_syscall_t *cpt)
{
    app_pc start;
    int i, j;
    if (!options.analyze_unknown_syscalls ||
        !options.check_uninitialized)
        return;
    LOG(SYSCALL_VERBOSE, "unknown system call #"PIFX" %s\n",
        sysnum, os_syscall_get_name(sysnum) == NULL ? "" : os_syscall_get_name(sysnum));
    if (options.verbose >= 2) {
        ELOGF(0, f_global, "WARNING: unhandled system call #"PIFX"\n", sysnum);
    } else {
        /* PR 484069: reduce global logfile size */
        DO_ONCE(ELOGF(0, f_global, "WARNING: unhandled system calls found\n"));
    }
    for (i=0; i<SYSCALL_NUM_ARG_TRACK; i++) {
        cpt->sysarg_ptr[i] = NULL;
        if (get_sysparam_shadow_val(sysnum, i, mc) == SHADOW_DEFINED) {
            start = (app_pc) dr_syscall_get_param(drcontext, i);
            LOG(2, "pre-unknown-syscall #"PIFX": param %d == "PFX"\n", sysnum, i, start);
            if (ALIGNED(start, 4) && shadow_get_byte(start) != SHADOW_UNADDRESSABLE) {
                /* This looks like a memory parameter.  It might contain OUT
                 * values mixed with IN, so we do not stop at the first undefined
                 * byte: instead we stop at an unaddr or at the max size.
                 * We need two passes to know how far was can safely read,
                 * so we go ahead and use dynamically sized memory as well.
                 */
                byte *s_at = NULL;
                int prev;
                bool overlap = false;
                for (j=0; j<SYSCALL_ARG_TRACK_MAX_SZ; j++) {
                    for (prev=0; prev<i; prev++) {
                        if (cpt->sysarg_ptr[prev] < start + j &&
                            cpt->sysarg_ptr[prev] + cpt->sysarg_sz[prev] > start) {
                            /* overlap w/ prior arg.  while we could miss some
                             * data due to the max sz we just bail for simplicity.
                             */
                            overlap = true;
                            break;
                        }
                    }
                    if (overlap || shadow_get_byte(start + j) == SHADOW_UNADDRESSABLE)
                        break;
                }
                if (j > 0) {
                    LOG(SYSCALL_VERBOSE,
                        "pre-unknown-syscall #"PIFX": param %d == "PFX" %d bytes\n",
                        sysnum, i, start, j);
                    /* Make a copy of the arg values */
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
                    } else {
                        LOG(SYSCALL_VERBOSE,
                            "WARNING: unable to read syscall arg "PFX"-"PFX"!\n",
                            start, start + j);
                        cpt->sysarg_sz[i] = 0;
                    }
                }
                if (options.syscall_sentinels) {
                    for (j=0; j<cpt->sysarg_sz[i]; j++) {
                        if (shadow_get_byte(start + j) == SHADOW_UNDEFINED) {
                            size_t written;
                            /* Detect writes to data that happened to have the same
                             * value beforehand (happens often with 0) by writing
                             * a sentinel.
                             * XXX: want more-performant safe write on Windows:
                             * xref PR 605237
                             * XXX: another thread could read the data (after
                             * all we're not sure it's really syscall data) and
                             * unexpectedly read the sentinel value
                             */
                            if (s_at == NULL)
                                s_at = start + j;
                            if (!dr_safe_write(start + j, 1,
                                               &UNKNOWN_SYSVAL_SENTINEL, &written) ||
                                written != 1) {
                                /* if page is read-only then assume rest is not OUT */
                                LOG(1, "WARNING: unable to write sentinel value @"PFX"\n",
                                    start + j);
                                break;
                            }
                        } else if (s_at != NULL) {
                            LOG(2, "writing sentinel value to "PFX"-"PFX" %d %d "PFX"\n",
                                s_at, start + j, i, j, cpt->sysarg_ptr[i]);
                            s_at = NULL;
                        }
                    }
                    if (s_at != NULL) {
                        LOG(2, "writing sentinel value to "PFX"-"PFX"\n", s_at, start + j);
                        s_at = NULL;
                    }
                }
            }
        }
    }
}

static void
handle_post_unknown_syscall(void *drcontext, int sysnum, cls_syscall_t *cpt)
{
    int i, j;
    byte *w_at = NULL;
    byte post_val[SYSCALL_ARG_TRACK_MAX_SZ];
    if (!options.analyze_unknown_syscalls ||
        !options.check_uninitialized)
        return;
    /* we analyze params even if syscall failed, since in some cases
     * some params are still written (xref i#486, i#358)
     */
    for (i=0; i<SYSCALL_NUM_ARG_TRACK; i++) {
        if (cpt->sysarg_ptr[i] != NULL) {
            if (safe_read(cpt->sysarg_ptr[i], cpt->sysarg_sz[i], post_val)) {
                for (j = 0; j < cpt->sysarg_sz[i]; j++) {
                    byte *pc = cpt->sysarg_ptr[i] + j;
                    if (shadow_get_byte(pc) == SHADOW_UNDEFINED) {
                        /* kernel could have written sentinel.
                         * XXX: we won't mark as defined if pre-syscall value
                         * matched sentinel and kernel wrote sentinel!
                         */
                        LOG(4, "\targ %d "PFX" %d comparing %x to %x\n", i,
                            cpt->sysarg_ptr[i], j,
                            post_val[j], cpt->sysarg_val[i][j]);
                        if ((options.syscall_sentinels &&
                             post_val[j] != UNKNOWN_SYSVAL_SENTINEL) ||
                            (!options.syscall_sentinels &&
                             post_val[j] != cpt->sysarg_val[i][j])) {
                            if (w_at == NULL)
                                w_at = pc;
                            /* I would assert that this is still marked undefined, to
                             * see if we hit any races, but we have overlapping syscall
                             * args and I don't want to check for them
                             */
                            ASSERT(shadow_get_byte(pc) != SHADOW_UNADDRESSABLE, "");
                            if (options.syscall_dword_granularity) {
                                /* w/o sentinels (which are dangerous) we often miss
                                 * seemingly unchanged bytes (often zero) so mark
                                 * the containing dword (i#477)
                                 */
                                shadow_set_range((byte *)ALIGN_BACKWARD(pc, 4),
                                                 (byte *)ALIGN_BACKWARD(pc, 4) + 4,
                                                 SHADOW_DEFINED);
                            } else {
                                shadow_set_byte(pc, SHADOW_DEFINED);
                            }
                        } else {
                            if (post_val[j] == UNKNOWN_SYSVAL_SENTINEL &&
                                cpt->sysarg_val[i][j] != UNKNOWN_SYSVAL_SENTINEL) {
                                /* kernel didn't write so restore app value that
                                 * we clobbered w/ our sentinel.
                                 */
                                size_t written;
                                LOG(4, "restoring app sysval @"PFX"\n", pc);
                                if (!dr_safe_write(pc, 1, &cpt->sysarg_val[i][j],
                                                   &written) || written != 1) {
                                    LOG(1, "WARNING: unable to restore app sysval @"PFX"\n",
                                        pc);
                                }
                            }
                            if (w_at != NULL) {
                                LOG(SYSCALL_VERBOSE, "unknown-syscall #"PIFX
                                    ": param %d written "PFX" %d bytes\n",
                                    sysnum, i, w_at, pc - w_at);
                                w_at = NULL;
                            }
                        }
                    } else {
                        LOG(4, "\targ %d "PFX" byte %d defined\n", i,
                            cpt->sysarg_ptr[i], j);
                    }
                }
                if (w_at != NULL) {
                    LOG(SYSCALL_VERBOSE, "unknown-syscall #"PIFX": param %d written "
                        PFX" %d bytes\n",
                        sysnum, i, w_at, (cpt->sysarg_ptr[i] + j) - w_at);
                    w_at = NULL;
                }
            } else {
                /* If we can't read I assume we are also unable to write to undo
                 * sentinel writes: though should try since param could span pages
                 */
                LOG(1, "WARNING: unable to read app sysarg @"PFX"\n", cpt->sysarg_ptr[i]);
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
        handle_mem_ref(flags, &loc, ptr, sz, mc, NULL);
    }
}

bool
sysarg_invalid(syscall_arg_t *arg)
{
    return (arg->param == 0 && arg->size == 0 && arg->flags == 0);
}

#ifndef MAX_PATH
# define MAX_PATH 4096
#endif

/* pass 0 for size if there is no max size */
bool
handle_cstring(bool pre, int sysnum, dr_mcontext_t *mc, const char *id,
               byte *start, size_t size/*in bytes*/, uint arg_flags, char *safe,
               bool check_addr)
{
    uint check_type = SYSARG_CHECK_TYPE(arg_flags, pre);
    /* the kernel wrote a wide string to the buffer: only up to the terminating
     * null should be marked as defined
     */
    uint i;
    char c;
    /* input params have size 0: for safety stopping at MAX_PATH */
    size_t maxsz = (size == 0) ? (MAX_PATH*sizeof(char)) : size;
    if (start == NULL)
        return false; /* nothing to do */
    if (pre && !TEST(SYSARG_READ, arg_flags)) {
        if (!check_addr)
            return false;
        if (size > 0) {
            /* if max size specified, on pre-write check whole thing for addr */
            check_sysmem(check_type, sysnum, start, size, mc, id);
            return true;
        }
    }
    if (!pre && !TEST(SYSARG_WRITE, arg_flags))
        return false; /*nothing to do */
    for (i = 0; i < maxsz; i += sizeof(char)) {
        if (safe != NULL)
            c = safe[i/sizeof(char)];
        else if (!safe_read(start + i, sizeof(c), &c)) {
            WARN("WARNING: unable to read syscall param string\n");
            break;
        }
        if (c == L'\0')
            break;
    }
    check_sysmem(check_type, sysnum, start, i + sizeof(char), mc, id);
    return true;
}

/* assumes pt->sysarg[] has already been filled in */
static ptr_uint_t
sysarg_get_size(void *drcontext, cls_syscall_t *pt, syscall_arg_t *arg,
                int argnum, bool pre, byte *start, int sysnum, dr_mcontext_t *mc)
{
    ptr_uint_t size = 0;
    if (arg->size == SYSARG_POST_SIZE_RETVAL) {
        /* XXX: some syscalls (in particular NtGdi* and NtUser*) return
         * the capacity needed when the input buffer is NULL or
         * size of input buffer is given as 0.  For the buffer being NULL
         * we won't erroneously mark as defined, but for size being 0
         * if buffer is non-NULL we could: entry should use
         * SYSARG_NO_WRITE_IF_COUNT_0 in such cases.
         */
        if (pre) {
            /* Can't ask for retval on pre but we have a few syscalls where the
             * pre-size is only known if the app makes a prior syscall (w/ NULL
             * buffer, usually) to find it out: i#485.  Today we don't handle that
             * and thus don't check for unaddr until after the kernel writes.
             */
            size = 0;
        } else {
            size = dr_syscall_get_result(drcontext);
        }
    } else if (arg->size == SYSARG_SIZE_IN_FIELD) {
        /* 4-byte size field in struct */
        uint sz;
        byte *field = start + arg->misc/*offs of size field */;
        if (start != NULL) {
            /* by using this flag, os-specific code gives up first access rights
             * (i.e., to skip this check, don't use this flag)
             */
            if (pre) {
                check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum,
                             field, sizeof(sz), mc, NULL);
            }
            if (safe_read(field, sizeof(sz), &sz))
                size = sz;
            else
                WARN("WARNING: cannot read struct size field\n");
        }
    } else {
        ASSERT(arg->size > 0 || -arg->size < SYSCALL_NUM_ARG_STORE,
               "reached max syscall args stored");
        size = (arg->size > 0) ? arg->size : ((uint) pt->sysarg[-arg->size]);
        if (TEST(SYSARG_LENGTH_INOUT, arg->flags)) {
            /* for x64 can't just take cur val of size so recompute */
            size_t *ptr;
            ASSERT(arg->size <= 0, "inout can't be immed");
            ptr = (size_t *) pt->sysarg[-arg->size];
            /* XXX: in some cases, ptr isn't checked for definedness until
             * after this de-ref (b/c the SYSARG_READ entry is after this
             * entry in the arg array: we could re-arrange the entries?
             */
            if (ptr == NULL || !safe_read((void *)ptr, sizeof(size), &size))
                size = 0;
        } else if (TEST(SYSARG_POST_SIZE_IO_STATUS, arg->flags)) {
#ifdef WINDOWS
            IO_STATUS_BLOCK *status = (IO_STATUS_BLOCK *) pt->sysarg[-arg->size];
            ULONG sz;
            ASSERT(sizeof(status->Information) == sizeof(sz), "");
            ASSERT(!pre, "post-io flag should be on dup entry only");
            ASSERT(arg->size <= 0, "io block can't be immed");
            if (safe_read((void *)(&status->Information), sizeof(sz), &sz))
                size = sz;
            else
                WARN("WARNING: cannot read IO_STATUS_BLOCK\n");
#else
            ASSERT(false, "linux should not have io_status flag set");
#endif
        }
    }
    if (TEST(SYSARG_SIZE_IN_ELEMENTS, arg->flags)) {
        ASSERT(arg->misc > 0 || -arg->misc < SYSCALL_NUM_ARG_STORE,
               "reached max syscall args stored");
        size *= ((arg->misc > 0) ? arg->misc : ((int) pt->sysarg[-arg->misc]));
    }
    return size;
}

static void
process_pre_syscall_reads_and_writes(void *drcontext, int sysnum, dr_mcontext_t *mc,
                                     syscall_info_t *sysinfo)
{
    cls_syscall_t *pt = (cls_syscall_t *) drmgr_get_cls_field(drcontext, cls_idx_syscall);
    app_pc start;
    ptr_uint_t size;
    uint num_args;
    int i, last_param = -1;
    char idmsg[32];

    LOG(2, "processing pre system call #"PIFX" %s\n", sysnum, sysinfo->name);
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
        LOG(SYSCALL_VERBOSE, "\t  pre considering arg %d %d %x\n", sysinfo->arg[i].param,
            sysinfo->arg[i].size, sysinfo->arg[i].flags);
        if (sysarg_invalid(&sysinfo->arg[i]))
            break;

        /* The length written may not match that requested, so we check whether
         * addressable at pre-syscall point but only mark as defined (i.e.,
         * commit the write) at post-syscall when know true length.  This also
         * waits to determine syscall success before committing, but it opens up
         * more possibilities for races (PR 408540).  When the pre and post
         * sizes differ, we indicate what the post-syscall write size is via a
         * second entry w/ the same param#.
         * Xref PR 408536.
         */
        if (sysinfo->arg[i].param == last_param) {
            /* Only used in post-syscall */
            continue;
        }
        last_param = sysinfo->arg[i].param;

        if (TEST(SYSARG_INLINED_BOOLEAN, sysinfo->arg[i].flags))
            continue;

        start = (app_pc) dr_syscall_get_param(drcontext, sysinfo->arg[i].param);
        size = sysarg_get_size(drcontext, pt, &sysinfo->arg[i], i, true/*pre*/, start,
                               sysnum, mc);

        /* FIXME PR 406355: we don't record which params are optional 
         * FIXME: some OUT params may not be written if the IN is bogus:
         * we should check here since harder to undo post-syscall on failure.
         */
        if (start != NULL && size > 0) {
            bool skip = os_handle_pre_syscall_arg_access(sysnum, mc, i,
                                                         &sysinfo->arg[i],
                                                         start, size);

            /* pass syscall # as pc for reporting purposes */
            /* we treat in-out read-and-write as simply read, since if
             * not defined we'll report and then mark as defined anyway.
             */
            if (!skip) {
                /* indicate which syscall arg (i#510) */
                IF_DEBUG(int res = )
                    dr_snprintf(idmsg, BUFFER_SIZE_ELEMENTS(idmsg), "parameter #%d",
                                sysinfo->arg[i].param);
                ASSERT(res > 0 && res < BUFFER_SIZE_ELEMENTS(idmsg),
                       "message buffer too small");
                NULL_TERMINATE_BUFFER(idmsg);

                check_sysmem((TEST(SYSARG_READ, sysinfo->arg[i].flags) ?
                             MEMREF_CHECK_DEFINEDNESS : MEMREF_CHECK_ADDRESSABLE),
                             sysnum, start, size, mc, idmsg);
            }
        }
    }
}

static void
process_post_syscall_reads_and_writes(void *drcontext, int sysnum, dr_mcontext_t *mc,
                                      syscall_info_t *sysinfo)
{
    cls_syscall_t *pt = (cls_syscall_t *) drmgr_get_cls_field(drcontext, cls_idx_syscall);
    app_pc start;
    ptr_uint_t size, last_size = 0;
    uint num_args;
    int i, last_param = -1;
    IF_DEBUG(int res;)
    char idmsg[32];
#ifdef WINDOWS
    ptr_int_t result = dr_syscall_get_result(drcontext);
#endif
    LOG(SYSCALL_VERBOSE, "processing post system call #");
    if (SYSNUM_HAS_SECONDARY(sysnum)) {
        LOG(SYSCALL_VERBOSE, PIFX"."PIFX, SYSNUM_PRIMARY(sysnum),
            SYSNUM_SECONDARY(sysnum));
    } else
        LOG(SYSCALL_VERBOSE, PIFX, sysnum);
    LOG(SYSCALL_VERBOSE, " %s res="PIFX"\n",
        sysinfo->name, dr_syscall_get_result(drcontext));
    num_args = SYSINFO_NUM_ARGS(sysinfo);
    for (i=0; i<num_args; i++) {
        LOG(SYSCALL_VERBOSE, "\t  post considering arg %d %d %x "PFX"\n",
            sysinfo->arg[i].param, sysinfo->arg[i].size, sysinfo->arg[i].flags,
            pt->sysarg[sysinfo->arg[i].param]);
        if (sysarg_invalid(&sysinfo->arg[i]))
            break;
        ASSERT(i < SYSCALL_NUM_ARG_STORE, "not storing enough args");
        if (!TEST(SYSARG_WRITE, sysinfo->arg[i].flags))
            continue;
        ASSERT(!TEST(SYSARG_INLINED_BOOLEAN, sysinfo->arg[i].flags),
               "inlined bool should always be read, not write");
#ifdef WINDOWS
        /* i#486, i#531, i#932: for too-small buffer, only last param written */
        if (TEST(SYSINFO_RET_SMALL_WRITE_LAST, sysinfo->flags) &&
            (result == STATUS_BUFFER_TOO_SMALL ||
             result == STATUS_BUFFER_OVERFLOW ||
             result == STATUS_INFO_LENGTH_MISMATCH) &&
            i+1 < num_args &&
            !sysarg_invalid(&sysinfo->arg[i+1]))
            continue;
#endif

        start = (app_pc) pt->sysarg[sysinfo->arg[i].param];
        size = sysarg_get_size(drcontext, pt, &sysinfo->arg[i], i, false/*!pre*/, start,
                               sysnum, mc);
        /* indicate which syscall arg (i#510) */
        IF_DEBUG(res = )
            dr_snprintf(idmsg, BUFFER_SIZE_ELEMENTS(idmsg), "parameter #%d",
                        sysinfo->arg[i].param);
        ASSERT(res > 0 && res < BUFFER_SIZE_ELEMENTS(idmsg), "message buffer too small");
        NULL_TERMINATE_BUFFER(idmsg);

        if (sysinfo->arg[i].param == last_param) {
            /* For a double entry, the 2nd indicates the actual written size */
            if (size == 0
                IF_WINDOWS(/* i#798: On async write, use capacity, not OUT size. */
                           || result == STATUS_PENDING
                           /* i#486, i#531: don't use OUT size on partial write */
                           || result == STATUS_BUFFER_TOO_SMALL
                           || result == STATUS_BUFFER_OVERFLOW)) {
                /* we use SYSARG_LENGTH_INOUT for some optional params: in that
                 * case use the 1st entry's max size.
                 * XXX: we could put in our own param when the app supplies NULL
                 */
                size = last_size;
            }
            if (TEST(SYSARG_NO_WRITE_IF_COUNT_0, sysinfo->arg[i].flags)) {
                /* Currently used only for NtUserGetKeyboardLayoutList.
                 * If the count (passed in a param indicated by the first entry's
                 * size field) is zero, the kernel returns the capacity needed,
                 * but doesn't write anything, regardless of the buffer value.
                 */
                ASSERT(i > 0, "logic error");
                ASSERT(sysinfo->arg[i-1].size <= 0, "invalid syscall table entry");
                if (pt->sysarg[-sysinfo->arg[i-1].size] == 0)
                    size = 0;
            }
            if (start != NULL && size > 0) {
                bool skip = os_handle_post_syscall_arg_access
                    (sysnum, mc, i, &sysinfo->arg[i], start, size);
                if (!skip)
                    check_sysmem(MEMREF_WRITE, sysnum, start, size, mc, idmsg);
            }
            continue;
        }
        last_param = sysinfo->arg[i].param;
        last_size = size;
        /* If the first in a double entry, give 2nd entry precedence, but
         * keep size in last_size in case 2nd was optional OUT and is NULL
         */
        if (i < num_args && sysinfo->arg[i+1].param == last_param &&
            !sysarg_invalid(&sysinfo->arg[i+1]))
            continue;
        LOG(SYSCALL_VERBOSE, "\t     start "PFX", size "PIFX"\n", start, size);
        if (start != NULL && size > 0) {
            bool skip = os_handle_post_syscall_arg_access(sysnum, mc, i,
                                                          &sysinfo->arg[i],
                                                          start, size);
            if (!skip)
                check_sysmem(MEMREF_WRITE, sysnum, start, size, mc, idmsg);
        }
    }
}

syscall_info_t *
get_sysinfo(int *sysnum IN OUT, cls_syscall_t *pt)
{
    syscall_info_t *sysinfo = syscall_lookup(*sysnum);
    if (sysinfo != NULL) {
        if (TEST(SYSINFO_SECONDARY_TABLE, sysinfo->flags)) {
            uint code;
            ASSERT(SYSINFO_NUM_ARGS(sysinfo) >= 1, "at least 1 arg for code");
            code = pt->sysarg[sysinfo->arg[0].param];
            /* encode a new sysnum */
            ASSERT((uint)*sysnum <= SYSNUM_MAX_PRIMARY, "sysnum too large");
            ASSERT(code <= SYSNUM_MAX_SECONDARY, "secondary sysnum too large");
            *sysnum = SYSNUM_COMBINE(*sysnum, code);
            /* get a new sysinfo */
            sysinfo = syscall_lookup(*sysnum);
        }
    }
    return sysinfo;
}

static bool
event_pre_syscall(void *drcontext, int sysnum)
{
    cls_syscall_t *pt = (cls_syscall_t *) drmgr_get_cls_field(drcontext, cls_idx_syscall);
    syscall_info_t *sysinfo;
    dr_mcontext_t mc; /* do not init whole thing: memset is expensive */
    int i;
    bool res = true;
    mc.size = sizeof(mc);
    mc.flags = DR_MC_CONTROL|DR_MC_INTEGER; /* don't need xmm */
    dr_get_mcontext(drcontext, &mc);

#ifdef STATISTICS
    /* XXX: we could dynamically allocate entries and separate secondary syscalls */
    if (sysnum >= MAX_SYSNUM-1) {
        ATOMIC_INC32(syscall_invoked[MAX_SYSNUM-1]);
    } else {
        ATOMIC_INC32(syscall_invoked[sysnum]);
    }
#endif

    LOG(SYSCALL_VERBOSE, "system call #"PIFX" %s\n", sysnum, get_syscall_name(sysnum));
    DOLOG(SYSCALL_VERBOSE, { 
        /* for sysenter, pc is at vsyscall and there's no frame for wrapper.
         * simplest soln: skip to wrapper now.
         */
        app_pc tmp = mc.pc;
        app_pc parent;
        if (safe_read((void *)mc.xsp, sizeof(parent), &parent))
            mc.pc = parent;
        report_callstack(drcontext, &mc);
        mc.pc = tmp;
    });

    /* save params for post-syscall access 
     * FIXME: it's possible for a pathological app to crash us here
     * by setting up stack so that our blind reading of SYSCALL_NUM_ARG_STORE
     * params will hit unreadable page: should use TRY/EXCEPT
     */
    for (i = 0; i < SYSCALL_NUM_ARG_STORE; i++) {
        pt->sysarg[i] = dr_syscall_get_param(drcontext, i);
        LOG(SYSCALL_VERBOSE, "\targ %d = "PIFX"\n", i, pt->sysarg[i]);
    }

    /* acquire expanded sysnum for os_shared_pre_syscall() in addition to
     * shadow checks
     */
    sysinfo = get_sysinfo(&sysnum, pt);
    DOLOG(SYSCALL_VERBOSE, {
        if (sysinfo != NULL && SYSNUM_HAS_SECONDARY(sysnum)) {
            LOG(SYSCALL_VERBOSE, "system call #"PIFX"."PIFX" %s\n",
                SYSNUM_PRIMARY(sysnum), SYSNUM_SECONDARY(sysnum),
                get_syscall_name(sysnum));
        }
    });

    /* give os-specific-code chance to do non-shadow processing */
    res = os_shared_pre_syscall(drcontext, pt, sysnum _IF_WINDOWS(&mc));
    if (auxlib_known_syscall(sysnum))
        res = auxlib_shared_pre_syscall(drcontext, sysnum, &mc) && res;

    /* FIXME: i#750 need enable system call parameter checks in pattern mode. */
    if (options.shadowing) {
        bool known = false;
        if (sysinfo != NULL) {
            known = TEST(SYSINFO_ALL_PARAMS_KNOWN, sysinfo->flags);
            process_pre_syscall_reads_and_writes(drcontext, sysnum, &mc, sysinfo);
            res = os_shadow_pre_syscall(drcontext, pt, sysnum) && res;
        }
        /* there may be overlap between our table and auxlib: e.g., SYS_ioctl */
        if (auxlib_known_syscall(sysnum)) {
            known = true;
            res = auxlib_shadow_pre_syscall(drcontext, sysnum, &mc) && res;
        }
        if (!known) {
            handle_pre_unknown_syscall(drcontext, sysnum, &mc, pt);
        }
    }

    /* syscall-specific handling we ourselves need, which must come after
     * shadow handling for proper NtContinue handling and proper
     * NtCallbackReturn handling
     */
    handle_pre_alloc_syscall(drcontext, sysnum, &mc, pt->sysarg, SYSCALL_NUM_ARG_STORE);

    if (options.perturb)
        res = perturb_pre_syscall(drcontext, sysnum) && res;

#ifdef SYSCALL_DRIVER
    /* do this as late as possible to avoid our own syscalls from corrupting
     * the list of writes.
     * the current plan is to query the driver on all syscalls, not just unknown,
     * as a sanity check on both sides.
     */
    if (options.syscall_driver)
        driver_pre_syscall(drcontext, sysnum);
#endif

    return res;
}

static void
event_post_syscall(void *drcontext, int sysnum)
{
    cls_syscall_t *pt = (cls_syscall_t *) drmgr_get_cls_field(drcontext, cls_idx_syscall);
    dr_mcontext_t mc; /* do not init whole thing: memset is expensive */
    mc.size = sizeof(mc);
    mc.flags = DR_MC_CONTROL|DR_MC_INTEGER; /* don't need xmm */
    dr_get_mcontext(drcontext, &mc);

#ifdef SYSCALL_DRIVER
    /* do this as early as possible to avoid drmem's own syscalls.
     * unfortunately the module load event runs before this: so we skip
     * NtMapViewOfSection.
     */
    if (options.syscall_driver) {
        const char *name = get_syscall_name(sysnum);
        if (name == NULL || strcmp(name, "NtMapViewOfSection") != 0)
            driver_process_writes(drcontext, sysnum);
    }
#endif

    handle_post_alloc_syscall(drcontext, sysnum, &mc, pt->sysarg, SYSCALL_NUM_ARG_STORE);
    os_shared_post_syscall(drcontext, pt, sysnum _IF_WINDOWS(&mc));
    if (auxlib_known_syscall(sysnum))
        auxlib_shared_post_syscall(drcontext, sysnum, &mc);

    if (options.shadowing) {
        bool known = false;
        syscall_info_t *sysinfo;

        /* post-syscall, eax is defined */
        register_shadow_set_dword(REG_XAX, SHADOW_DWORD_DEFINED);

        sysinfo = get_sysinfo(&sysnum, pt);
        if (sysinfo != NULL) {
            known = TEST(SYSINFO_ALL_PARAMS_KNOWN, sysinfo->flags);
            if (!os_syscall_succeeded(sysnum, sysinfo,
                                      (ptr_int_t)dr_syscall_get_result(drcontext))) {
                LOG(SYSCALL_VERBOSE, "system call %i %s failed with "PFX"\n",
                    sysnum, get_syscall_name(sysnum), dr_syscall_get_result(drcontext));
            } else {
                /* commit the writes via MEMREF_WRITE */
                process_post_syscall_reads_and_writes(drcontext, sysnum, &mc, sysinfo);
            }
            os_shadow_post_syscall(drcontext, pt, sysnum);
        }
        if (auxlib_known_syscall(sysnum)) {
            known = true;
            auxlib_shadow_post_syscall(drcontext, sysnum, &mc);
        }
        if (!known)
            handle_post_unknown_syscall(drcontext, sysnum, pt);
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
    int i;
    for (i = 0; i < SYSCALL_NUM_ARG_TRACK; i++) {
        if (cpt->sysarg_val_bytes[i] > 0) {
            ASSERT(cpt->sysarg_val[i] != NULL, "sysarg alloc error");
            thread_free(drcontext, cpt->sysarg_val[i], cpt->sysarg_val_bytes[i],
                        HEAPSTAT_MISC);
        } else {
            ASSERT(cpt->sysarg_val[i] == NULL, "sysarg alloc error");
        }
    }
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

void
syscall_init(void *drcontext _IF_WINDOWS(app_pc ntdll_base))
{
    cls_idx_syscall = drmgr_register_cls_field(syscall_context_init, syscall_context_exit);
    ASSERT(cls_idx_syscall > -1, "unable to reserve CLS field");

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
    drmgr_register_pre_syscall_event(event_pre_syscall);
    dr_register_post_syscall_event(event_post_syscall);

    /* We support additional system call handling via a separate shared library */
    if (options.auxlib[0] != '\0')
        syscall_load_auxlib(options.auxlib);

#ifdef SYSCALL_DRIVER
    if (options.syscall_driver)
        driver_init();
#endif
}

void
syscall_exit(void)
{
#ifdef SYSCALL_DRIVER
    if (options.syscall_driver)
        driver_exit();
#endif

    if (auxlib != NULL && !dr_unload_aux_library(auxlib))
        LOG(1, "WARNING: unable to unload auxlib\n");
 
    syscall_os_exit();

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
#ifdef SYSCALL_DRIVER
    if (options.syscall_driver)
        driver_handle_callback(drcontext);
#endif
}

void
syscall_handle_cbret(void *drcontext)
{
    /* we could get rid of this and call from syscall_context_exit() for !thread_exit */
#ifdef SYSCALL_DRIVER
    if (options.syscall_driver)
        driver_handle_cbret(drcontext);
#endif
}
