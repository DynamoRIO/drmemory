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

#ifndef _DRSYSCALL_OS_H_
#define _DRSYSCALL_OS_H_ 1

#include "utils.h"

#ifdef WINDOWS
# define SYSCALL_NUM_ARG_STORE 14
#else
# define SYSCALL_NUM_ARG_STORE 6 /* 6 is max on Linux */
#endif

#define SYSCALL_NUM_ARG_TRACK IF_WINDOWS_ELSE(26, 6)

/* for diagnostics: eventually provide some runtime option,
 * -logmask or something: for now have to modify this constant
 */
#define SYSCALL_VERBOSE 2

/* syscall numbers are most natural in decimal on linux but hex on windows */
#ifdef LINUX
# define SYSNUM_FMT "%d"
#else
# define SYSNUM_FMT PIFX
#endif

/* extra_info slot usage */
enum {
    /* The size computed by SYSARG_SIZE_IN_FIELD is saved here across the
     * syscall.  We only support one such parameter per syscall.
     */
    EXTRA_INFO_SIZE_FROM_FIELD,
#ifdef LINUX
    EXTRA_INFO_SOCKADDR,
    EXTRA_INFO_MSG_CONTROL,
    EXTRA_INFO_MSG_CONTROLLEN,
#endif
    EXTRA_INFO_MAX,
};

extern int cls_idx_drsys;

extern drsys_options_t drsys_ops;

extern const char * const param_type_names[];

enum {
    /*****************************************/
    /* syscall_arg_t.flags */
    SYSARG_READ                = 0x00000001,
    SYSARG_WRITE               = 0x00000002,
    /* The data structure type has pointers or uninitialized fields
     * or padding and needs special processing according to the
     * SYSARG_TYPE_* code stored in syscall_arg_t.misc.
     */
    SYSARG_COMPLEX_TYPE        = 0x00000004,
    /* the size points at the IO_STATUS_BLOCK param */
    SYSARG_POST_SIZE_IO_STATUS = 0x00000008,
    /* the size points at a poiner-to-8-byte value param */
    SYSARG_POST_SIZE_8BYTES    = 0x00000010,
    /* the param holding the size is a pointer b/c it's an IN OUT var */
    SYSARG_LENGTH_INOUT        = 0x00000020,
    /* The size is not in bytes but in elements where the size of
     * each element is in the misc field.  The misc field can
     * contain <= in which case the element size is stored in that
     * parameter number.
     * This flag trumps SYSARG_COMPLEX_TYPE, so if there is an
     * overlap then special handling must be done for the type.
     */
    SYSARG_SIZE_IN_ELEMENTS    = 0x00000040,
    /* BOOLEAN is only 1 byte so ok if only lsb is defined
     * FIXME: are we going to need the sizes of all the params, esp.
     * when we move to 64-bit?
     */
    SYSARG_INLINED_BOOLEAN     = 0x00000080,
    /* for SYSARG_POST_SIZE_RETVAL on a duplicate entry, nothing is
     * written if the count, given in the first entry, is zero,
     * regardless of the buffer pointer value.
     */
    SYSARG_NO_WRITE_IF_COUNT_0 = 0x00000100,
    /* for handle check */
    SYSARG_IS_HANDLE           = 0x00000200,
    /* i#502-c#5 the arg should be ignored if the next arg is null */
    SYSARG_IGNORE_IF_NEXT_NULL = 0x00000400,

    /*****************************************/
    /* syscall_arg_t.size, using values that cannot be mistaken for
     * a parameter reference.
     */
    /* <available>            = -100, */
    /* used in repeated syscall_arg_t entry for post-syscall size */
    SYSARG_POST_SIZE_RETVAL   = -101,
    /* Size is stored as a field of size 4 bytes with an offset given by
     * syscall_arg_t.misc.  Can only be used by one arg per syscall.
     */
    SYSARG_SIZE_IN_FIELD      = -102,

    /*****************************************/
    /* syscall_arg_t.misc when flags has SYSARG_COMPLEX_TYPE */
    /* The following flags are used on Windows. */
    SYSARG_TYPE_CSTRING                 = DRSYS_TYPE_CSTRING, /* Linux too */
    SYSARG_TYPE_CSTRING_WIDE            = DRSYS_TYPE_CWSTRING,
    SYSARG_TYPE_PORT_MESSAGE            = DRSYS_TYPE_PORT_MESSAGE,
    SYSARG_TYPE_CONTEXT                 = DRSYS_TYPE_CONTEXT,
    SYSARG_TYPE_EXCEPTION_RECORD        = DRSYS_TYPE_EXCEPTION_RECORD,
    SYSARG_TYPE_SECURITY_QOS            = DRSYS_TYPE_SECURITY_QOS,
    SYSARG_TYPE_SECURITY_DESCRIPTOR     = DRSYS_TYPE_SECURITY_DESCRIPTOR,
    SYSARG_TYPE_UNICODE_STRING          = DRSYS_TYPE_UNICODE_STRING,
    SYSARG_TYPE_UNICODE_STRING_NOLEN    = DRSYS_TYPE_LAST + 1,
    SYSARG_TYPE_OBJECT_ATTRIBUTES       = DRSYS_TYPE_OBJECT_ATTRIBUTES,
    SYSARG_TYPE_LARGE_STRING            = DRSYS_TYPE_LARGE_STRING,
    SYSARG_TYPE_DEVMODEW                = DRSYS_TYPE_DEVMODEW,
    SYSARG_TYPE_WNDCLASSEXW             = DRSYS_TYPE_WNDCLASSEXW,
    SYSARG_TYPE_CLSMENUNAME             = DRSYS_TYPE_CLSMENUNAME,
    SYSARG_TYPE_MENUITEMINFOW           = DRSYS_TYPE_MENUITEMINFOW,
    SYSARG_TYPE_ALPC_PORT_ATTRIBUTES    = DRSYS_TYPE_ALPC_PORT_ATTRIBUTES,
    SYSARG_TYPE_ALPC_SECURITY_ATTRIBUTES= DRSYS_TYPE_ALPC_SECURITY_ATTRIBUTES,
    /* These are Linux-specific */
    SYSARG_TYPE_SOCKADDR                = DRSYS_TYPE_SOCKADDR,
    SYSARG_TYPE_MSGHDR                  = DRSYS_TYPE_MSGHDR,
    SYSARG_TYPE_MSGBUF                  = DRSYS_TYPE_MSGBUF,
};

/* We encode the actual size of a write, if it can differ from the
 * requested size, as a subsequent syscall_arg_t entry with the same
 * param#.  A negative size there refers to a parameter that should be
 * de-referenced to obtain the actual write size.  The de-reference size
 * is assumed to be 4 unless SYSARG_POST_SIZE_8BYTES is set.
 */
typedef struct _syscall_arg_t {
    int param; /* ordinal of parameter */
    int size; /* >0 = abs size; <=0 = -param that holds size */
    uint flags; /* SYSARG_ flags */
    /* Meaning depends on flags.  I'd use a union but that would make
     * the syscall tables ugly w/ a ton of braces.
     * Currently used for:
     * - SYSARG_COMPLEX_TYPE: holds SYSARG_TYPE_* enum value
     * - SYSARG_SIZE_IN_ELEMENTS: holds size of array entry
     * - SYSARG_SIZE_IN_FIELD: holds offset of 4-byte size field
     */
    int misc;
} syscall_arg_t;

enum {
    /* If not set, automated param comparison is used to find writes */
    SYSINFO_ALL_PARAMS_KNOWN    = 0x00000001,
    /* When checking the sysnum vs a wrapper function, do not consider
     * removing the prefix
     */
    SYSINFO_REQUIRES_PREFIX     = 0x00000002,
    /* NtUser syscall wrappers are spread across user32.dll and imm32.dll */
    SYSINFO_IMM32_DLL           = 0x00000004,
    /* Return value indicates failure only when zero */
    SYSINFO_RET_ZERO_FAIL       = 0x00000008,
    /* Return value of STATUS_BUFFER_TOO_SMALL (i#486),
     * STATUS_BUFFER_OVERFLOW (i#531), or STATUS_INFO_LENGTH_MISMATCH
     * (i#932) writes final arg but no others.
     * If it turns out some syscalls distinguish between the two ret values
     * we can split the flag up but seems safer to combine.
     */
    SYSINFO_RET_SMALL_WRITE_LAST= 0x00000010,
    /* System call takes a code from one of its params that is in essence
     * a new system call number in a new sub-space.
     * The num_out field contains a pointer to a new syscall_info_t
     * array to use with the first param's code.
     * The first argument field indicates which param contains the code.
     * Any other argument fields in the initial entry are ignored.
     */
    SYSINFO_SECONDARY_TABLE     = 0x00000020,
    /* System call deletes handle */
    SYSINFO_DELETE_HANDLE       = 0x00000040,
    /* System call creates handle
     * we assume that no syscall both returns and has OUT arg,
     * so using the same flag for both cases.
     */
    SYSINFO_CREATE_HANDLE       = 0x00000080,
};

#ifdef WINDOWS
/* unverified but we don't expect pointers beyond 1st 11 args
 * (even w/ dup entries for diff in vs out size to writes)
 */
# define MAX_NONINLINED_ARGS 11
#else
# define MAX_NONINLINED_ARGS 6
#endif

#define SYSCALL_ARG_TRACK_MAX_SZ 2048

typedef struct _syscall_info_t {
    drsys_sysnum_t num; /* system call number: filled in dynamically */
    const char *name;
    uint flags; /* SYSINFO_ flags */
    int arg_count;
    /* list of args that are not inlined */
    syscall_arg_t arg[MAX_NONINLINED_ARGS];
    /* For custom handling w/o separate number lookup.
     * If SYSINFO_SECONDARY_TABLE is set in flags, this is instead
     * a pointer to a new syscall_info_t table.
     * (I'd use a union but that makes syscall table initializers uglier)
     */
    drsys_sysnum_t *num_out;
} syscall_info_t;

typedef struct _cls_syscall_t {
    /* the interface keeps state for API simplicity and for performance */
    drsys_sysnum_t sysnum;
    syscall_info_t *sysinfo;
    dr_mcontext_t mc;
    bool pre;

    /* for recording args so post-syscall can examine */
    reg_t sysarg[SYSCALL_NUM_ARG_STORE];
#ifdef WINDOWS
    reg_t pre_xdx;
#endif

    /* for recording additional info for particular arg types */
    ptr_int_t extra_info[EXTRA_INFO_MAX];
#ifdef DEBUG
    /* We should be able to statically share extra_info[].  This helps find errors. */
    bool extra_inuse[SYSCALL_NUM_ARG_STORE];
#endif
    bool first_iter;
    bool first_iter_generic_loop; /* just for sysarg_get_size */

    /* for comparing memory across unknown system calls */
    bool known;
    app_pc sysarg_ptr[SYSCALL_NUM_ARG_TRACK];
    size_t sysarg_sz[SYSCALL_NUM_ARG_TRACK];
    /* dynamically allocated */
    size_t sysarg_val_bytes[SYSCALL_NUM_ARG_TRACK];
    byte *sysarg_val[SYSCALL_NUM_ARG_TRACK];
} cls_syscall_t;

/* used for simpler arg passing among syscall arg handlers */
typedef struct _sysarg_iter_info_t {
    drsys_arg_t *arg;
    drsys_iter_cb_t cb_mem;
    drsys_iter_cb_t cb_arg;
    void *user_data;
    cls_syscall_t *pt;
    bool abort;
} sysarg_iter_info_t;


drmf_status_t
drsyscall_os_init(void *drcontext);

void
drsyscall_os_exit(void);

syscall_info_t *
syscall_lookup(drsys_sysnum_t num);

void
drsyscall_os_thread_init(void *drcontext);

void
drsyscall_os_thread_exit(void *drcontext);

void
drsyscall_os_module_load(void *drcontext, const module_data_t *info, bool loaded);

bool
is_using_sysenter(void);

bool
is_using_sysint(void);

/* Either sets arg->reg to DR_REG_NULL and sets arg->start_addr, or sets arg->reg
 * to non-DR_REG_NULL
 */
void
drsyscall_os_get_sysparam_location(cls_syscall_t *pt, uint argnum, drsys_arg_t *arg);

/* check syscall param at pre-syscall only */
void
check_sysparam(uint sysnum, uint argnum, dr_mcontext_t *mc, size_t argsz);

/* for memory shadowing checks */
void
os_handle_pre_syscall(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii);

void
os_handle_post_syscall(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii);

/* returns true if the given argument was processed in a non-standard way
 * (e.g. OS-specific structures) and we should skip the standard check
 */
bool
os_handle_pre_syscall_arg_access(sysarg_iter_info_t *ii,
                                 const syscall_arg_t *arg_info,
                                 app_pc start, uint size);

/* returns true if the given argument was processed in a non-standard way
 * (e.g. OS-specific structures) and we should skip the standard check
 */
bool
os_handle_post_syscall_arg_access(sysarg_iter_info_t *ii,
                                  const syscall_arg_t *arg_info,
                                  app_pc start, uint size);

bool
os_syscall_succeeded(drsys_sysnum_t sysnum, syscall_info_t *info, ptr_int_t res);

/* provides name if known when not in syscall_lookup(num) */
const char *
os_syscall_get_name(drsys_sysnum_t num);

bool
os_syscall_get_num(const char *name, drsys_sysnum_t *num OUT);

uint
sysnum_hash(void *val);

bool
sysnum_cmp(void *v1, void *v2);

bool
sysarg_invalid(syscall_arg_t *arg);

void
store_extra_info(cls_syscall_t *pt, int index, ptr_int_t value);

ptr_int_t
release_extra_info(cls_syscall_t *pt, int index);

bool
report_memarg_ex(sysarg_iter_info_t *iter_info,
                 int ordinal, drsys_param_mode_t mode,
                 app_pc ptr, size_t sz, const char *id,
                 drsys_param_type_t type, const char *type_name,
                 drsys_param_type_t containing_type);

bool
report_memarg_type(sysarg_iter_info_t *iter_info,
                   int ordinal, uint arg_flags,
                   app_pc ptr, size_t sz, const char *id,
                   drsys_param_type_t type, const char *type_name);

bool
report_memarg_field(sysarg_iter_info_t *ii,
                    const syscall_arg_t *arg_info,
                    app_pc ptr, size_t sz, const char *id,
                    drsys_param_type_t type, const char *type_name);

bool
report_memarg(sysarg_iter_info_t *iter_info,
              const syscall_arg_t *arg_info,
              app_pc ptr, size_t sz, const char *id);

bool
report_sysarg(sysarg_iter_info_t *iter_info, int ordinal, uint arg_flags);

bool
handle_cstring(sysarg_iter_info_t *ii, int ordinal, uint arg_flags, const char *id,
               byte *start, size_t size/*in bytes*/, char *safe, bool check_addr);

#endif /* _DRSYSCALL_OS_H_ */
