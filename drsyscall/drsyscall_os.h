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

#ifndef _SYSCALL_OS_H_
#define _SYSCALL_OS_H_ 1

#ifdef WINDOWS
# define SYSCALL_NUM_ARG_STORE 14
#else
# define SYSCALL_NUM_ARG_STORE 6 /* 6 is max on Linux */
#endif

#define SYSCALL_NUM_ARG_TRACK IF_WINDOWS_ELSE(26, 6)

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

extern int cls_idx_syscall;

typedef struct _cls_syscall_t {
    /* for recording args so post-syscall can examine */
    reg_t sysarg[SYSCALL_NUM_ARG_STORE];

    /* for recording additional info for particular arg types */
    ptr_int_t extra_info[EXTRA_INFO_MAX];
#ifdef DEBUG
    /* We should be able to statically share extra_info[].  This helps find errors. */
    bool extra_inuse[SYSCALL_NUM_ARG_STORE];
#endif

    /* for comparing memory across unknown system calls */
    app_pc sysarg_ptr[SYSCALL_NUM_ARG_TRACK];
    size_t sysarg_sz[SYSCALL_NUM_ARG_TRACK];
    /* dynamically allocated */
    size_t sysarg_val_bytes[SYSCALL_NUM_ARG_TRACK];
    byte *sysarg_val[SYSCALL_NUM_ARG_TRACK];

    /* Saves syscall params across syscall */
    void *sysaux_params;

#ifdef WINDOWS
    /* for GDI checks (i#752) */
    HDC paintDC;
    /* for handle leak checks (i#974) */
    void *handle_info;
#endif
} cls_syscall_t;

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
    SYSARG_TYPE_PORT_MESSAGE            =  0,
    SYSARG_TYPE_CONTEXT                 =  1,
    SYSARG_TYPE_EXCEPTION_RECORD        =  2,
    SYSARG_TYPE_SECURITY_QOS            =  3,
    SYSARG_TYPE_SECURITY_DESCRIPTOR     =  4,
    SYSARG_TYPE_UNICODE_STRING          =  5,
    SYSARG_TYPE_CSTRING_WIDE            =  6,
    SYSARG_TYPE_OBJECT_ATTRIBUTES       =  7,
    SYSARG_TYPE_LARGE_STRING            =  8,
    SYSARG_TYPE_DEVMODEW                =  9,
    SYSARG_TYPE_WNDCLASSEXW             = 10,
    SYSARG_TYPE_CLSMENUNAME             = 11,
    SYSARG_TYPE_MENUITEMINFOW           = 12,
    SYSARG_TYPE_UNICODE_STRING_NOLEN    = 13,
    SYSARG_TYPE_CSTRING                 = 14, /* Linux too */
    SYSARG_TYPE_ALPC_PORT_ATTRIBUTES    = 15,
    SYSARG_TYPE_ALPC_SECURITY_ATTRIBUTES= 16,
    /* These are Linux-specific */
    SYSARG_TYPE_SOCKADDR                = 17,
    SYSARG_TYPE_MSGHDR                  = 18,
    SYSARG_TYPE_MSGBUF                  = 19,
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
    int num; /* system call number: filled in dynamically */
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
    int *num_out;
} syscall_info_t;

#define SYSARG_CHECK_TYPE(flags, pre) \
    ((pre) ? (TEST(SYSARG_READ, (flags)) ? \
              MEMREF_CHECK_DEFINEDNESS : MEMREF_CHECK_ADDRESSABLE) : \
     (TEST(SYSARG_WRITE, (flags)) ? MEMREF_WRITE : 0))

/* For secondary syscalls, b/c we have "int sysnum" as a param all over the place,
 * we don't want to introduce a compound type.
 * So, we pack it into a single integer value.
 * Because we store it as a 24-bit value in packed_frame_t we limit to 24 bits
 * everywhere.
 * We assume the primary maxes out at 0x3fff and the secondary at 0x1ff
 * which is true for all uses today: but we if we start using secondary
 * for ioctls we will need to expand this and perhaps have a different way
 * of encoding into packed_frame_t.
 * Top bit indicates whether secondary exists (since sysnum can be 0).
 */
#define SYSNUM_HAS_SECONDARY(combined) ((combined) & 0x800000)
#define SYSNUM_COMBINE(primary, secondary) ((primary) | ((secondary) << 14) | 0x800000)
#define SYSNUM_MAX_PRIMARY 0x3fff
#define SYSNUM_PRIMARY(combined) ((combined) & 0x3fff)
#define SYSNUM_MAX_SECONDARY 0x1ff
#define SYSNUM_SECONDARY(combined) (((combined) >> 14) & SYSNUM_MAX_SECONDARY)

void
syscall_os_init(void *drcontext _IF_WINDOWS(app_pc ntdll_base));

void
syscall_os_exit(void);

syscall_info_t *
syscall_lookup(int num);

void
syscall_os_thread_init(void *drcontext);

void
syscall_os_thread_exit(void *drcontext);

void
syscall_os_module_load(void *drcontext, const module_data_t *info, bool loaded);

uint
get_sysparam_shadow_val(uint sysnum, uint argnum, dr_mcontext_t *mc);

/* check syscall param at pre-syscall only */
void
check_sysparam(uint sysnum, uint argnum, dr_mcontext_t *mc, size_t argsz);

/* for tasks unrelated to shadowing that are common to all tools */
bool
os_shared_pre_syscall(void *drcontext, cls_syscall_t *pt, int sysnum
                      _IF_WINDOWS(dr_mcontext_t *mc));

void
os_shared_post_syscall(void *drcontext, cls_syscall_t *pt, int sysnum
                       _IF_WINDOWS(dr_mcontext_t *mc));

/* for memory shadowing checks */
bool
os_shadow_pre_syscall(void *drcontext, cls_syscall_t *pt, int sysnum);

void
os_shadow_post_syscall(void *drcontext, cls_syscall_t *pt, int sysnum);

/* returns true if the given argument was processed in a non-standard way
 * (e.g. OS-specific structures) and we should skip the standard check
 */
bool
os_handle_pre_syscall_arg_access(int sysnum, dr_mcontext_t *mc, uint arg_num,
                                 const syscall_arg_t *arg_info,
                                 app_pc start, uint size);

/* returns true if the given argument was processed in a non-standard way
 * (e.g. OS-specific structures) and we should skip the standard check
 */
bool
os_handle_post_syscall_arg_access(int sysnum, dr_mcontext_t *mc, uint arg_num,
                                  const syscall_arg_t *arg_info,
                                  app_pc start, uint size);

bool
os_syscall_succeeded(int sysnum, syscall_info_t *info, ptr_int_t res);

/* provides name if known when not in syscall_lookup(num) */
const char *
os_syscall_get_name(uint num);

#ifdef WINDOWS
/* uses tables and other sources not available to sysnum_from_name() */
int
os_syscall_get_num(void *drcontext, const module_data_t *info, const char *name);
#endif

syscall_info_t *
get_sysinfo(int *sysnum IN OUT, cls_syscall_t *pt);

bool
sysarg_invalid(syscall_arg_t *arg);

void
store_extra_info(cls_syscall_t *pt, int index, ptr_int_t value);

ptr_int_t
release_extra_info(cls_syscall_t *pt, int index);

#endif /* _SYSCALL_OS_H_ */
