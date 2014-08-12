/* **********************************************************
 * Copyright (c) 2014 Google, Inc.  All rights reserved.
 * **********************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of Google, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "drsyscall.h"
#include "windefs.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#define OUTBUF_SIZE 2048
/* took these unicode string sizes from real drstrace output */
#define UNICODE_STR_SIZE 72
#define UNICODE_BUF_MAX_SIZE 538

typedef struct _buf_info_t {
    char buf[OUTBUF_SIZE];
    size_t sofar;
    ssize_t len;
} buf_info_t;

extern bool
drstrace_unit_test_syscall_arg_iteration(drsys_arg_t arg, void *user_data);
extern bool
drstrace_unit_test_syscall_init();
extern bool
drstrace_unit_test_syscall_exit();

static void
init_arg(drsys_arg_t *arg,
         const char *arg_name,
         drsys_param_type_t containing_type,
         drsys_param_mode_t mode,
         size_t size,
         void *start_addr,
         int ordinal,
         drsys_syscall_t *syscall,
         drsys_sysnum_t sysnum,
         drsys_param_type_t type,
         bool pre,
         reg_id_t reg,
         const char *type_name,
         bool valid,
         const char *enum_name,
         ptr_uint_t value,
         ptr_uint_t value64) {

    if (arg == NULL)
        return;
    arg->arg_name = arg_name;
    arg->containing_type = containing_type;
    arg->mode = mode;
    arg->size = size;
    arg->start_addr = start_addr;
    arg->ordinal = ordinal;
    arg->syscall = syscall;
    arg->sysnum.number = sysnum.number;
    arg->sysnum.secondary = sysnum.secondary;
    arg->type = type;
    arg->pre = pre;
    arg->reg = reg;
    arg->type_name = type_name;
    arg->valid = valid;
    arg->enum_name = enum_name;
    arg->value = value;
    arg->value64 = value64;

    return;
}

static void
check_output(drsys_arg_t arg, char *check_data)
{
    void *out_data = calloc(1, sizeof(buf_info_t));
    drstrace_unit_test_syscall_arg_iteration(arg, out_data);
    if (strcmp((char *)out_data, check_data) != 0)
        dr_abort();
    printf((char *)out_data);
    free(out_data);
}

int
main(int argc, char **argv, char **envp)
{
    drsys_arg_t arg;
    drsys_sysnum_t sysnum;
    WCHAR wbuf[UNICODE_BUF_MAX_SIZE]; /* buffer to test UNICODE_STRING printing */
    char *out_buf;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK io;
    LARGE_INTEGER li;
    HANDLE handle;
    char check_str[OUTBUF_SIZE];

    if (!drstrace_unit_test_syscall_init())
        dr_abort();
    /* XXX: Since drsyscall features can't be simply initialized in a standalone mode
     * we set sysnums to 0x0. Currently we don't need syscall numbers at all to test args
     * printing but such functionality may be required in the future.
     */
    sysnum.number = 0x0;
    sysnum.secondary = 0x0;
    /* NtCreateFile arg0 OUT PHANDLE FileHandle */
    init_arg(&arg,
             NULL, /* arg name */
             DRSYS_TYPE_INVALID, /* containing type */
             DRSYS_PARAM_OUT, /* mode */
             0x4, /* size */
             0x0, /* start_addr */
             0x0, /* ordinal */
             0x0, /* syscall */
             sysnum,
             DRSYS_TYPE_HANDLE, /* type */
             true, /* pre */
             0x0, /* reg */
             "HANDLE", /* type_name */
             true, /* valid */
             NULL, /* enum_name */
             (ptr_uint_t)&handle, /* value */
             (ptr_uint_t)&handle /* value64 */);
    _snprintf(check_str, OUTBUF_SIZE,
              "\targ 0: "PFX" (type=HANDLE*, size=0x4)\n",
              &handle);
    check_output(arg, check_str);

    /* NtCreateFile arg1 IN ACCESS_MASK DesiredAccess*/
    init_arg(&arg,
             NULL, /* arg name */
             DRSYS_TYPE_INVALID, /* containing type */
             DRSYS_PARAM_INLINED|DRSYS_PARAM_IN, /* mode */
             0x4, /* size */
             0x0, /* start_addr */
             0x1, /* ordinal */
             0x0, /* syscall */
             sysnum,
             DRSYS_TYPE_UNSIGNED_INT, /* type */
             true, /* pre */
             0x0, /* reg */
             "unsigned int", /* type_name */
             true, /* valid */
             NULL, /* enum_name */
             0xF0F0F0F0, /* value */
             0xF0F0F0F0 /* value64 */);
    check_output(arg, "\targ 1: 0xf0f0f0f0 (type=unsigned int, size=0x4)\n");

    /* NtCreateFile arg2 IN POBJECT_ATTRIBUTES ObjectAttributes */
    oa.Attributes = 0x40;
    oa.Length = 0x18;
    oa.ObjectName = (PUNICODE_STRING)wbuf;
    oa.ObjectName->Buffer = L"\\??\\C:\\Windows\\Fonts\\staticcache.dat";
    oa.ObjectName->Length = UNICODE_STR_SIZE;
    oa.ObjectName->MaximumLength = UNICODE_BUF_MAX_SIZE;
    oa.RootDirectory = 0x0;
    oa.SecurityDescriptor = 0x0;
    oa.SecurityQualityOfService  = 0x0;
    init_arg(&arg,
             NULL, /* arg name */
             DRSYS_TYPE_INVALID, /* containing type */
             DRSYS_PARAM_IN, /* mode */
             0x4, /* size */
             0x0, /* start_addr */
             0x2, /* ordinal */
             0x0, /* syscall */
             sysnum,
             DRSYS_TYPE_OBJECT_ATTRIBUTES, /* type */
             true, /* pre */
             0x0, /* reg */
             "OBJECT_ATTRIBUTES", /* type_name */
             true, /* valid */
             NULL, /* enum_name */
             (ptr_uint_t)&oa, /* value */
             (ptr_uint_t)&oa  /* value64 */);
    _snprintf(check_str, OUTBUF_SIZE,
              "\targ 2: len=0x18, root=0x0, name=72/538 \"\\??\\C:\\Windows\
\\Fonts\\staticcache.dat\", att=0x40, sd="PFX", sqos\
="PFX" (type=OBJECT_ATTRIBUTES*, size=0x4)\n",
              oa.SecurityDescriptor,
              oa.SecurityQualityOfService);
    check_output(arg, check_str);

    /* NtCreateFile arg3 OUT PIO_STATUS_BLOCK IoStatusBLock */
    init_arg(&arg,
             NULL, /* arg name */
             DRSYS_TYPE_INVALID, /* containing type */
             DRSYS_PARAM_OUT, /* mode */
             0x4, /* size */
             0x0, /* start_addr */
             0x3, /* ordinal */
             0x0, /* syscall */
             sysnum,
             DRSYS_TYPE_IO_STATUS_BLOCK, /* type */
             true, /* pre */
             0x0, /* reg */
             "IO_STATUS_BLOCK", /* type_name */
             true, /* valid */
             NULL, /* enum_name */
             (ptr_uint_t)&io, /* value */
             (ptr_uint_t)&io /* value64 */);

    _snprintf(check_str, OUTBUF_SIZE,
              "\targ 3: "PFX" (type=IO_STATUS_BLOCK*, size=0x4)\n",
              &io);
    check_output(arg, check_str);

    /* NtCreateFile arg4 IN_OPT PLARGE_INTEGER AllocSize */
    li.QuadPart = 0xF0F0F0F0F0F0F0F0;
    init_arg(&arg,
             NULL, /* arg name */
             DRSYS_TYPE_INVALID, /* containing type */
             DRSYS_PARAM_IN, /* mode */
             0x4, /* size */
             0x0, /* start_addr */
             0x4, /* ordinal */
             0x0, /* syscall */
             sysnum,
             DRSYS_TYPE_LARGE_INTEGER, /* type */
             true, /* pre */
             0x0, /* reg */
             "LARGE_INTEGER", /* type_name */
             true, /* valid */
             NULL, /* enum_name */
             (ptr_uint_t)&li, /* value */
             (ptr_uint_t)&li  /* value64 */);
    check_output(arg, "\targ 4: 0xf0f0f0f0f0f0f0f0 (type=LARGE_INTEGER*, size=0x4)\n");

    /* NtCreateFile arg5 IN ULONG SharedAttributes */
    init_arg(&arg,
             NULL, /* arg name */
             DRSYS_TYPE_INVALID, /* containing type */
             DRSYS_PARAM_INLINED|DRSYS_PARAM_IN, /* mode */
             0x4, /* size */
             0x0, /* start_addr */
             0x5, /* ordinal */
             0x0, /* syscall */
             sysnum,
             DRSYS_TYPE_UNSIGNED_INT, /* type */
             true, /* pre */
             0x0, /* reg */
             "unsigned int", /* type_name */
             true, /* valid */
             "FILE_ATTRIBUTE_READONLY", /* enum_name */
             FILE_ATTRIBUTE_READONLY|
             FILE_ATTRIBUTE_DIRECTORY|
             FILE_ATTRIBUTE_NORMAL,  /* value */
             FILE_ATTRIBUTE_READONLY|
             FILE_ATTRIBUTE_DIRECTORY|
             FILE_ATTRIBUTE_NORMAL /* value64 */);
    check_output(arg, "\targ 5: FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_DIRECTORY\
|FILE_ATTRIBUTE_NORMAL (type=named constant, value=0x91, size=0x4)\n");

    /* We don't test other IN params of NtCreateFile b/c they don't cover
     * more routines in drstrace.c.
     */

    /* NtCreateFile ret arg0 OUT PHANDLE FileHandle */
    handle = (HANDLE)0x120;
    init_arg(&arg,
             NULL, /* arg name */
             DRSYS_TYPE_INVALID, /* containing type */
             DRSYS_PARAM_OUT, /* mode */
             0x4, /* size */
             0x0, /* start_addr */
             0x0, /* ordinal */
             0x0, /* syscall */
             sysnum,
             DRSYS_TYPE_HANDLE, /* type */
             false, /* pre */
             0x0, /* reg */
             "HANDLE", /* type_name */
             true, /* valid */
             NULL, /* enum_name */
             (ptr_uint_t)&handle, /* value */
             (ptr_uint_t)&handle /* value64 */);
    _snprintf(check_str, OUTBUF_SIZE,
              "\targ 0: "PFX" => 0x120 (type=HANDLE*, size=0x4)\n",
              &handle);
    check_output(arg, check_str);

    /* NtCreateFile ret arg3 OUT IO_STATUS_BLOCK IoStatusBlock */
    io.StatusPointer.Pointer = 0x0;
    io.StatusPointer.Status = 0x2;
    io.Information = 0x1;
    init_arg(&arg,
             NULL, /* arg name */
             DRSYS_TYPE_INVALID, /* containing type */
             DRSYS_PARAM_OUT, /* mode */
             0x4, /* size */
             0x0, /* start_addr */
             0x3, /* ordinal */
             0x0, /* syscall */
             sysnum,
             DRSYS_TYPE_IO_STATUS_BLOCK, /* type */
             false, /* pre */
             0x0, /* reg */
             "IO_STATUS_BLOCK", /* type_name */
             true, /* valid */
             NULL, /* enum_name */
             (ptr_uint_t)&io, /* value */
             (ptr_uint_t)&io /* value64 */);
    check_output(arg, "\targ 3: status=0x2, info=0x1 (type=IO_STATUS_BLOCK*,\
 size=0x4)\n");

    /* NtCreateFile OUT return NTSTATUS ret */
    init_arg(&arg,
             NULL, /* arg name */
             DRSYS_TYPE_INVALID, /* containing type */
             DRSYS_PARAM_RETVAL|DRSYS_PARAM_INLINED, /* mode */
             0x4, /* size */
             0x0, /* start_addr */
             -1, /* ordinal */
             0x0, /* syscall */
             sysnum,
             DRSYS_TYPE_NTSTATUS, /* type */
             false, /* pre */
             0x0, /* reg */
             "NTSTATUS", /* type_name */
             true, /* valid */
             NULL, /* enum_name */
             0x0, /* value */
             0x0 /* value64 */);
    check_output(arg, "\tretval: 0x0 (type=NTSTATUS, size=0x4)\n");
    if (!drstrace_unit_test_syscall_exit())
        dr_abort();

    /* XXX i#1601: We should cover structure printing routines but it may require
     * a lot of time since wintypes.pdb can not be available and should be fetched
     * from remote MS Symbol Server.
     */
    return 0;
}
