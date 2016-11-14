/* **********************************************************
 * Copyright (c) 2014-2016 Google, Inc.  All rights reserved.
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
#include "dr_frontend.h"
#include "windefs.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define OUTBUF_SIZE 2048
#define DBGHELP_PATH "dbghelp.dll"
/* took these unicode string sizes from real drstrace output */
#define UNICODE_STR_SIZE 72
#define UNICODE_BUF_MAX_SIZE 538

typedef struct _buf_info_t {
    char buf[OUTBUF_SIZE];
    size_t sofar;
    ssize_t len;
} buf_info_t;

typedef struct _KEY_CACHED_INFORMATION {
  LARGE_INTEGER LastWriteTime;
  ULONG         TitleIndex;
  ULONG         SubKeys;
  ULONG         MaxNameLen;
  ULONG         Values;
  ULONG         MaxValueNameLen;
  ULONG         MaxValueDataLen;
  ULONG         NameLength;
} KEY_CACHED_INFORMATION;

extern bool
drstrace_unit_test_syscall_arg_iteration(drsys_arg_t arg, void *user_data);
extern bool
drstrace_unit_test_syscall_init();
extern bool
drstrace_unit_test_syscall_exit();
extern void
drstrace_set_symbol_path(const char *pdb_dir);

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
check_symbol_fetching()
{
    char symbol_dir[MAXIMUM_PATH];
    char symsrv_path[MAXIMUM_PATH];
    bool pdb_exists;
    drfront_status_t res;
    int i;
#   define MAX_TRIES 4

    if (drfront_get_absolute_path("../logs",
                                  symbol_dir, MAXIMUM_PATH) != DRFRONT_SUCCESS) {
        fprintf(stderr, "drfront_get_absolute_path failed\n");
        fflush(stderr);
        dr_abort();
    }
    /* create output dir with appended PID */
    _snprintf(symbol_dir, MAXIMUM_PATH, "%s\\%s_%d",
              symbol_dir, "drstrace_unit_tests",
              dr_get_process_id());

    if (drfront_create_dir(symbol_dir) != DRFRONT_SUCCESS) {
        fprintf(stderr, "drfront_create_dir |%s| failed\n", symbol_dir);
        fflush(stderr);
        dr_abort();
    }
    if (drfront_sym_init(symbol_dir, DBGHELP_PATH) != DRFRONT_SUCCESS) {
        fprintf(stderr, "drfront_sym_init failed\n");
        fflush(stderr);
        dr_abort();
    }
    if (drfront_set_client_symbol_search_path(symbol_dir, true, symsrv_path,
                                              MAXIMUM_PATH) != DRFRONT_SUCCESS) {
        fprintf(stderr, "drfront_set_client_symbol_search_path failed\n");
        fflush(stderr);
        dr_abort();
    }
    if (drfront_set_symbol_search_path(symsrv_path) != DRFRONT_SUCCESS) {
        fprintf(stderr, "drfront_set_symbol_search_path failed\n");
        fflush(stderr);
        dr_abort();
    }

    /* i#1925: the MS symbol server can be flaky, so we try several times. */
    for (i = 0; i < MAX_TRIES; i++) {
        res = drfront_fetch_module_symbols(SYMBOL_DLL_PATH, symbol_dir, MAXIMUM_PATH);
        if (res == DRFRONT_SUCCESS)
            break;
    }
    if (res != DRFRONT_SUCCESS) {
        /* Provide more info b/c this can fail if the test dir is moved or sthg */
        fprintf(stderr, "drfront_fetch_module_symbols failed %d for |%s|\n",
               res, SYMBOL_DLL_PATH);
        fflush(stderr);
        dr_abort();
    }
    if (drfront_access(symbol_dir, DRFRONT_READ, &pdb_exists) != DRFRONT_SUCCESS ||
        !pdb_exists) {
        fprintf(stderr, "drfront_access failed\n");
        fflush(stderr);
        dr_abort();
    }
    if (drfront_sym_exit() != DRFRONT_SUCCESS) {
        fprintf(stderr, "drfront_sym_exit failed\n");
        fflush(stderr);
        dr_abort();
    }
    /* XXX i#1606: We should call fetch symbols functionality
     * inside drstrace. Now we use drfront routine which is not
     * cover drstrace.
     */
    drstrace_set_symbol_path(symbol_dir);
}


static void
check_output(drsys_arg_t arg, char *check_data)
{
    void *out_data = calloc(1, sizeof(buf_info_t));
    drstrace_unit_test_syscall_arg_iteration(arg, out_data);
    printf((char *)check_data);
    printf((char *)out_data);
    if (strcmp((char *)out_data, check_data) != 0)
        dr_abort();
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
    char pdb_dir[MAXIMUM_PATH];
    char check_str[OUTBUF_SIZE];
    KEY_CACHED_INFORMATION ki;

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

    printf("Testing symbol library fetching features\n");
    check_symbol_fetching();
    printf("done\n");
    /* create arg with structure */
    ki.LastWriteTime.LowPart = 0x20202020;
    ki.LastWriteTime.HighPart = 0xF0F0F0F0;
    ki.MaxNameLen = 0xE0E0E0E0;
    ki.MaxValueDataLen = 0xD0D0D0D0;
    ki.MaxValueNameLen = 0x10101010;
    ki.NameLength = 0xB0B0B0B0;
    ki.SubKeys = 0xA0A0A0A0;
    ki.TitleIndex = 0x90909090;
    ki.Values = 0x80808080;
    /* NtQueryKey.KeyCachedInformation arg 2 OUT PVOID KeyInformation */
    init_arg(&arg,
             NULL, /* arg name */
             DRSYS_TYPE_INVALID, /* containing type */
             DRSYS_PARAM_OUT, /* mode */
             0x4, /* size */
             0x0, /* start_addr */
             0x2, /* ordinal */
             0x0, /* syscall */
             sysnum,
             DRSYS_TYPE_STRUCT, /* type */
             false, /* pre */
             0x0, /* reg */
             "PVOID", /* type_name */
             true, /* valid */
             "_KEY_CACHED_INFORMATION", /* enum_name */
             (ptr_uint_t)&ki, /* value */
             (ptr_uint_t)&ki /* value64 */);

    _snprintf(check_str, OUTBUF_SIZE,
              "\targ 2: _KEY_CACHED_INFORMATION {_LARGE_INTEGER {0x"HEX64_FORMAT_STRING"\
}, int="PIFX", int="PIFX", int="PIFX", int="PIFX", int="PIFX", int="PIFX", int="PIFX"} (type=\
<struct>*, size=0x4)\n",
              ki.LastWriteTime.QuadPart, (ptr_uint_t)ki.TitleIndex,
              (ptr_uint_t)ki.SubKeys, (ptr_uint_t)ki.MaxNameLen, (ptr_uint_t)ki.Values,
              (ptr_uint_t)ki.MaxValueNameLen,(ptr_uint_t)ki.MaxValueDataLen,
              (ptr_uint_t)ki.NameLength);

    check_output(arg, check_str);

    /* check wrong data: the same input but with invalid pointer to struct data */
    init_arg(&arg,
             NULL, /* arg name */
             DRSYS_TYPE_INVALID, /* containing type */
             DRSYS_PARAM_OUT, /* mode */
             0x4, /* size */
             0x0, /* start_addr */
             0x2, /* ordinal */
             0x0, /* syscall */
             sysnum,
             DRSYS_TYPE_STRUCT, /* type */
             false, /* pre */
             0x0, /* reg */
             "PVOID", /* type_name */
             true, /* valid */
             "_KEY_CACHED_INFORMATION", /* enum_name */
             (ptr_uint_t)NULL, /* value */
             (ptr_uint_t)NULL /* value64 */);
    _snprintf(check_str, OUTBUF_SIZE,
              "\targ 2: NULL (type=<struct>*, size=0x4)\n");
    check_output(arg, check_str);

    if (!drstrace_unit_test_syscall_exit())
        dr_abort();

    printf("all done\n");
    return 0;
}
