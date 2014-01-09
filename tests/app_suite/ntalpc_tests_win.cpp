/* **********************************************************
 * Copyright (c) 2012 Google, Inc.  All rights reserved.
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

#include <windows.h>
#include <stdio.h>
#include <rpc.h>

#include "os_version_win.h"
#include "gtest/gtest.h"

#pragma comment(lib, "rpcrt4.lib")

typedef struct _rpc_MIDL_PROC_FORMAT_STRING {
    short          pad;
    unsigned char  format[28];
} rpc_MIDL_PROC_FORMAT_STRING;

static const RPC_CLIENT_INTERFACE RpcClientInterface;
static RPC_BINDING_HANDLE AutoBindHandle;

static const rpc_MIDL_PROC_FORMAT_STRING rpc__MIDL_ProcFormatString = {
    0,
    {
    /* Procedure Ping */
        0x0,
        0x68,               /* Old Flags:  comm or fault/decode */
        NdrFcLong( 0x0 ),   /* 0 */
        NdrFcShort( 0x0 ),  /* 0 */
        NdrFcShort( 0x8 ),  /* x86 Stack size/offset = 8 */
        0x32,               /* FC_BIND_PRIMITIVE */
        0x0,                /* 0 */
        NdrFcShort( 0x0 ),  /* x86 Stack size/offset = 0 */
        NdrFcShort( 0x0 ),  /* 0 */
        NdrFcShort( 0x8 ),  /* 8 */
        0x44,               /* Oi2 Flags:  has return, has ext, */
        0x1,                /* 1 */
        0x8,                /* 8 */
        0x1,                /* Ext Flags:  new corr desc, */
        NdrFcShort( 0x0 ),  /* 0 */
        NdrFcShort( 0x0 ),  /* 0 */
        NdrFcShort( 0x0 ),  /* 0 */
    }
};

static const COMM_FAULT_OFFSETS CommFaultOffsets[] = {
    { -1, -1 },	/* x86 Offsets for Ping */
};

static const MIDL_STUB_DESC Rpc_StubDesc = {
    (void *) &RpcClientInterface,
    MIDL_user_allocate,
    MIDL_user_free,
    &AutoBindHandle,
    0,
    0,
    0,
    0,
    0,
    1,                  /* -error bounds_check flag */
    0x50002,            /* Ndr library version */
    0,
    0x700022b,          /* MIDL Version 7.0.555 */
    CommFaultOffsets,
    0,
    0,                  /* notify & notify_flag routine table */
    0x1,                /* MIDL flag */
    0,                  /* cs routines */
    0,                  /* proxy/server info */
    0
};

TEST(NtAlpcTest, RpcPing) {
    if (GetWindowsVersion() < WIN_VISTA) {
        printf("WARNING: Disabling RpcPing on Pre-Vista.\n");
        return;
    }

    TCHAR *network_address = NULL;
    TCHAR *protocol = "ncalrpc";
    TCHAR *string_binding;
    RPC_BINDING_HANDLE binding;
    RPC_STATUS status;
    CLIENT_CALL_RETURN ret;
    ULONG authn_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY;

    status = RpcStringBindingCompose(0, (RPC_CSTR) protocol, (RPC_CSTR) network_address,
                                     0, 0, (RPC_CSTR *) &string_binding);
    ASSERT_EQ(RPC_S_OK, status);

    status = RpcBindingFromStringBinding((RPC_CSTR) string_binding, &binding);
    ASSERT_EQ(RPC_S_OK, status);

    status = RpcBindingSetAuthInfo(binding, 0, authn_level, RPC_C_AUTHN_WINNT, 0, 0);
    ASSERT_EQ(RPC_S_OK, status);

    ret = NdrClientCall2((PMIDL_STUB_DESC ) &Rpc_StubDesc,
                         (PFORMAT_STRING) &rpc__MIDL_ProcFormatString.format[0],
                         (TCHAR *) &binding);

    /* Cleanup */
    status = RpcBindingFree(&binding);
    status = RpcStringFree((RPC_CSTR *) &string_binding);
}

void * __RPC_USER MIDL_user_allocate(size_t size) {
    return(HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, size));
}

void __RPC_USER MIDL_user_free( void *pointer) {
    HeapFree(GetProcessHeap(), 0, pointer);
}
