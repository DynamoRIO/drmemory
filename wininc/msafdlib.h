/****************************************************************************
 ****************************************************************************
 ***
 ***   This header was generated from a ReactOS header to make
 ***   information necessary for userspace to call into the Windows
 ***   kernel available to Dr. Memory.  It contains only constants,
 ***   structures, and macros generated from the original header, and
 ***   thus, contains no copyrightable information.
 ***
 ****************************************************************************
 ****************************************************************************/

/* from reactos/include/reactos/winsock/msafdlib.h */

#ifndef __MSAFDLIB_H
#define __MSAFDLIB_H

/* Socket State */
typedef enum _SOCKET_STATE
{
    SocketUndefined = -1,
    SocketOpen,
    SocketBound,
    SocketBoundUdp,
    SocketConnected,
    SocketClosed
} SOCKET_STATE, *PSOCKET_STATE;

/* 
 * Shared Socket Information.
 * It's called shared because we send it to Kernel-Mode for safekeeping
 */
typedef struct _SOCK_SHARED_INFO {
    SOCKET_STATE                State;
    INT                            AddressFamily;
    INT                            SocketType;
    INT                            Protocol;
    INT                            SizeOfLocalAddress;
    INT                            SizeOfRemoteAddress;
    struct linger                LingerData;
    ULONG                        SendTimeout;
    ULONG                        RecvTimeout;
    ULONG                        SizeOfRecvBuffer;
    ULONG                        SizeOfSendBuffer;
    struct {
        BOOLEAN                    Listening:1;
        BOOLEAN                    Broadcast:1;
        BOOLEAN                    Debug:1;
        BOOLEAN                    OobInline:1;
        BOOLEAN                    ReuseAddresses:1;
        BOOLEAN                    ExclusiveAddressUse:1;
        BOOLEAN                    NonBlocking:1;
        BOOLEAN                    DontUseWildcard:1;
        BOOLEAN                    ReceiveShutdown:1;
        BOOLEAN                    SendShutdown:1;
        BOOLEAN                    UseDelayedAcceptance:1;
        BOOLEAN                    UseSAN:1;
    }; // Flags
    DWORD                        CreateFlags;
    DWORD                        CatalogEntryId;
    DWORD                        ServiceFlags1;
    DWORD                        ProviderFlags;
    GROUP                        GroupID;
    DWORD                        GroupType;
    INT                            GroupPriority;
    INT                            SocketLastError;
    HWND                        hWnd;
    LONG                        Unknown;
    DWORD                        SequenceNumber;
    UINT                        wMsg;
    LONG                        AsyncEvents;
    LONG                        AsyncDisabledEvents;
} SOCK_SHARED_INFO, *PSOCK_SHARED_INFO;

/* The blob of data we send to Kernel-Mode for safekeeping */
typedef struct _SOCKET_CONTEXT {
    SOCK_SHARED_INFO SharedData;
    GUID Guid; /* bruening: observed on XP and win7 (i#375) */
    ULONG SizeOfHelperData;
    ULONG Padding;
    SOCKADDR LocalAddress; /* bruening: presumably var-len */
    SOCKADDR RemoteAddress; /* bruening: presumably var-len */
    /* Plus Helper Data */
} SOCKET_CONTEXT, *PSOCKET_CONTEXT;

#endif /* __MSAFDLIB_H */
