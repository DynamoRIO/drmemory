/* **********************************************************
 * Copyright (c) 2012-2015 Google, Inc.  All rights reserved.
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

#include "gtest/gtest.h"

#include <winsock2.h>
#pragma comment(lib,"ws2_32.lib")
#include <process.h>

/* XXX: much of the ClientServer code is identical to the posix version: can we share? */

static void
ClientServer_client(int port)
{
    int res;
    struct sockaddr_in saddr = {};
    struct sockaddr from_addr;
    int from_len = sizeof(from_addr);
    int fd_client;
    struct hostent *hp = gethostbyname("localhost");
    ASSERT_NE(hp, (struct hostent *)NULL);
    char buf[512];

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = ((struct in_addr *)(hp->h_addr))->s_addr;
    saddr.sin_port = htons(port);

    /* connect and exchange greetings */
    fd_client = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_NE(fd_client, -1);
    res = connect(fd_client, (struct sockaddr *) &saddr, sizeof(saddr));
    ASSERT_NE(res, -1);
    res = send(fd_client, "hello", strlen("hello")+1, 0);
    ASSERT_NE(res, -1);
    res = recvfrom(fd_client, buf, sizeof(buf), 0, &from_addr, &from_len);
    ASSERT_NE(res, -1);
    EXPECT_LE(strlen("goodbye")+1, (int)from_len);
    ASSERT_STREQ(buf, "goodbye");

    closesocket(fd_client);
}

static unsigned int WINAPI
ClientServer_thread(void *arg)
{
    int port = (int)(intptr_t) arg;
    /* The gtest asserts require a void return value so we use a helper function: */
    ClientServer_client(port);
    _endthreadex(0);
    return 0;
}

TEST(SocketTests, ClientServer) {
    WSADATA wsa;
    SOCKET fds[2];

    int res = WSAStartup(MAKEWORD(2, 2), &wsa);
    ASSERT_EQ(res, 0);

    int fd_socket, fd_connect;
    int port, size;
    struct sockaddr_in saddr = {};
    char buf[512];

    saddr.sin_family = AF_INET;
    /* default firewall blocks INADDR_ANY */
    saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    /* use 0 so the kernel assigns us an open port # */
    saddr.sin_port = htons(0);

    fd_socket = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_NE(fd_socket, -1);
    res = bind(fd_socket, (struct sockaddr *) &saddr, sizeof(saddr));
    ASSERT_NE(res, -1);
    res = listen(fd_socket, 16/*max queue length*/);
    ASSERT_NE(res, -1);

    /* get the port # we were assigned */
    size = sizeof(saddr);
    res = getsockname(fd_socket, (struct sockaddr *) &saddr, &size);
    ASSERT_NE(res, -1);
    port = ntohs(saddr.sin_port);

    unsigned int tid;
    HANDLE thread = (HANDLE)
        _beginthreadex(NULL, 0, ClientServer_thread, (void*)(intptr_t)port, 0, &tid);

    /* wait for child to connect */
    size = sizeof(saddr);
    fd_connect = accept(fd_socket, (struct sockaddr *) &saddr, &size);
    ASSERT_NE(fd_connect, -1);

    /* exchange greetings */
    res = recv(fd_connect, buf, sizeof(buf), 0);
    ASSERT_NE(res, -1);
    ASSERT_STREQ(buf, "hello");
    res = send(fd_connect, "goodbye", strlen("goodbye")+1, 0);
    ASSERT_NE(res, -1);

    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    closesocket(fd_connect);
    closesocket(fd_socket);

    WSACleanup();
}

static void
set_socket_block_behavior(int fd_socket, bool block)
{
    u_long ioctl_arg = block ? 0 : 1;
    int res = ioctlsocket(fd_socket, FIONBIO, &ioctl_arg);
    ASSERT_NE(res, SOCKET_ERROR);
}

static void
NonBlocking_client(int port)
{
    int res;
    struct sockaddr_in saddr = {};
    struct sockaddr from_addr;
    int from_len = sizeof(from_addr);
    int fd_client;
    struct hostent *hp = gethostbyname("localhost");
    ASSERT_NE(hp, (struct hostent *)NULL);
    char buf[512];

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = ((struct in_addr *)(hp->h_addr))->s_addr;
    saddr.sin_port = htons(port);

    /* connect and exchange greetings */
    fd_client = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_NE(fd_client, -1);
    set_socket_block_behavior(fd_client, false);
    res = connect(fd_client, (struct sockaddr *) &saddr, sizeof(saddr));
    EXPECT_TRUE(res != -1 || WSAGetLastError() == WSAEWOULDBLOCK);

    /* XXX: change the rest to async as well */
    set_socket_block_behavior(fd_client, true);
    res = send(fd_client, "hello", strlen("hello")+1, 0);
    ASSERT_NE(res, -1);
    res = recvfrom(fd_client, buf, sizeof(buf), 0, &from_addr, &from_len);
    ASSERT_NE(res, -1);
    EXPECT_LE(strlen("goodbye")+1, (int)from_len);
    ASSERT_STREQ(buf, "goodbye");

    closesocket(fd_client);
}

static unsigned int WINAPI
NonBlocking_thread(void *arg)
{
    int port = (int)(intptr_t) arg;
    /* The gtest asserts require a void return value so we use a helper function: */
    NonBlocking_client(port);
    _endthreadex(0);
    return 0;
}

TEST(SocketTests, NonBlocking) {
    WSADATA wsa;
    SOCKET fds[2];

    int res = WSAStartup(MAKEWORD(2, 2), &wsa);
    ASSERT_EQ(res, 0);

    int fd_socket, fd_connect;
    int port, size;
    struct sockaddr_in saddr = {};
    char buf[512];
    u_long ioctl_arg;

    saddr.sin_family = AF_INET;
    /* default firewall blocks INADDR_ANY */
    saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    /* use 0 so the kernel assigns us an open port # */
    saddr.sin_port = htons(0);

    fd_socket = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_NE(fd_socket, -1);
    set_socket_block_behavior(fd_socket, false);
    res = bind(fd_socket, (struct sockaddr *) &saddr, sizeof(saddr));
    ASSERT_NE(res, -1);
    res = listen(fd_socket, 16/*max queue length*/);
    ASSERT_NE(res, -1);

    /* get the port # we were assigned */
    size = sizeof(saddr);
    res = getsockname(fd_socket, (struct sockaddr *) &saddr, &size);
    ASSERT_NE(res, -1);
    port = ntohs(saddr.sin_port);

    unsigned int tid;
    HANDLE thread = (HANDLE)
        _beginthreadex(NULL, 0, NonBlocking_thread, (void*)(intptr_t)port, 0, &tid);

    /* wait for child to connect via select() to test AFD_POLL_INFO, etc. */
    fd_set reads, writes;
    FD_ZERO(&reads);
    FD_SET(fd_socket, &reads);
    res = select(0, &reads, NULL, NULL, NULL);
    ASSERT_NE(res, SOCKET_ERROR);
    ASSERT_EQ(1, FD_ISSET(fd_socket, &reads));

    size = sizeof(saddr);
    fd_connect = accept(fd_socket, (struct sockaddr *) &saddr, &size);
    ASSERT_NE(fd_connect, -1);

    /* XXX: change the rest to async as well */
    set_socket_block_behavior(fd_socket, true);
    res = recv(fd_connect, buf, sizeof(buf), 0);
    ASSERT_NE(res, -1);
    ASSERT_STREQ(buf, "hello");
    res = send(fd_connect, "goodbye", strlen("goodbye")+1, 0);
    ASSERT_NE(res, -1);

    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    closesocket(fd_connect);
    closesocket(fd_socket);

    WSACleanup();
}
