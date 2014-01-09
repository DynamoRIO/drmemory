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

#include "gtest/gtest.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h> /* gethostbyname */
#include <netinet/in.h> /* sockaddr_in */
#include <arpa/inet.h> /* ntohs */
#include <errno.h>

TEST(SocketTests, ClientServer) {
    int fd_socket, fd_connect;
    int port, res;
    pid_t child;
    socklen_t size;
    struct sockaddr_in saddr = {};
    char buf[512];

    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
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

    child = fork();
    ASSERT_TRUE(child >= 0);
    if (child == 0) {
        struct sockaddr from_addr;
        socklen_t from_len = sizeof(from_addr);
        int fd_client;
        struct hostent *hp = gethostbyname("localhost");
        ASSERT_NE(hp, (struct hostent *)NULL);

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
        EXPECT_EQ(0, (int)from_len);  /* no from addr with SOCK_STREAM */
        ASSERT_STREQ(buf, "goodbye");

        close(fd_client);
        exit(0);
    } else {
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

        int status;
        do {
            res = waitpid(child, &status, 0);
        } while (res == -1 && errno == EINTR);
        ASSERT_EQ(res, child);
        ASSERT_EQ(0, status);

        close(fd_connect);
        close(fd_socket);
    }
}
