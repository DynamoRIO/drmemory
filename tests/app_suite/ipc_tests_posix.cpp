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

#include <semaphore.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>

TEST(IPCTests, SYSV_Semaphore) {
    int semid;
    int res;
    key_t key = IPC_PRIVATE;
    semid = semget(key, 1, IPC_CREAT | 0666);
    ASSERT_NE(semid, -1);

    struct sembuf sops[1];
    sops[0].sem_num = 0;
    sops[0].sem_op = 1; /* inc by 1 */
    sops[0].sem_flg = 0;
    res = semop(semid, sops, 1);
    ASSERT_EQ(res, 0);

    res = semctl(semid, 0, IPC_RMID);
    ASSERT_EQ(res, 0);
}

TEST(IPCTests, Futex_Semaphore) {
    // These end up using futexes
    sem_t mysem;
    int value;

    sem_init(&mysem, 0, 0);

    sem_post(&mysem);
    sem_getvalue(&mysem, &value);
    ASSERT_EQ(value, 1);

    sem_wait(&mysem);
    sem_getvalue(&mysem, &value);
    ASSERT_EQ(value, 0);

    sem_destroy(&mysem);
}
