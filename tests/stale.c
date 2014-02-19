/* **********************************************************
 * Copyright (c) 2010 VMware, Inc.  All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#ifdef UNIX
# include <unistd.h>
# include <time.h>     /* for nanosleep */
#else
# include <windows.h>
#endif

/* We have an array and we touch each element once, with a sleep before
 * we touch the next one
 */
#define ARRAY_LEN 10
#define SLEEP_MS 100
static int *stale[ARRAY_LEN];

int
main()
{
    unsigned int i;
    for (i = 0; i < ARRAY_LEN; i++)
        stale[i] = malloc(sizeof(int));

    for (i = 0; i < ARRAY_LEN; i++) {
        *(stale[i]) = i;
#ifdef UNIX
        struct timespec sleeptime;
        sleeptime.tv_sec = 0;
        sleeptime.tv_nsec = SLEEP_MS*1000*1000;
        nanosleep(&sleeptime, NULL);
#else
        SleepEx(SLEEP_MS, 0);
#endif
    }

    printf("all done\n");
    return 0;
}
