/* **********************************************************
 * Copyright (c) 2009 VMware, Inc.  All rights reserved.
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

#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h> /* for wait and mmap */
#include <sys/wait.h>  /* for wait */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

int
main(int argc, char *argv[])
{
    pid_t child;
    if (argc < 2) {
        printf("ERROR: not enough args\n");
        return -1;
    }
    printf("parent is running\n");
    fflush(stdout);
    child = fork();
    if (child < 0) {
        perror("ERROR on fork");
    } else if (child > 0) {
        pid_t result;
        int iters = 0;
        /* PR 479089: we can get interrupted, so loop */
        do {
            result = waitpid(child, NULL, 0);
            assert(++iters < 100);
        } while (result == -1 && errno == EINTR);
        assert(result == child);
        printf("child has exited\n");
        fflush(stdout);
    } else {
        int result;
        char *arg[] = { argv[1], NULL };
        char *env[] = { NULL };
        printf("child is running\n");
        fflush(stdout);
        result = execve(argv[1], arg, env);
        if (result < 0)
            perror("ERROR in execve");
    }
    return 0;
}
