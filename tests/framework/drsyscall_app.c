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

/* Test of the Dr. Syscall Extension */

#include <stdio.h>
#include <stdlib.h>
#ifdef LINUX
# include <sys/types.h>
# include <sys/stat.h>
# include <fcntl.h>
# include <unistd.h>
#else
# include <windows.h>
#endif

static void
syscall_test(void)
{
#ifdef LINUX
    int fd = open("/dev/null", O_WRONLY);
    int *uninit = (int *) malloc(sizeof(*uninit));
    write(fd, uninit, sizeof(*uninit));
    free(uninit);
#else
    MEMORY_BASIC_INFORMATION mbi;
    void **uninit = (void **) malloc(sizeof(*uninit));
    VirtualQuery(*uninit, &mbi, sizeof(mbi));
    free(uninit);
#endif
}

int
main(int argc, char **argv)
{
    syscall_test();
    printf("done\n");
    return 0;
}
