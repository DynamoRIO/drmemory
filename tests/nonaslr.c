/* **********************************************************
 * Copyright (c) 2015 Google, Inc.  All rights reserved.
 * **********************************************************/

/* Dr. Memory: the memory debugger
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License, and no later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/* i#1782: Test shadow memory on non-ASLR Linux */

#include <sys/personality.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    char *arg[] = { argv[1], NULL };
    if (argc < 2) {
        printf("need to pass in executable path\n");
        return 1;
    }
    if (personality(ADDR_NO_RANDOMIZE) == -1) {
        printf("fail to disable ASLR\n");
        return 1;
    }
    execv(argv[1], arg);
    return 0;
}
