/* **********************************************************
 * Copyright (c) 2011-2013 Google, Inc.  All rights reserved.
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
#ifdef UNIX
# include <dlfcn.h>
#else
# include <windows.h>
#endif
#include <stdlib.h>

int
main(int argc, char** argv)
{
    int i, iters;

    if (argc < 3) {
        fprintf(stderr, "Usage: <library-path> <iters>\n");
        return 1;
    }

    iters = atoi(argv[2]);

    for (i=0; i<iters; i++) {
#ifdef WINDOWS
        HANDLE lib = LoadLibrary(argv[1]);
#else /* UNIX */
        void *lib = dlopen(argv[1], RTLD_LAZY);
#endif
        if (lib == NULL) {
            fprintf(stderr, "error loading library %s\n", argv[1]);
            break;
        } else {
#ifdef WINDOWS
            FreeLibrary(lib);
#else /* UNIX */
            dlclose(lib);
#endif
        }
    }
    fprintf(stderr, "all done\n");
    return 0;
}
