/* **********************************************************
 * Copyright (c) 2010 Google, Inc.  All rights reserved.
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
#include <dlfcn.h>

__attribute__ ((visibility ("default")))
int
my_export(int x)
{
    return x;
}

static void
load_and_sym(const char *path, const char *sym, int flags)
{
    void *lib = dlopen(path, flags);
    printf("dlopen %s %s\n", (path == NULL) ? "<NULL>" : path,
           (lib == NULL) ? "failure" : "success");
    if (lib == NULL) {
        printf("dlerror loading %s: %s\n", (path == NULL) ? "<NULL>" : path, dlerror());
    } else {
        if (sym != NULL) {
            void *addr = dlsym(lib, sym);
            printf("dlsym %s %s\n", sym, (addr == NULL) ? "failure" : "success");
        }
        dlclose(lib);
    }
}

int
main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage error: must pass in path to library to load\n");
        return 1;
    }

    /* open existing executable */
    load_and_sym(NULL, "my_export", RTLD_LAZY);

    /* load a simple library */
    load_and_sym("libm.so.6", "cos", RTLD_NOW);

    /* load a library w/o in-file .bss to test PR 528744 */
    load_and_sym("libgcc_s.so.1", "__gcc_personality_v0", RTLD_LAZY);

    /* load a library w/ a missing symbol for loader longjmp path (xref PR 530902) */
    load_and_sym(argv[1], NULL, RTLD_NOW);

    return 0;
}
