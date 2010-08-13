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
#include <crtdbg.h>
#include <malloc.h>

static void
use(char *a)
{
    if (*a == 777) { // Use *a in a conditional statement.
        printf("777\n");
    }
}

static void
oob_read_test(void)
{
    char *foo = (char*) malloc(8);
    use(foo+48);
    use(foo+25);
    use(foo+8); 
    use(foo-1); 
    use(foo-30);
    use(foo-37);
    use(foo-41);
    free(foo);
}

static void
crtdbg_test(void)
{
    /* PR 595801: test _dbg versions of malloc routines */
#ifdef _DEBUG
    void *p = _malloc_dbg(9, _CLIENT_BLOCK, __FILE__, __LINE__);
    /* note that _free_dbg complains if type doesn't match, but _msize_dbg does not */
    size_t sz = _msize_dbg(p, _CLIENT_BLOCK);
    _free_dbg(p, _CLIENT_BLOCK);
    
    _free_dbg(NULL, _NORMAL_BLOCK);
    _free_dbg(NULL, _CLIENT_BLOCK);
#endif
}

/* TODO PR 595802: test _recalloc and _aligned_* malloc routines
 */

int main()
{
    oob_read_test();
    crtdbg_test();
    printf("Done\n");
    return 0;
}
