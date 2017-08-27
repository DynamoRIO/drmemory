/* **********************************************************
 * Copyright (c) 2014-2017 Google, Inc.  All rights reserved.
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

/* The selfmod part of our code is from DynamoRIO's security-common/selfmod test
 * which is under this copyright and license:
 */

/* **********************************************************
 * Copyright (c) 2003-2008 VMware, Inc.  All rights reserved.
 * **********************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#ifdef UNIX
# include <sys/mman.h>
# include <stdint.h>
#else
# include <windows.h>
#endif

static void *ecode;

static char code[] = {
    /*8048537:*/ 0xb8, 0x78, 0x56, 0x34, 0x12,       /* mov    $0x12345678,%eax */
    /*804853c:*/ 0xb9, 0x00, 0x00, 0x00, 0x00,       /* mov    $0x0,%ecx        */
    /*8048541:*/                                     /*repeat1:                 */
#ifdef X64
    /*8048541:*/ 0xff, 0xc8,                         /* dec    %eax             */
    /*8048542:*/ 0xff, 0xc1,                         /* inc    %ecx             */
#else
    /*8048541:*/ 0x48,                               /* dec    %eax             */
    /*8048542:*/ 0x41,                               /* inc    %ecx             */
#endif
    /*8048543:*/ 0x83, 0xf8, 0x00,                   /* cmp    $0x0,%eax        */
#ifdef X64
    /*8048546:*/ 0x75, 0xf7,                         /* jne    8048541 <repeat1>*/
#else
    /*8048546:*/ 0x75, 0xf9,                         /* jne    8048541 <repeat1>*/
#endif
    /*8048548:*/ 0x89, 0xc8,                         /* mov    %ecx,%eax        */
    /*804854a:*/ 0xc3,                               /* ret                     */
};

void
foo(int iters)
{
    int res;
    void *p = ecode;
    *(int *)(((char *)ecode) + 1) = iters;
    res = ((int (*)(void))p)();
    printf("Executed 0x%x iters\n", res);
}

int
main()
{
#ifdef UNIX
    ecode = mmap(0, sizeof(code), PROT_EXEC|PROT_READ|PROT_WRITE,
		   MAP_ANON|MAP_PRIVATE, -1, 0);
    if (ecode == MAP_FAILED) {
        printf("mmap failed\n");
        return 1;
    }
#else
    ecode = VirtualAlloc(0, sizeof(code), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!ecode) {
        printf("VirtualAlloc failed\n");
        return 1;
    }
#endif
    memcpy(ecode, code, sizeof(code));

    foo(0xabcd);
    foo(0x1234);
    foo(0xef01);

    printf("all done\n");
    return 0;
}
