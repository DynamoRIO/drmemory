/* **********************************************************
 * Copyright (c) 2012-2013 Google, Inc.  All rights reserved.
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

/* test the -soft_kills option (i#544) */

#include "windows.h"
#include <stdio.h>

/* we use a file for IPC.  this means we can't run this test twice in parallel. */
#define TEMP_FILE "tmp-procterm.txt"

#define SLEEP_PER_ATTEMPT 100
#define MAX_ATTEMPTS 100 /* @ 100ms each => 10 seconds */

static void *
allocate_something(void)
{
    return malloc(42);
}

int
main(int argc, char** argv)
{
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;
    /* first remove file so we aren't fooled by prior runs */
    if (_access(TEMP_FILE, 4/*read*/) != -1) {
        if (!DeleteFile(TEMP_FILE)) {
            fprintf(stderr, "unable to delete file %s: %d", TEMP_FILE, GetLastError());
            exit(1);
        }
    }
    if (argc == 1) {
        /* parent */
        if (!CreateProcess(argv[0], "procterm.exe 1", NULL, NULL, FALSE, 0,
                           NULL, NULL, &si, &pi)) 
            fprintf(stderr, "ERROR on CreateProcess\n"); 
        else {
            int status, count = 0;

            /* make an error, to test -native_parent by its absence */
            char *alloc = malloc(3);
            *(alloc + 3) = 1;
            free(alloc);

            /* wait for child to allocate its memory */
            while (count < MAX_ATTEMPTS && _access(TEMP_FILE, 4/*read*/) == -1) {
                Sleep(SLEEP_PER_ATTEMPT);
                count++;
            }
            TerminateProcess(pi.hProcess, 42);
            WaitForSingleObject(pi.hProcess, INFINITE);
            GetExitCodeProcess(pi.hProcess, (LPDWORD) &status);
            fprintf(stderr, "child has exited with status %d\n", status);
            CloseHandle(pi.hProcess);
        }
    }
    else {
        /* child */
        HANDLE f = INVALID_HANDLE_VALUE;
        DWORD written;

        /* leak something and let's ensure -soft_kills performs the leak scan */
        allocate_something();

        /* tell parent we've done the allocation */
        f = CreateFile(TEMP_FILE, GENERIC_WRITE, FILE_SHARE_READ,
                       NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "cannot create file %s: %d\n", TEMP_FILE, GetLastError());
        } else if (!WriteFile(f, &f, sizeof(f), &written, NULL) ||
                   written != sizeof(f)) {
            fprintf(stderr, "cannot write file %s: %d\n", TEMP_FILE, GetLastError());
        }
        CloseHandle(f);

        /* now wait until parent kills us */
        Sleep(30000);
    }
    fprintf(stderr, "app exiting\n");
    return 0;
}
