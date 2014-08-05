/* **********************************************************
 * Copyright (c) 2010-2014 Google, Inc.  All rights reserved.
 * Copyright (c) 2008-2010 VMware, Inc.  All rights reserved.
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

/* Tool to dump version info, for use ensuring we have version info for our
 * binaries.
 */

#include <windows.h>
#include <stdio.h>

int
main(int argc, char *argv[])
{
    DWORD sz;
    BYTE *info;
    VS_FIXEDFILEINFO *ver;
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <dll or exe>\n", argv[0]);
        return 1;
    }
    sz = GetFileVersionInfoSize(argv[1], NULL);
    if (sz == 0) {
        char buf[MAX_PATH];
        DWORD err = GetLastError();
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                      NULL, err, 0, buf, MAX_PATH, NULL);
        fprintf(stderr, "Error %d opening %s: %s", err, argv[1], buf);
        return 0;
    }
    info = malloc(sz);
    if (!GetFileVersionInfo(argv[1], 0, sz, info)) {
        fprintf(stderr, "Error %d reading version info\n", GetLastError());
        free(info);
        return 0;
    }
    if (!VerQueryValue(info, "\\", (void **) &ver, &sz) ||
        sz < sizeof(ver)) {
        fprintf(stderr, "Error retrieving version fields\n");
        free(info);
        return 1;
    }

    printf("FileVersion: %d.%d.%d.%d\n",
           HIWORD(ver->dwFileVersionMS),
           LOWORD(ver->dwFileVersionMS),
           HIWORD(ver->dwFileVersionLS),
           LOWORD(ver->dwFileVersionLS));

    printf("ProductVersion: %d.%d.%d.%d\n",
           HIWORD(ver->dwProductVersionMS),
           LOWORD(ver->dwProductVersionMS),
           HIWORD(ver->dwProductVersionLS),
           LOWORD(ver->dwProductVersionLS));

    free(info);
    return 0;
}
