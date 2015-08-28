/* **********************************************************
 * Copyright (c) 2014 Google, Inc.  All rights reserved.
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

/* This program installs Dr. Memory as an External Tool for Visual Studio.
 * There is no clean interface to do this, so we have to write directly
 * to registry keys.  The program also supports uninstalling.
 * Xref i#1009c#4.
 *
 * The program expects to be launched from the installer.
 * XXX: it would be nice to have an option so the user can disable running
 * this, but we don't have that kind of NSIS integration.
 *
 * One argument is required: either "-uninstall", or the full path to
 * drmemory.exe.
 *
 * XXX: as VS embeds the tool number inside the key values, we can
 * easily have a race with another registry editing program, or with
 * VS itself.
 *
 * XXX: for VS2010 Express, the user has to manually select
 * "Tools | Settings | Expert Settings" to enable External Tools in general.
 * I did not see a way to do that automatically.
 */

#define UNICODE

#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

#define BUFFER_SIZE_BYTES(buf)      sizeof(buf)
#define BUFFER_SIZE_ELEMENTS(buf)   (BUFFER_SIZE_BYTES(buf) / sizeof((buf)[0]))
#define BUFFER_LAST_ELEMENT(buf)    (buf)[BUFFER_SIZE_ELEMENTS(buf) - 1]
#define NULL_TERMINATE_BUFFER(buf)  BUFFER_LAST_ELEMENT(buf) = 0

#define MIN_VS_VER    8 /* VS2005 */
#define MAX_VS_VER   16 /* trying to look forwarded: tested only through 12 */
#define VS_ROOT      L"SOFTWARE\\Microsoft\\VisualStudio\\%d.0\\External Tools"
/* VS2008 Express and VS2010 Express use this */
#define VS_ALT1_ROOT L"SOFTWARE\\Microsoft\\VCExpress\\%d.0\\External Tools"
/* VS2012 Express and VS2013 Express use this */
#define VS_ALT2_ROOT L"SOFTWARE\\Microsoft\\WDExpress\\%d.0\\External Tools"

/* We want to set these two options */
#define TOOLOPT_PROMPTFORARGS 0x04
#define TOOLOPT_USEOUTPUTWIN  0x08

/* Straight from our documentation */
#define TOOL_TITLE  L"Dr. Memory"
#define TOOL_ARGS   L"-visual_studio -- $(TargetPath)"
#define TOOL_DIR    L"$(TargetDir)"
#define TOOL_OPTS   (TOOLOPT_PROMPTFORARGS | TOOLOPT_USEOUTPUTWIN)

static DWORD
nbytes(const wchar_t *str)
{
    return sizeof(wchar_t) * (wcslen(str) + 1);
}

static BOOL
remove_tool_value(HKEY key, const wchar_t *name_base, DWORD index)
{
    LONG res;
    wchar_t name[MAX_PATH];
    _snwprintf(name, BUFFER_SIZE_ELEMENTS(name), L"%s%d", name_base, index);
    NULL_TERMINATE_BUFFER(name);
    res = RegDeleteValueW(key, name);
    if (res != ERROR_SUCCESS) {
        /* Some values are not always present, so don't print a message */
        if (wcscmp(name_base, L"ToolTitlePkg") != 0 &&
            wcscmp(name_base, L"ToolTitleResID") != 0)
            fprintf(stderr, "Failed to remove %S: %d\n", name, res);
        return FALSE;
    }
    return TRUE;
}

static BOOL
copy_tool_value(HKEY key, const wchar_t *name_base, DWORD src, DWORD dst, DWORD type)
{
    LONG res;
    wchar_t name_src[MAX_PATH];
    wchar_t name_dst[MAX_PATH];
    BYTE val[MAX_PATH*sizeof(wchar_t)];
    DWORD get_type, size;

    _snwprintf(name_src, BUFFER_SIZE_ELEMENTS(name_src), L"%s%d", name_base, src);
    NULL_TERMINATE_BUFFER(name_src);
    size = BUFFER_SIZE_BYTES(val);
    res = RegQueryValueExW(key, name_src, 0, &get_type, val, &size);
    if (res != ERROR_SUCCESS || get_type != type) {
        /* Some values are not always present, so don't print a message */
        if (wcscmp(name_base, L"ToolTitlePkg") != 0 &&
            wcscmp(name_base, L"ToolTitleResID") != 0)
            fprintf(stderr, "Failed to get %S: %d\n", name_src, res);
        return FALSE;
    }

    _snwprintf(name_dst, BUFFER_SIZE_ELEMENTS(name_dst), L"%s%d", name_base, dst);
    NULL_TERMINATE_BUFFER(name_dst);
    res = RegSetValueExW(key, name_dst, 0, type, val, size);
    if (res != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to set %S: %d\n", name_dst, res);
        return FALSE;
    }

    return TRUE;
}

static BOOL
uninstall_tool(HKEY key)
{
    LONG res;
    wchar_t name[MAX_PATH];
    wchar_t val[MAX_PATH];
    DWORD num_keys, type, size, i;
    DWORD tool_opts = TOOL_OPTS;

    size = sizeof(num_keys);
    res = RegQueryValueExW(key, L"ToolNumKeys", 0, &type, (LPBYTE) &num_keys, &size);
    if (res != ERROR_SUCCESS || type != REG_DWORD || size != sizeof(num_keys)) {
        fprintf(stderr, "Failed to query ToolNumKeys: %d\n", res);
        return FALSE;
    }

    for (i = 0; i < num_keys; i++) {
        _snwprintf(name, BUFFER_SIZE_ELEMENTS(name), L"ToolTitle%d", i);
        NULL_TERMINATE_BUFFER(name);
        size = BUFFER_SIZE_BYTES(val);
        res = RegQueryValueExW(key, name, 0, &type, (LPBYTE) val, &size);
        NULL_TERMINATE_BUFFER(val);
        if (res == ERROR_SUCCESS && type == REG_SZ &&
            wcscmp(val, TOOL_TITLE) == 0) {
            printf("Removing Dr. Memory entry #%d\n", i);
            break;
        }
    }

    if (i == num_keys) {
        printf("Did not find a Dr. Memory entry\n");
        return FALSE;
    }

    num_keys--;
    res = RegSetValueExW(key, L"ToolNumKeys", 0, REG_DWORD, (LPBYTE) &num_keys,
                         sizeof(num_keys));
    if (res != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to set ToolNumKeys: %d\n", res);
        return FALSE;
    }

    /* Now shift all the existing entries down one index.
     * On a failure in any one of these we simply keep going.
     */
    for (; i < num_keys; i++) {
        copy_tool_value(key, L"ToolTitle", i+1, i, REG_SZ);
        copy_tool_value(key, L"ToolCmd", i+1, i, REG_SZ);
        copy_tool_value(key, L"ToolDir", i+1, i, REG_SZ);
        copy_tool_value(key, L"ToolArg", i+1, i, REG_SZ);
        copy_tool_value(key, L"ToolOpt", i+1, i, REG_DWORD);
        copy_tool_value(key, L"ToolSourceKey", i+1, i, REG_SZ);
        copy_tool_value(key, L"ToolTitlePkg", i+1, i, REG_SZ);
        copy_tool_value(key, L"ToolTitleResID", i+1, i, REG_DWORD);
    }
    remove_tool_value(key, L"ToolTitle", num_keys);
    remove_tool_value(key, L"ToolCmd", num_keys);
    remove_tool_value(key, L"ToolDir", num_keys);
    remove_tool_value(key, L"ToolArg", num_keys);
    remove_tool_value(key, L"ToolOpt", num_keys);
    remove_tool_value(key, L"ToolSourceKey", num_keys);
    remove_tool_value(key, L"ToolTitlePkg", num_keys);
    remove_tool_value(key, L"ToolTitleResID", num_keys);

    return TRUE;
}

static BOOL
write_tool_value(HKEY key, const wchar_t *name_base, DWORD index, DWORD type,
                 LPBYTE value, DWORD value_sz)
{
    LONG res;
    wchar_t name[MAX_PATH];
    _snwprintf(name, BUFFER_SIZE_ELEMENTS(name), L"%s%d", name_base, index);
    NULL_TERMINATE_BUFFER(name);
    res = RegSetValueExW(key, name, 0, type, value, value_sz);
    if (res != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to set %S: %d\n", name_base, res);
        return FALSE;
    }
    return TRUE;
}

static BOOL
install_tool(HKEY key, const wchar_t *tool_path)
{
    LONG res;
    wchar_t name[MAX_PATH];
    wchar_t val[MAX_PATH];
    DWORD num_keys, type, size, i;
    DWORD tool_opts = TOOL_OPTS;

    size = sizeof(num_keys);
    res = RegQueryValueExW(key, L"ToolNumKeys", 0, &type, (LPBYTE) &num_keys, &size);
    if (res != ERROR_SUCCESS || type != REG_DWORD || size != sizeof(num_keys)) {
        fprintf(stderr, "Failed to query ToolNumKeys: %d\n", res);
        return FALSE;
    }

    for (i = 0; i < num_keys; i++) {
        _snwprintf(name, BUFFER_SIZE_ELEMENTS(name), L"ToolTitle%d", i);
        NULL_TERMINATE_BUFFER(name);
        size = BUFFER_SIZE_BYTES(val);
        res = RegQueryValueExW(key, name, 0, &type, (LPBYTE) val, &size);
        NULL_TERMINATE_BUFFER(val);
        if (res == ERROR_SUCCESS && type == REG_SZ &&
            wcscmp(val, TOOL_TITLE) == 0) {
            /* XXX: should we only replace if the path is from our installer
             * to avoid clobbering a manually-added special entry or sthg?
             * But we can't really tell if they used a custom install dir.
             */
            printf("Dr. Memory already installed: replacing the entry (#%d)\n", i);
            break;
        }
    }

    if (i == num_keys) {
        printf("Adding Dr. Memory as entry #%d\n", i);
        num_keys++;
        res = RegSetValueExW(key, L"ToolNumKeys", 0, REG_DWORD, (LPBYTE) &num_keys,
                            sizeof(num_keys));
        if (res != ERROR_SUCCESS) {
            fprintf(stderr, "Failed to set ToolNumKeys: %d\n", res);
            return FALSE;
        }
    }

    /* On a failure in any one of these we simply keep going */
    write_tool_value(key, L"ToolTitle", i, REG_SZ, (LPBYTE) TOOL_TITLE,
                     nbytes(TOOL_TITLE));
    write_tool_value(key, L"ToolCmd", i, REG_SZ, (LPBYTE) tool_path, nbytes(tool_path));
    write_tool_value(key, L"ToolDir", i, REG_SZ, (LPBYTE) TOOL_DIR, nbytes(TOOL_DIR));
    write_tool_value(key, L"ToolArg", i, REG_SZ, (LPBYTE) TOOL_ARGS, nbytes(TOOL_ARGS));
    write_tool_value(key, L"ToolOpt", i, REG_DWORD, (LPBYTE) &tool_opts, sizeof(DWORD));
    write_tool_value(key, L"ToolSourceKey", i, REG_SZ, (LPBYTE) L"", nbytes(L""));
    /* We do not write ToolTitlePkg or ToolTitleResID */

    return TRUE;
}

static void
try_VS_install(const wchar_t *registry, int ver, BOOL uninstall, const wchar_t *tool_path)
{
    LONG res;
    HKEY key;
    wchar_t root[MAX_PATH];
    _snwprintf(root, BUFFER_SIZE_ELEMENTS(root), registry, ver);
    NULL_TERMINATE_BUFFER(root);
    res = RegOpenKeyExW(HKEY_CURRENT_USER, root, 0, KEY_READ|KEY_WRITE, &key);
    if (res == ERROR_SUCCESS) {
        printf("Installing for Visual Studio %d.0\n", ver);
        if (uninstall)
            uninstall_tool(key);
        else
            install_tool(key, tool_path);
    }
    res = RegCloseKey(key);
}

int
wmain(int argc, const wchar_t *argv[])
{
    int ver;
    BOOL uninstall = FALSE;

    if (argc != 2) {
        fprintf(stderr, "Error: one arg required (-uninstall, or drmemory.exe path)\n");
        return 1;
    }
    if (wcscmp(argv[1], L"-uninstall") == 0)
        uninstall = TRUE;

    /* Go ahead and install for all versions of VS we find */
    for (ver = MIN_VS_VER; ver <= MAX_VS_VER; ver++) {
        try_VS_install(VS_ROOT, ver, uninstall, argv[1]);
        try_VS_install(VS_ALT1_ROOT, ver, uninstall, argv[1]);
        try_VS_install(VS_ALT2_ROOT, ver, uninstall, argv[1]);
    }
    /* It's not an error to find nothing (we run this from our installer) */
    return 0;
}
