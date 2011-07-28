/* **********************************************************
 * Copyright (c) 2011 Google, Inc.  All rights reserved.
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

#include <windows.h>

#pragma comment(lib, "advapi32.lib")

#include "gtest/gtest.h"

TEST(RegistryTests, CreateGetKey) {
    // Was: http://code.google.com/p/drmemory/issues/detail?id=408
    HKEY hklm_key;
    DWORD disposition;
    LONG result;

    wchar_t subkey[] = L"Software\\DrMemory Unit Tests\\HKLM Override";
    RegDeleteKeyW(HKEY_CURRENT_USER, subkey);  // Remove the key if it was present.

    result = RegCreateKeyExW(HKEY_CURRENT_USER, subkey,
                             0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
                             NULL, &hklm_key, &disposition);
    ASSERT_EQ(ERROR_SUCCESS, result);

    // Create a SID that represents ALL USERS.
    DWORD users_sid_size = SECURITY_MAX_SID_SIZE;
    SID users_sid[SECURITY_MAX_SID_SIZE];
    ::CreateWellKnownSid(WinBuiltinUsersSid, NULL, users_sid, &users_sid_size);

    // Get the security descriptor for the registry key.
    DWORD original_sd_size_needed = 0;
    result = RegGetKeySecurity(hklm_key, DACL_SECURITY_INFORMATION, NULL,
                               &original_sd_size_needed);
    ASSERT_EQ(ERROR_INSUFFICIENT_BUFFER, result);

    SECURITY_DESCRIPTOR original_sd[100];
    ASSERT_LE(original_sd_size_needed, sizeof(original_sd));

    result = RegGetKeySecurity(hklm_key, DACL_SECURITY_INFORMATION, original_sd,
                               &original_sd_size_needed);
    ASSERT_EQ(ERROR_SUCCESS, result);
}
