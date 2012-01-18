/* **********************************************************
 * Copyright (c) 2012 Google, Inc.  All rights reserved.
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

#include <windows.h>
#include <shobjidl.h>
#include <shlguid.h>
#include <fstream>

#include "os_version_win.h"
#include "gtest/gtest.h"

#define BUFFER_SIZE_BYTES(buf)      sizeof(buf)
#define BUFFER_SIZE_ELEMENTS(buf)   (BUFFER_SIZE_BYTES(buf) / sizeof((buf)[0]))

namespace {
const wchar_t *kTempLinkName = L"app_suite_shell_link.lnk";
const wchar_t *kTempFileName = L"app_suite_txt_file.txt";
const wchar_t *kLinkDescription = L"ResolveShortcutTest";
}

class ShellTest : public ::testing::Test {
 protected:
    virtual void SetUp() {
        // Compute link filename.
        wchar_t temp_dir[MAX_PATH];
        int len = GetTempPathW(BUFFER_SIZE_ELEMENTS(temp_dir), temp_dir);
        // GetTempPathW sometimes gives an 8.3 path, so canonicalize into a full
        // path.
        wchar_t full_dir[MAX_PATH];
        len = GetFullPathNameW(temp_dir, BUFFER_SIZE_ELEMENTS(full_dir),
                               full_dir, NULL);
        EXPECT_NE(0, len) << "GetFullPathNameW failed: "
                          << GetLastError() << '\n';
        link_path_.clear();
        link_path_ += temp_dir;  // Documented to end in trailing slash.
        link_path_ += kTempLinkName;

        // Create a text file.
        file_path_.clear();
        file_path_ += temp_dir;  // Documented to end in trailing slash.
        file_path_ += kTempFileName;
        std::wofstream file;
        file.open(file_path_.c_str());
        file << L"File contents\r\n";
        file.close();

        // Initialize COM.
        HRESULT hr = CoInitialize(NULL);
        EXPECT_TRUE(SUCCEEDED(hr));
    }

    virtual void TearDown() {
        DeleteFileW(link_path_.c_str());
        DeleteFileW(file_path_.c_str());
        CoUninitialize();
    }

    std::wstring link_path_;
    std::wstring file_path_;
};

TEST_F(ShellTest, CreateShortcut) {
    // FIXME i#12: Re-enable on XP when passes.
    if (GetWindowsVersion() < WIN_VISTA) {
        printf("WARNING: Disabling ShellTest.* on Pre-Vista, see i#12.\n");
        return;
    }

    HRESULT hr;
    IShellLinkW *shell;
    IPersistFile *persist = NULL;

    // Create a shortcut.
    hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                          IID_IShellLinkW, (LPVOID*)(&shell));
    EXPECT_TRUE(SUCCEEDED(hr));
    hr = shell->QueryInterface(IID_IPersistFile, (void**)(&persist));
    EXPECT_TRUE(SUCCEEDED(hr));
    hr = shell->SetPath(file_path_.c_str());
    EXPECT_TRUE(SUCCEEDED(hr));
    hr = shell->SetDescription(kLinkDescription);
    EXPECT_TRUE(SUCCEEDED(hr));
    hr = persist->Save(link_path_.c_str(), TRUE);
    EXPECT_TRUE(SUCCEEDED(hr));
    if (persist)
        persist->Release();
    if (shell)
        shell->Release();
}

TEST_F(ShellTest, CreateAndResolveShortcut) {
    // FIXME i#12: Re-enable on XP when passes.
    if (GetWindowsVersion() < WIN_VISTA) {
        printf("WARNING: Disabling ShellTest.* on Pre-Vista, see i#12.\n");
        return;
    }


    HRESULT hr;
    IShellLinkW *shell;
    IPersistFile *persist = NULL;

    // Create a shortcut.
    hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                          IID_IShellLinkW, (LPVOID*)(&shell));
    EXPECT_TRUE(SUCCEEDED(hr));
    hr = shell->QueryInterface(IID_IPersistFile, (void**)(&persist));
    EXPECT_TRUE(SUCCEEDED(hr));
    hr = shell->SetPath(file_path_.c_str());
    EXPECT_TRUE(SUCCEEDED(hr));
    hr = shell->SetDescription(kLinkDescription);
    EXPECT_TRUE(SUCCEEDED(hr));
    hr = persist->Save(link_path_.c_str(), TRUE);
    EXPECT_TRUE(SUCCEEDED(hr));
    if (persist)
        persist->Release();
    if (shell)
        shell->Release();

    // Resolve it.

    // Get pointer to the IShellLink interface
    hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                          IID_IShellLinkW, (LPVOID*)&shell);
    EXPECT_TRUE(SUCCEEDED(hr));

    // Query IShellLink for the IPersistFile interface
    hr = shell->QueryInterface(IID_IPersistFile, (void**)(&persist));
    EXPECT_TRUE(SUCCEEDED(hr));

    // Load the shell link
    hr = persist->Load(link_path_.c_str(), STGM_READ);
    EXPECT_TRUE(SUCCEEDED(hr));

    // Try to find the target of a shortcut
    hr = shell->Resolve(0, SLR_NO_UI);
    EXPECT_TRUE(SUCCEEDED(hr));

    wchar_t link_target[MAX_PATH];
    hr = shell->GetPath(link_target, MAX_PATH, NULL, SLGP_UNCPRIORITY);
    EXPECT_TRUE(SUCCEEDED(hr));
    EXPECT_EQ(file_path_, link_target);

    wchar_t description[MAX_PATH];
    hr = shell->GetDescription(description, MAX_PATH);
    EXPECT_TRUE(SUCCEEDED(hr));
    EXPECT_STREQ(kLinkDescription, description);

    if (persist)
        persist->Release();
    if (shell)
        shell->Release();
}
