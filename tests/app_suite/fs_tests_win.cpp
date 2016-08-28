/* **********************************************************
 * Copyright (c) 2013-2016 Google, Inc.  All rights reserved.
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

#include "gtest/gtest.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <string>
#include <windows.h>
#include <Winternl.h>

TEST(FSTests, Stat){
    /* Test i#1298 default suppression of real error in MSVCRT stat() */
    struct stat buf;
    const char* fileName = "";
    std::string fileNameString(fileName);
    stat(fileNameString.c_str(), &buf);
}

TEST(FSTests, FISize){
    /* XXX i#1304: move types from common/windefs.h to wininc/ to avoid
     * duplicate type declaration here */
    typedef struct _FILE_BASIC_INFORMATION {
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        ULONG         FileAttributes;
    } FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;
    ASSERT_EQ(sizeof(LARGE_INTEGER)*4,
              offsetof(FILE_BASIC_INFORMATION, FileAttributes));

    typedef struct _FILE_DISPOSITION_INFORMATION {
        BOOLEAN DeleteFile;
    } FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;
    ASSERT_EQ(sizeof(FILE_DISPOSITION_INFORMATION), sizeof(BOOLEAN));

    typedef struct _FILE_END_OF_FILE_INFORMATION {
        LARGE_INTEGER EndOfFile;
    } FILE_END_OF_FILE_INFORMATION, *PFILE_END_OF_FILE_INFORMATION;
    typedef struct _FILE_VALID_DATA_LENGTH_INFORMATION {
        LARGE_INTEGER ValidDataLength;
    } FILE_VALID_DATA_LENGTH_INFORMATION, *PFILE_VALID_DATA_LENGTH_INFORMATION;
    typedef struct _FILE_POSITION_INFORMATION {
        LARGE_INTEGER CurrentByteOffset;
    } FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;
    ASSERT_EQ(sizeof(FILE_POSITION_INFORMATION), sizeof(LARGE_INTEGER));

    typedef enum _IO_PRIORITY_HINT {
        IoPriorityVeryLow   = 0,
        IoPriorityLow       = 1,
        IoPriorityNormal    = 2,
        IoPriorityHigh      = 3,
        IoPriorityCritical  = 4,
        MaxIoPriorityTypes  = 5
    } IO_PRIORITY_HINT;
    typedef struct _FILE_IO_PRIORITY_HINT_INFORMATION {
        IO_PRIORITY_HINT PriorityHint;
    } FILE_IO_PRIORITY_HINT_INFORMATION, *PFILE_IO_PRIORITY_HINT_INFORMATION;
    ASSERT_EQ(sizeof(FILE_IO_PRIORITY_HINT_INFORMATION), sizeof(IO_PRIORITY_HINT));

    typedef struct _FILE_LINK_INFORMATION {
        BOOLEAN ReplaceIfExists;
        HANDLE  RootDirectory;
        ULONG   FileNameLength;
        WCHAR   FileName[1];
    } FILE_LINK_INFORMATION, *PFILE_LINK_INFORMATION;
    typedef struct _FILE_RENAME_INFORMATION {
        BOOLEAN ReplaceIfExists;
        HANDLE  RootDirectory;
        ULONG   FileNameLength;
        WCHAR   FileName[1];
    } FILE_RENAME_INFORMATION, *PFILE_RENAME_INFORMATION;
    ASSERT_EQ(sizeof(HANDLE) + sizeof(ULONG),
              offsetof(FILE_LINK_INFORMATION, FileName) -
              offsetof(FILE_LINK_INFORMATION, RootDirectory));
}

TEST(FSTests, RenameFile){
    HANDLE hFile = CreateFile(TEXT("testfile.txt"),
                              GENERIC_READ | GENERIC_WRITE,
                              0,          // open with exclusive access
                              NULL,       // no security attributes
                              CREATE_NEW, // creating a new temp file
                              0,          // not overlapped index/O
                              NULL);
    ASSERT_NE(hFile, INVALID_HANDLE_VALUE);
    ASSERT_TRUE(CloseHandle(hFile));
    ASSERT_TRUE(MoveFile(TEXT("testfile.txt"), TEXT("renamefile.txt")));
    ASSERT_TRUE(DeleteFile(TEXT("renamefile.txt")));
}

DWORD WINAPI
JobNotify(HANDLE hiocp)
{
    BOOL flag_done = FALSE;
    DWORD bytes_xferred;
    ULONG entries_num = 3;
    ULONG_PTR comp_key;
    ULONG entries_removed;
    LPOVERLAPPED po;
    OVERLAPPED_ENTRY po_entry[2];
    while (!flag_done) {
        /* The routine calls NtRemoveIoCompletion. */
        BOOL result = GetQueuedCompletionStatus(hiocp,
                                                &bytes_xferred,
                                                &comp_key,
                                                &po,
                                                INFINITE);
        if (!result) {
            printf("GetQueuedCompletionStatus failed with error: %u", GetLastError());
            return 1;
        }
        /* The routine calls NtRemoveIoCompletionEx. */
        result = GetQueuedCompletionStatusEx(hiocp,
                                             po_entry,
                                             entries_num,
                                             &entries_removed,
                                             INFINITE,
                                             FALSE);
        if (!result) {
            printf("GetQueuedCompletionStatusEx failed with error: %u", GetLastError());
            return 1;
        }
        if ((po_entry[0].lpOverlapped != (LPOVERLAPPED)123456789)||
            (po_entry[1].lpOverlapped != (LPOVERLAPPED)987654321)||
              entries_removed != 2)
              printf("GetQueuedCompletionStatus received unexpected output values");
        flag_done = (comp_key == (UINT_PTR) 0);
    }
    return 0;
}

TEST(FSTests, SetIoCompletion) {
    HANDLE hiocp;
    DWORD thread_id_array;
    HANDLE thread_hiocp;
    hiocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    ASSERT_NE(hiocp, INVALID_HANDLE_VALUE);
    thread_hiocp = CreateThread(NULL,
                                0,
                                JobNotify,
                                hiocp,
                                0,
                                &thread_id_array);
    ASSERT_NE(thread_hiocp, INVALID_HANDLE_VALUE);
    /* Post a special key that tells the completion port thread to terminate.
     * The routine calls NtSetIoCompletion.
     */
    BOOL result = PostQueuedCompletionStatus(hiocp,
                                             NULL,
                                             (UINT_PTR) 0,
                                             NULL);
    ASSERT_NE(NULL, result);
    /* We make 2 additional Post syscall to test
     * NtSetIoCompletionEx.
     */
    result = PostQueuedCompletionStatus(hiocp,
                                        NULL,
                                        (UINT_PTR) 0,
                                        (LPOVERLAPPED)123456789);
    ASSERT_NE(NULL, result);
    result = PostQueuedCompletionStatus(hiocp,
                                        NULL,
                                        (UINT_PTR) 0,
                                        (LPOVERLAPPED)987654321);
    ASSERT_NE(NULL, result);
    /* Wait for the completion port thread to terminate */
    WaitForSingleObject(thread_hiocp, INFINITE);
}

TEST(FSTests, NamedPipe) {
    /* Test i#1827 */
    BOOL ret = WaitNamedPipeW(L"\\\\.\\pipe\\bogusname", 1);
    EXPECT_EQ(ret, FALSE);

    /* Test i#1891 */
    ret = WaitNamedPipeW(L"\\\\.\\pipe\\bogusname", NMPWAIT_USE_DEFAULT_WAIT);
    EXPECT_EQ(ret, FALSE);
}
