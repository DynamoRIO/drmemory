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

#define _CRT_RAND_S
#include <windows.h>

#include <stdlib.h>

#include "gtest/gtest.h"

TEST(CryptoTests, Rand) {
    // Was: http://https://github.com/DynamoRIO/drmemory/issues/15
    unsigned int value = 1;
    ASSERT_EQ(0, rand_s(&value));
}

// From:
// http://msdn.microsoft.com/en-us/library/windows/desktop/aa379931(v=vs.85).aspx
typedef struct _plaintext_blob_t {
    BLOBHEADER hdr;
    DWORD cbKeySize;
    BYTE rgbKeyData[1];
} plaintext_blob_t;

// http://https://github.com/DynamoRIO/drmemory/issues/412
TEST(CryptoTests, CryptoBasic) {
    BOOL success;
    HCRYPTPROV provider;
    success = CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_AES, 0);
    // Ask for a new keyset if this one doesn't exist.
    if (!success && GetLastError() == NTE_BAD_KEYSET) {
        success = CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_AES,
                                      CRYPT_NEWKEYSET);
    }
    ASSERT_TRUE(success) << "CryptAcquireContext failed: " << GetLastError();

    HCRYPTKEY key;
    success = CryptGenKey(provider, CALG_AES_256, CRYPT_EXPORTABLE, &key);
    ASSERT_TRUE(success) << "CryptGenKey failed: " << GetLastError();

    // Get the key size.
    DWORD buffer_size = 0;
    success = CryptExportKey(key, 0, PLAINTEXTKEYBLOB, 0, NULL, &buffer_size);
    ASSERT_TRUE(success) << "CryptExportKey 1 failed: " << GetLastError();

    // Export the key.
    BYTE *buffer = new BYTE[buffer_size];
    success = CryptExportKey(key, 0, PLAINTEXTKEYBLOB, 0, buffer, &buffer_size);
    ASSERT_TRUE(success) << "CryptExportKey 2 failed: " << GetLastError();

    plaintext_blob_t *blob = (plaintext_blob_t*)buffer;
    ASSERT_EQ(buffer_size - offsetof(plaintext_blob_t, rgbKeyData), blob->cbKeySize);

    // Check that the rest of it is initialized.  Copy the buffer and compare it
    // against itself to trigger the uninit checks.
    BYTE *key_copy = new BYTE[blob->cbKeySize];
    memcpy(key_copy, blob->rgbKeyData, blob->cbKeySize);
    ASSERT_EQ(0, memcmp(blob->rgbKeyData, key_copy, blob->cbKeySize));
    delete [] key_copy;

    delete [] buffer;
    CryptDestroyKey(key);
    CryptReleaseContext(provider, 0);
}
