/* **********************************************************
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

/* **********************************************************
 * Copyright (c) 2003-2007 VMware, Inc.  All rights reserved.
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

/* Modeled after DynamoRIO's MD5 and CRC32 code */

#ifndef _CRYPTO_H_
#define _CRYPTO_H_ 1

#include "dr_api.h"

/* MD5 */
/* Note: MD5 is only 16 bytes in length, but it is usually used as a
 * string, so each byte will result in 2 chars being used.
 */
#define MD5_BLOCK_LENGTH 64
#define MD5_RAW_BYTES 16
#define MD5_STRING_LENGTH  (2*MD5_RAW_BYTES)

/* To compute the message digest of several chunks of bytes, declare
 * an md5_context_t structure, pass it to md5_init, call md5_update as
 * needed on buffers full of bytes, and then call md5_final, which will
 * fill a supplied 16-byte array with the digest.
 */
typedef struct _md5_context_t {
    uint state[4];                           /* state */
    uint64 count;                            /* number of bits, mod 2^64 */
    byte buffer[MD5_BLOCK_LENGTH];  /* input buffer */
} md5_context_t;

void
md5_init(md5_context_t *ctx);

void
md5_update(md5_context_t *ctx, const byte *buf, size_t len);

void
md5_final(byte digest[16], md5_context_t *ctx);

void
get_md5_for_region(const byte *region_start, uint len,
                   byte digest[MD5_RAW_BYTES] /* OUT */);

bool
md5_digests_equal(const byte digest1[MD5_RAW_BYTES],
                  const byte digest2[MD5_RAW_BYTES]);

/* Produces a single uint suitable for a hashtable index */
uint
md5_hash(const byte digest[MD5_RAW_BYTES]);

uint
crc32(const char *buf, const uint len);

void
crc32_whole_and_half(const char *buf, const uint len, uint crc[2]);

bool
crc32_whole_and_half_equal(const uint crc1[2], const uint crc2[2]);

/* Produces a single uint suitable for a hashtable index */
uint
crc32_whole_and_half_hash(const uint crc[2]);

#endif /* _CRYPTO_H_ */
