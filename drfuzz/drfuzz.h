/* **************************************************************
 * Copyright (c) 2015 Google, Inc.  All rights reserved.
 * **************************************************************/

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
 * * Neither the name of Google, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef _DR_FUZZ_H_
#define _DR_FUZZ_H_ 1

/* Dr. Fuzz: DynamoRIO Fuzz Testing Extension */

/* Framework-shared header */
#include "drmemory_framework.h"
#include "../framework/drmf.h"

/**
 * @file drfuzz.h
 * @brief Header for Dr. Fuzz: DynamoRIO Fuzz Testing Extension
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup drfuzz Dr. Fuzz: DynamoRIO Fuzz Testing Extension
 */
/*@{*/ /* begin doxygen group */

DR_EXPORT
/**
 * Initialize the Dr. Fuzz extension. This function must be called before any other
 * Dr. Fuzz API functions. Can be called any number of times, but each call must be
 * paired with a corresponding call to drfuzz_exit().
 */
drmf_status_t
drfuzz_init(client_id_t client_id);

DR_EXPORT
/**
 * Clean up all resources used by the Dr. Fuzz extension.
 */
drmf_status_t
drfuzz_exit(void);

/*@}*/ /* end doxygen group */

#ifdef __cplusplus
}
#endif

#endif /* _DR_FUZZ_H_ */
