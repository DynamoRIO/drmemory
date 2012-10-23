/* **********************************************************
 * Copyright (c) 2012 Google, Inc.  All rights reserved.
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

#ifndef _DR_SYSCALL_H_
#define _DR_SYSCALL_H_ 1

/* Dr. Syscall: DynamoRIO System Call Extension */

/* Framework-shared header */
#include "drmemory_framework.h"

/**
 * @file drsyscall.h
 * @brief Header for Dr. Syscall: System Call Monitoring Extension
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup drsyscall Dr. Syscall: System Call Monitoring Extension
 */
/*@{*/ /* begin doxygen group */


DR_EXPORT
/**
 * Initializes the Dr. Syscall extension.  Must be called prior to any
 * of the other routines, and should only be called once.
 *
 * \return success code.  Will return failure if called a second time.
 */
drmf_status_t
drsys_init(client_id_t client_id);

DR_EXPORT
/**
 * Cleans up the Dr. Syscall extension.
 */
drmf_status_t
drsys_exit(void);


/* FIXME i#822: fill in rest of API */


/*@}*/ /* end doxygen group */

#ifdef __cplusplus
}
#endif

#endif /* _DR_SYSCALL_H_ */
