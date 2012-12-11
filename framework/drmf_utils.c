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

/* Dr. Memory Framework: globals to satisfy the logging/assert/notify code
 * for our exported Dr. Syscall library and avoid compiling our code twice.
 */

#include "dr_api.h"
#include <ctype.h> /* for tolower */

bool op_print_stderr = false;
uint op_verbose_level = 0;
bool op_ignore_asserts = true;
file_t f_global = INVALID_FILE;
int tls_idx_util = -1;
file_t f_results = INVALID_FILE;

void
drmemory_abort(void)
{
    /* nothing */
}

void
print_prefix_to_console(void)
{
    /* nothing */
}
