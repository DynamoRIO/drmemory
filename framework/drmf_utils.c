/* **********************************************************
 * Copyright (c) 2012-2013 Google, Inc.  All rights reserved.
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
file_t f_potential = INVALID_FILE;

typedef int heapstat_t;

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

void *
global_alloc(size_t size, heapstat_t type)
{
    return dr_global_alloc(size);
}

void
global_free(void *p, size_t size, heapstat_t type)
{
    dr_global_free(p, size);
}

void *
thread_alloc(void *drcontext, size_t size, heapstat_t type)
{
    return dr_thread_alloc(drcontext, size);
}

void
thread_free(void *drcontext, void *p, size_t size, heapstat_t type)
{
    dr_thread_free(drcontext, p, size);
}

void *
nonheap_alloc(size_t size, uint prot, heapstat_t type)
{
    return dr_nonheap_alloc(size, prot);
}

void
nonheap_free(void *p, size_t size, heapstat_t type)
{
    dr_nonheap_free(p, size);
}

bool
safe_read(void *base, size_t size, void *out_buf)
{
    size_t bytes_read = 0;
    return (dr_safe_read(base, size, out_buf, &bytes_read) &&
            bytes_read == size);
}

#if DEBUG
void
report_callstack(void *drcontext, dr_mcontext_t *mc)
{
}
#endif /* DEBUG */

/* not available in ntdll CRT so we supply our own */
/* XXX: duplicated vs utils.c: share via shared_utils.c or sthg? */
const char *
strcasestr(const char *text, const char *pattern)
{
    const char *cur_text, *cur_pattern, *root;
    cur_text = text;
    root = text;
    cur_pattern = pattern;
    while (true) {
        if (*cur_pattern == '\0')
            return root;
        if (*cur_text == '\0')
            return NULL;
        if ((char)tolower(*cur_text) == (char)tolower(*cur_pattern)) {
            cur_text++;
            cur_pattern++;
        } else {
            root++;
            cur_text = root;
            cur_pattern = pattern;
        }
    }
}

