/* **********************************************************
 * Copyright (c) 2011-2014 Google, Inc.  All rights reserved.
 * Copyright (c) 2007-2010 VMware, Inc.  All rights reserved.
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

/* Code shared between Dr. Memory and the DRMF Extensions (which don't
 * want to link the full utils.c)
 */

#include "dr_api.h"
#include "utils.h"
#include <ctype.h> /* for tolower */
#include <string.h>

/* not available in ntdll CRT so we supply our own */
#ifndef MACOS /* available on Mac */
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
#endif

char *
drmem_strdup(const char *src, heapstat_t type)
{
    char *dup = NULL;
    if (src != NULL) {
        dup = global_alloc(strlen(src)+1, type);
        strncpy(dup, src, strlen(src)+1);
    }
    return dup;
}

char *
drmem_strndup(const char *src, size_t max, heapstat_t type)
{
    char *dup = NULL;
    /* deliberately not calling strlen on src since may be quite long */
    const char *c;
    size_t sz;
    for (c = src; c != '\0' && (c - src < max); c++)
        ; /* nothing */
    sz = (c - src < max) ? c -src : max;
    if (src != NULL) {
        dup = global_alloc(sz + 1, type);
        strncpy(dup, src, sz);
        dup[sz] = '\0';
    }
    return dup;
}
