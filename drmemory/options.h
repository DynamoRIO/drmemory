/* **********************************************************
 * Copyright (c) 2011 Google, Inc.  All rights reserved.
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

#ifndef _OPTIONS_H_
#define _OPTIONS_H_ 1

#include "utils.h"  /* for MAX_OPTION_LEN */

typedef char opstring_t[MAX_OPTION_LEN];

/* for repeatable options (i#574): ends in double nul */
typedef char multi_opstring_t[MAX_OPTION_LEN];

typedef struct _drmemory_options_t {
#define OPTION_CLIENT(scope, name, type, defval, min, max, short, long) \
    type name;
#define OPTION_FRONT(scope, name, type, defval, min, max, short, long) \
    /*nothing*/
    /* we use <> so other tools can override the optionsx.h in "." */
#include <optionsx.h>
} drmemory_options_t;
#undef OPTION_CLIENT
#undef OPTION_FRONT

extern drmemory_options_t options;

extern bool stack_swap_threshold_fixed;

void
options_init(const char *opstr);

void
usage_error(const char *msg, const char *submsg);

#ifdef TOOL_DR_MEMORY
# define ZERO_STACK() (options.zero_stack && options.count_leaks &&\
                       (options.leaks_only || !options.check_uninitialized))
#else
/* we zero for leaks, and staleness does not care about xsp */
# define ZERO_STACK() (options.zero_stack && options.check_leaks)
#endif

#endif /* _OPTIONS_H_ */
