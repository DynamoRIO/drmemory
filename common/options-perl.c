/* **********************************************************
 * Copyright (c) 2011 Google, Inc.  All rights reserved.
 * Copyright (c) 2009-2010 VMware, Inc.  All rights reserved.
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

/* Options list for perl */

#define OPTION_FRONT OPTION_CLIENT
/* There's no adjacent-string-literal concatenation in Perl */
#ifdef TOOL_DR_MEMORY
# define TOOLNAME ."Dr. Memory".
#else
# define TOOLNAME ."Dr. Heapstat".
#endif

%default_op_vals = (
#define OPTION_CLIENT(scope, name, type, defval, min, max, short, long)  \
                 #name => defval,
#include "optionsx.h"
                 );
#undef OPTION_CLIENT

%typenm = ( 'bool' => '',
            'uint' => ' <int>', /* we have range so simplify as "int" */
            'int'  => ' <int>',
            'opstring_t' => ' <string>' );

#define OPTION_CLIENT(scope, name, type, defval, min, max, short, long)  \
    if (#scope ne 'internal') {                                          \
        $options_usage .= sprintf("  -%-28s [%6s]  %s\n",                \
                                  #name . $typenm{#type}, #defval, short);\
    }
#include "optionsx.h"
#undef OPTION_CLIENT

#undef OPTION_FRONT
