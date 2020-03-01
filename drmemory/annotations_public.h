/* **********************************************************
 * Copyright (c) 2020 Google, Inc.  All rights reserved.
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

#ifndef _ANNOTATIONS_PUBLIC_H_
#define _ANNOTATIONS_PUBLIC_H_ 1

#include "dr_annotations_asm.h"

/* To simplify project configuration, this pragma excludes the file from GCC warnings. */
#ifdef __GNUC__
#    pragma GCC system_header
#endif

#define DRMEMORY_ANNOTATE_DUMP_MEMORY_LAYOUT() \
    DR_ANNOTATION(drmemory_dump_memory_layout)

#ifdef __cplusplus
extern "C" {
#endif

DR_DECLARE_ANNOTATION(void, drmemory_dump_memory_layout, (void));

#ifdef __cplusplus
}
#endif

#endif /* _ANNOTATIONS_PUBLIC_H_ */
