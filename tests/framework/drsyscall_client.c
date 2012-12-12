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

/* Test of the Dr. Syscall Extension */

#include "dr_api.h"
#include "drsyscall.h"

#undef ASSERT /* we don't want msgbox */
#define ASSERT(cond, msg) \
    ((void)((!(cond)) ? \
     (dr_fprintf(STDERR, "ASSERT FAILURE: %s:%d: %s (%s)", \
                 __FILE__,  __LINE__, #cond, msg), \
      dr_abort(), 0) : 0))

static
void exit_event(void)
{
    if (drsys_exit() != DRMF_SUCCESS)
        ASSERT(false, "drsys failed to exit");
    dr_fprintf(STDERR, "TEST PASSED\n");
}

DR_EXPORT
void dr_init(client_id_t id)
{
    drsys_options_t ops = { sizeof(ops), 0, };
    if (drsys_init(id, &ops) != DRMF_SUCCESS)
        ASSERT(false, "drsys failed to init");
    dr_register_exit_event(exit_event);
}
