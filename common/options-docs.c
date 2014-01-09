/* **********************************************************
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

/* Options list for documentation.  A script will:
 * - Remove all "
 * - Escape < and >
 * - Replace @! with <
 * - Replace @% with >
 * - Replace @& with "
 * - Replace @@ with a newline
 */

/* We deliberately add a newline between each list item to work around
 * bugs in doxygen 1.7.0+ (i#920, https://bugzilla.gnome.org/show_bug.cgi?id=678436)
 */
#define OPTION_CLIENT(scope, name, type, defval, min, max, short, long) \
\\if SCOPE_IS_PUBLIC_##scope \
\\if TYPE_IS_BOOL_##type \
 - @!b@% -name @!/b@% @@\
   @!br@%@!i@%default: defval@!/i@% @@\
   @!br@%long @@\
\\endif \
\\if TYPE_IS_STRING_##type \
 - @!b@% -name @!/b@% \\<string\\> @@\
   @!br@%@!i@%default: @&defval@&@!/i@% @@\
   @!br@%long @@\
\\endif \
\\if TYPE_HAS_RANGE_##type \
 - @!b@% -name @!/b@% \\<int\\> @@\
   @!br@%@!i@%default: defval (minimum: min, maximum: max)@!/i@% @@\
   @!br@%long @@\
\\endif \
\\endif @@
#define OPTION_FRONT OPTION_CLIENT
#include "optionsx.h"
#undef OPTION_CLIENT
#undef OPTION_FRONT
