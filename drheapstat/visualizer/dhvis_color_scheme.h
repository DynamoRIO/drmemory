/* **********************************************************
 * Copyright (c) 2013 Branden Clark  All rights reserved.
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

/* dhvis_color_scheme.h
 *
 * Keeps the colors used by dhvis in one place
 */

#include <QColor>

/* Format(Red, Green, Blue, Transparency) */

/* Orange */
static const QColor MEM_ALLOC_LINE_COLOR(255, 102, 0);
/* Green */
static const QColor PADDING_LINE_COLOR(0, 204, 0);
/* Teal */
static const QColor HEADERS_LINE_COLOR(27, 168, 188);
/* Purple */
static const QColor STALENESS_LINE_COLOR(138, 43, 226);
/* Light blue */
static const QColor SELECTION_COLOR(0, 203, 204, 40);
