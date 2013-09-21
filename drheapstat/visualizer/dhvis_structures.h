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

/* dhvis_structures.h
 *
 * Defines the structures used by the Dr. Heapstat visualizer
 *
 */

#ifndef DHVIS_STRUCTURES_H
#define DHVIS_STRUCTURES_H

#include <QMap>
#include <QVector>

struct dhvis_callstack_listing_t;

/* Many of the frames are the same, so we keep track of
 * the uniques by address.
 */
typedef QMap<quint64, QString> frame_map_t;

struct dhvis_snapshot_listing_t {
    QVector<dhvis_callstack_listing_t *> assoc_callstacks;
    quint64 snapshot_num;
    quint64 tot_mallocs;
    quint64 tot_bytes_asked_for;
    quint64 tot_bytes_usable;
    quint64 tot_bytes_occupied;
    quint64 num_time;
    bool is_peak;
};

struct dhvis_callstack_listing_t {
    QList<QString *> frame_data;
    quint64 callstack_num;
    quint64 instances;
    quint64 bytes_asked_for;
    quint64 extra_usable;
    quint64 extra_occupied;
    quint64 cur_snap_num;
};

struct dhvis_options_t {
    QString def_load_dir;
};

#endif
