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
struct dhvis_frame_data_t;

/* Need to typedef because ',' confuses Qt's foreach macro */
typedef QPair<quint64, quint64> stale_pair_t;
      /* <snapshot_num, (bytes,last_access)> */
typedef QMap<quint64, QVector<stale_pair_t> > stale_map_t;
#define STALE_BYTES first
#define STALE_LAST_ACCESS second

#define GRAPH_MARK_WIDTH 5
/* Fix scale for text; it appears upside down because Qt defaults to the
 * origin being at top left, with increasing 'y' going down. I adjust it
 * to bottom left for graphing with icreasing 'y' going up.
 */
#define DHVIS_DRAW_TEXT(painter, command) do { \
                                              (painter)->save(); \
                                              (painter)->scale(1, -1); \
                                              (command); \
                                              (painter)->restore(); \
                                          } while (0)

/* Many of the frames are the same, so we keep track of
 * the uniques by address.
 */
typedef QMap<quint64, dhvis_frame_data_t *> frame_map_t;

struct dhvis_snapshot_listing_t {
    QVector<dhvis_callstack_listing_t *> assoc_callstacks;
    QVector<dhvis_callstack_listing_t *> stale_callstacks;
    quint64 snapshot_num;
    quint64 tot_mallocs;
    quint64 tot_bytes_asked_for;
    quint64 tot_bytes_usable;
    quint64 tot_bytes_occupied;
    quint64 tot_bytes_stale;
    quint64 num_time;
    bool is_peak;
};

struct dhvis_callstack_listing_t {
    QList<dhvis_frame_data_t *> frame_data;
    quint64 callstack_num;
    quint64 instances;
    quint64 bytes_asked_for;
    quint64 extra_usable;
    quint64 extra_occupied;
    quint64 cur_snap_num;
    stale_map_t staleness_info;
    QMap<quint64, quint64> staleness_sum_info;
};

struct dhvis_frame_data_t {
    QMap<quint64, QVector<dhvis_callstack_listing_t *> > assoc_callstacks;
    QString exec_name;
    QString func_name;
    QString file_path;
    QString file_name;
    QString line_num;
    QString address;
};

struct dhvis_options_t {
    QString def_load_dir;
    QString dhrun_log_dir;
    int snap_vertical_ticks;
    int stale_vertical_ticks;
    int num_callstacks_per_page;
    int num_stale_per_page;
    bool square_graph;
    bool anti_aliasing_enabled;
    bool snap_stale_unit_num;
    bool stale_sum_enabled;
    bool stale_stale_unit_num;
    bool format_bytes;
};

bool sort_snapshots(dhvis_snapshot_listing_t *a,
                    dhvis_snapshot_listing_t *b);

bool stale_callstacks_sorter(dhvis_callstack_listing_t *a,
                             dhvis_callstack_listing_t *b);

bool stale_pair_sorter(stale_pair_t a, stale_pair_t b);

bool stale_sum_sorter(dhvis_callstack_listing_t *a,
                      dhvis_callstack_listing_t *b);

QString format_bytes(const quint64 &data);

#endif
