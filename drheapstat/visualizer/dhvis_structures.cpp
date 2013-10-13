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

/* dhvis_structures.cpp
 *
 * Provides the structures used by the Dr. Heapstat visualizer
 */

#include <QMap>
#include <QVector>
#include <QString>

#include "dhvis_structures.h"

/* Non-member
 * Helper for std::sort which sorts snapshots by num_time to
 * align them properly with process lifetime.
 */
bool
sort_snapshots(dhvis_snapshot_listing_t *a,
               dhvis_snapshot_listing_t *b)
{
    return a->num_time < b->num_time;
}

/* Non-member
 * Helper for std::sort
 * Sort each snapshot's stale_callstacks by stale_bytes for staleness graphing
 * (greatest first), with a secondary order of sequential callstack_num.
 */
bool
stale_callstacks_sorter(dhvis_callstack_listing_t *a,
                        dhvis_callstack_listing_t *b)
{
    /* X->staleness_info is already sorted, no need to search */

    quint64 a_max = 0;
    QVector<stale_pair_t> &sp_a = a->staleness_info[a->cur_snap_num];
    if (sp_a[0].STALE_BYTES > a_max)
        a_max = sp_a[0].STALE_BYTES;

    quint64 b_max = 0;
    QVector<stale_pair_t> &sp_b = b->staleness_info[b->cur_snap_num];
    if (sp_b[0].STALE_BYTES > b_max)
        b_max = sp_b[0].STALE_BYTES;

    if (a_max == b_max)
        return a->callstack_num < b->callstack_num;
    return a_max > b_max;
}

/* Non-member
 * Helper for std::sort which defines sorting for
 * stale_pair_t (greatest first).
 */
bool
stale_pair_sorter(stale_pair_t a, stale_pair_t b)
{
    return a.STALE_BYTES > b.STALE_BYTES;
}


/* Non-member
 * Helper for std::sort which defines sorting a snapshot's stale_callstacks by
 * the sum of stale_bytes, with a secondary order of sequential callstack_num.
 */
bool
stale_sum_sorter(dhvis_callstack_listing_t *a,
                 dhvis_callstack_listing_t *b)
{
    /* Already sorted */
    qreal a_max = a->staleness_sum_info[a->cur_snap_num];
    qreal b_max = b->staleness_sum_info[b->cur_snap_num];

    if (a_max == b_max)
        return a->callstack_num < b->callstack_num;
    return a_max > b_max;
}
