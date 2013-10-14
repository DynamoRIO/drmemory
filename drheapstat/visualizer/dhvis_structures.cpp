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

/* Non-member
 * Takes in a number of bytes and formats it into B, KB, MB or GB.
 * XXX i#1319: Perhaps add an option for base-2 vs base-10
 */
QString format_bytes(const quint64 &data)
{
    static const quint64 THOUSAND_DIGIT_MARKER = 1000;
    static const quint64 MILLION_DIGIT_MARKER = THOUSAND_DIGIT_MARKER * 1000;
    static const quint64 BILLION_DIGIT_MARKER = MILLION_DIGIT_MARKER * 1000;
    quint64 digit_marker = 0;
    QString string_data = QString::number(data);
    QString suffix = "";

    if (data > BILLION_DIGIT_MARKER) {
        suffix = " GB";
        digit_marker = BILLION_DIGIT_MARKER;
    } else if (data > MILLION_DIGIT_MARKER) {
        suffix = " MB";
        digit_marker = MILLION_DIGIT_MARKER;
    } else if (data >  THOUSAND_DIGIT_MARKER) {
        suffix = " KB";
        digit_marker = THOUSAND_DIGIT_MARKER;
    } else {
        suffix = " B";
        digit_marker = 1;
    }

    string_data = QString::number(data / digit_marker) + suffix;

    return string_data;
}