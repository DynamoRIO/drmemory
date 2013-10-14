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

/* dhvis_graph.cpp
 *
 * Provides the base of most graphs that will be used
 */

#define __CLASS__ "dhvis_graph_t::"

#include <QVector>
#include <QStringList>
#include <QString>
#include <QPicture>
#include <QPainter>
#include <QDebug>

#include <cmath>

#include "dhvis_color_scheme.h"
#include "dhvis_structures.h"
#include "dhvis_graph.h"

/* Round is not a defined function for Visual Studio's compiler
 * so we define our own to maintain compatibility.
 */
#ifdef Q_OS_WIN
    static inline qreal
    round(qreal num) {
        return floor(num + 0.5);
    }
#endif

/* Protected
 * Adjusts width or height dependent variables
 */
void
dhvis_graph_t::resizeEvent(QResizeEvent *event)
{
    Q_UNUSED(event);
    /* Dependent on width */
    right_bound = left_bound + x_axis_width();
    highlighted_point.setX(data_point_x(highlight_percent));

    current_graph_modified = true;
}

/* Private
 * Draws a rectangle on the graph that spans the height of the graph, and
 * the width that the user specifies. The highlighted area is then expanded to the
 * width of the entire graph.
 */
void
dhvis_graph_t::draw_selection(QPainter *painter)
{
    painter->save();
    painter->setPen(QPen(SELECTION_COLOR));
    painter->setBrush(QBrush(SELECTION_COLOR, Qt::SolidPattern));
    static const qreal SELECTION_UPPER_LEFT_Y = -10;
    painter->drawRect(first_point.x(),
                      SELECTION_UPPER_LEFT_Y,
                      last_point.x() - first_point.x(),
                      last_point.y());
    painter->restore();
}

/* Private
 * Draws an empty graph when no data is present
 */
void
dhvis_graph_t::draw_empty_graph(QPainter *painter)
{
    QString msg("No datapoints available!");

    qreal center_x = width() / 2;
    qreal center_y = height() / 2;

    QFontMetricsF font_metrics(font());
    qreal msg_width = font_metrics.width(msg);
    qreal msg_height = font_metrics.height();

    qreal msg_x = center_x - (msg_width / 2);
    qreal msg_y = center_y - (msg_height / 2);

    DHVIS_DRAW_TEXT(painter,
                    painter->drawText(QPointF(msg_x, -msg_y), msg));
}

/* Private
 * Draws the x-axis
 */
void
dhvis_graph_t::draw_x_axis(QPainter *painter)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    painter->save();

    QPen x_axis_pen(QColor(qRgb(0, 0, 0)));

    qreal x_axis_x = 0;
    qreal x_axis_y = 0;
    qreal x_axis_width = right_bound - left_bound;

    painter->setPen(x_axis_pen);
    painter->drawLine(QPointF(x_axis_x, x_axis_y),
                      QPointF(x_axis_width, x_axis_y));

    qreal x_axis_mark = x_axis_x;
    qreal mark_width;
    qreal mark_diff = view_end_mark - view_start_mark;
    if (callstacks_on_this_page != 0)
        mark_diff = callstacks_on_this_page;
    /* Avoid FPE */
    if (mark_diff < 2.0)
        mark_diff = 2.0;
    /* Draw tallies based on num callstacks */
    for (qreal i = 0; i <= mark_diff; i++) {
        mark_width = x_axis_y - GRAPH_MARK_WIDTH;
        /* Make a few ticks longer for use as visual references */
        if ((int)i % (int)round(mark_diff / 4.0) == 0)
            mark_width -= 2;
        painter->drawLine(QPointF(x_axis_mark, x_axis_y),
                          QPointF(x_axis_mark, mark_width));
        /* Adjust count */
        x_axis_mark += (x_axis_width-x_axis_x) / mark_diff;
    }

    painter->restore();
}

/* Private
 * Draws y-axis
 */
void
dhvis_graph_t::draw_y_axis(QPainter *painter)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    painter->save();

    QPen y_axis_pen(QColor(qRgb(0, 0, 0)));

    qreal y_axis_x = 0;
    qreal y_axis_y = 0;
    qreal y_axis_length = y_axis_height() - y_axis_y;

    painter->setPen(y_axis_pen);
    painter->drawLine(QPointF(y_axis_x, y_axis_y),
                      QPointF(y_axis_x, y_axis_length));

    /* Draw scale */
    qreal y_axis_mark = 0;
    quint64 cur_value = 0;
    qreal max_val = height_max;
    QString display_num = "";
    for (int count = 0; count <= num_tabs; count++) {
        /* Ensure max is correct */
        if (count == num_tabs) {
            cur_value = max_val;
            y_axis_mark = y_axis_length;
        }
        QRectF text_space(-(text_width + graph_outer_margin),
                          -(y_axis_mark + text_height / 2),
                          text_width,
                          text_height);
        display_num = QString::number(cur_value);
        if (options->format_bytes)
            display_num = format_bytes(cur_value);
        DHVIS_DRAW_TEXT(painter,
                        painter->drawText(text_space,
                                          display_num,
                                          QTextOption(Qt::AlignRight)));
        /* Draw a cross-graph line and save painter since a different
         * color is used.
         */
        painter->save();
        painter->setPen(QColor(0,0,0,25));
        painter->drawLine(QPointF(y_axis_x, y_axis_mark),
                          QPointF(right_bound - left_bound, y_axis_mark));
        painter->restore();
        /* Axis tick */
        painter->drawLine(QPointF(y_axis_x - GRAPH_MARK_WIDTH, y_axis_mark),
                          QPointF(y_axis_x, y_axis_mark));

        /* Adjust counts */
        y_axis_mark += (y_axis_length - y_axis_y) / (double)num_tabs;
        cur_value += max_val / (double)num_tabs;
    }
    painter->restore();
}
