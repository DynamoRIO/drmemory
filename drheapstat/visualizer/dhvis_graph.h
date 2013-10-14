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

/* dhvis_graph.h
 *
 * Defines the base of most graphs that will be used
 */

#ifndef DHVIS_GRAPH_T
#define DHVIS_GRAPH_T

#include <QWidget>
#include <QDoubleSpinBox>
#include <QRadioButton>
#include <QPicture>

class QLabel;

struct dhvis_options_t;

class dhvis_graph_t : public QWidget
{
    Q_OBJECT
public:
    virtual void update_settings(void) = 0;

protected:
    void resizeEvent(QResizeEvent *event);

    void draw_x_axis(QPainter *painter);

    void draw_y_axis(QPainter *painter);

    virtual qreal x_axis_width(void) = 0;

    virtual qreal y_axis_height(void) = 0;

    virtual qreal data_point_x(const qreal &x) = 0;

    virtual qreal data_point_y(const quint64 &y) = 0;

    void draw_empty_graph(QPainter *painter);

    void draw_selection(QPainter *painter);

    /* Graph Boundaries */
    qreal graph_outer_margin;
    QString maximum_value;
    qreal width_max;
    qreal height_max;
    qreal text_width;
    qreal text_height;
    qreal left_bound;
    qreal right_bound;

    /* Selection/zoom */
    QPoint first_point;
    QPoint last_point;
    qreal view_start_mark;
    qreal view_end_mark;
    int callstacks_on_this_page;

    /* Snapshot viewing */
    QPoint highlighted_point;
    qreal highlight_percent;
    int current_snapshot_num;
    int current_snapshot_index;

    /* Graph */
    QPicture current_graph;
    bool current_graph_modified;

    /* Stale controls */
    qreal stale_num;
    /* true = stale for
     * false = stale since
     */
    bool stale_type;
    QDoubleSpinBox *stale_num_spin_box;
    QLabel *stale_spin_box_label;
    QRadioButton *stale_for_radio;
    QRadioButton *stale_since_radio;

    /* Data */
    QString *time_unit;

    /* Options */
    dhvis_options_t *options;
    int num_tabs;

    static const int AXIS_SUFFIX_PADDING = 12;
    static const int EXTRA_AXIS_PADDING = 5;
};

#endif
