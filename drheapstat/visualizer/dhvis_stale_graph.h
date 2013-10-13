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

/* dhvis_stale_graph.h
 *
 * Defines the staleness data graph
 */

#ifndef DHVIS_STALE_GRAPH_H
#define DHVIS_STALE_GRAPH_H

#include "dhvis_graph.h"

class QHBoxLayout;
class QLabel;
class QPushButton;
class QSpinBox;
class QRadioButton;
class QToolButton;

struct dhvis_callstack_listing_t;
struct dhvis_snapshot_listing_t;

class dhvis_stale_graph_t : public dhvis_graph_t
{
    Q_OBJECT
public:
    dhvis_stale_graph_t(QVector<dhvis_callstack_listing_t *> *vec,
                        QVector<dhvis_snapshot_listing_t *> *s_vec,
                        QString *time_unit_,
                        int cur_snap_num,
                        int cur_snap_index,
                        dhvis_options_t *options_);

    bool is_null(void);

public slots:
    void update_settings();

private slots:
    void reset_graph_zoom(void);

    void show_prev_page(void);

    void show_next_page(void);

    void select_stale_type(bool checked);

    void set_stale_num(const qreal &new_num);

protected:
    void paintEvent(QPaintEvent *event);


    void mousePressEvent(QMouseEvent *event);

    void mouseReleaseEvent(QMouseEvent *event);

    void mouseMoveEvent(QMouseEvent *event);

private:
    void set_heap_data(QVector<dhvis_callstack_listing_t *> *vec,
                       QVector<dhvis_snapshot_listing_t *> *s_vec);

    void create_layout(void);

    void draw_helper(QPainter *painter, qreal &total_percent,
                     qreal &prev_percent,
                     dhvis_callstack_listing_t *callstack);

    void draw_heap_data(QPainter *painter);


    void max_height(void);

    void max_width(void);

    qreal x_axis_width(void);

    qreal y_axis_height(void);

    qreal data_point_y(const quint64 &y);

    qreal data_point_x(const qreal &x);

    void draw_view_cursor(QPainter *painter);

    qreal calc_callstack_index(const qreal &x_val);

    void calc_visible_callstacks(void);

    QString create_stale_suffix(const qreal &num);

    /* GUI */
    bool zooming;
    QVector<dhvis_callstack_listing_t *> visible_callstacks;
    int display_page;
    QToolButton *prev_page_button,
                *next_page_button;
    QLabel *page_label;

    /* Data */
    QVector<dhvis_callstack_listing_t *> *callstacks;
    QVector<dhvis_snapshot_listing_t *> *snapshots;
    int avg_time_between_snapshots;

    /* Controls */
    QHBoxLayout *control_layout;
    QLabel *info_label;
    QPushButton *reset_zoom_button;
};

#endif
