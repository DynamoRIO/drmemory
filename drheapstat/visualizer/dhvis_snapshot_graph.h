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

/* dhvis_snapshot_graph.h
 *
 * Defines the snapshot data graph
 */

#ifndef DHVIS_SNAPSHOT_GRAPH_H
#define DHVIS_SNAPSHOT_GRAPH_H

#include <QCheckBox>
#include <QGridLayout>
#include <QPushButton>
#include <QColor>

#include "dhvis_structures.h"
#include "dhvis_graph.h"

struct dhvis_snapshot_listing_t;

class dhvis_snapshot_graph_t : public dhvis_graph_t
{
    Q_OBJECT
public:
    dhvis_snapshot_graph_t(QVector<dhvis_snapshot_listing_t *> *vec,
                           QString *time_unit_,
                           dhvis_options_t *options_);

    bool is_null(void);

public slots:
    void update_settings(void);

private slots:
    void reset_graph_zoom(void);

    void change_lines(void);

    void select_stale_type(bool checked);

    void set_stale_num(const qreal &new_num);

signals:
    void highlight_changed(quint64 new_snapshot, quint64 new_index);

protected:
    void paintEvent(QPaintEvent *event);

    void mousePressEvent(QMouseEvent *event);

    void mouseReleaseEvent(QMouseEvent *event);

    void mouseMoveEvent(QMouseEvent *event);

private:
    void create_layout(void);

    void highlighted_snapshot(void);

    void set_heap_data(QVector<dhvis_snapshot_listing_t *> *vec);

    void draw_helper(QPainter *painter, qreal &total_percent,
                     QVector<QPoint> &prev_points, int loc,
                     quint64 *data, bool stored);

    void draw_heap_data(QPainter *painter);

    void max_height(void);

    void max_width(void);

    qreal x_axis_width(void);

    qreal y_axis_height(void);

    qreal data_point_y(const quint64 &y);

    qreal data_point_x(const qreal &x);

    void draw_view_cursor(QPainter *painter);

    QString create_stale_suffix(const qreal &num);

    bool fix_point_coincidence(QVector<QPoint> &points, QPoint *next, int offset,
                               bool exact);

    /* GUI */
    QGridLayout *control_layout;
    QPushButton *reset_graph_zoom_button;

    QCheckBox *headers_check_box;
    bool headers_line;
    QCheckBox *padding_check_box;
    bool padding_line;
    QCheckBox *mem_alloc_check_box;
    bool mem_alloc_line;
    QCheckBox *total_stale_check_box;
    bool staleness_line;

    /* Data */
    QVector<dhvis_snapshot_listing_t *> *snapshots;
    quint64 avg_time_between_snapshots;
};

#endif
