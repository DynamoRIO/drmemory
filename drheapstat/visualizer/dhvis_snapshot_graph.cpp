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

/* dhvis_snapshot_graph.cpp
 *
 * Provides the snapshot data graph
 */

#define __CLASS__ "dhvis_snapshot_graph_t::"

#include <QWidget>
#include <QPainter>
#include <QPicture>
#include <QDebug>
#include <QMouseEvent>
#include <QGridLayout>
#include <QCheckBox>
#include <QPushButton>
#include <QLabel>
#include <cmath>
#include <QHBoxLayout>

#include "dhvis_color_scheme.h"
#include "dhvis_structures.h"
#include "dhvis_tool.h"
#include "dhvis_graph.h"
#include "dhvis_snapshot_graph.h"

/* Public
 * Constructor
 */
dhvis_snapshot_graph_t::
dhvis_snapshot_graph_t(QVector<dhvis_snapshot_listing_t *> *vec,
                       QString *time_unit_,
                       dhvis_options_t *options_)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    setAttribute(Qt::WA_DeleteOnClose);
    graph_outer_margin = 10;
    snapshots = vec;
    time_unit = time_unit_;
    options = options_;
    if (options != NULL)
        num_tabs = options->snap_vertical_ticks;
    view_start_mark = 0;
    view_end_mark = 100;
    callstacks_on_this_page = 0;
    current_snapshot_num = -1;
    stale_num = -1;
    highlighted_point = QPoint(0,0);
    current_graph_modified = mem_alloc_line = padding_line
                           = headers_line = staleness_line = true;
    create_layout();
    set_heap_data(vec);
    set_stale_num(0);
}

/* Private
 * Creates the layout of the widget
 */
void
dhvis_snapshot_graph_t::create_layout(void)
{
    control_layout = new QGridLayout;
    /* Stale controls */
    QHBoxLayout *stale_controls_layout = new QHBoxLayout;
    stale_num_spin_box = new QDoubleSpinBox(this);
    stale_spin_box_label = new QLabel("");
    if (time_unit != NULL && options != NULL) {
        if (options->snap_stale_unit_num)
            stale_num_spin_box->setSingleStep(.1);
        stale_spin_box_label->setText(create_stale_suffix(0));
    }
    if (snapshots != NULL) {
        quint64 max;
        if (options->snap_stale_unit_num)
            max = snapshots->count();
        else
            max = snapshots->back()->num_time;
        stale_num_spin_box->setRange(0, max);
    }
    /* The spin box doesn't resize properly */
    stale_num_spin_box->setMinimumSize(100, stale_num_spin_box->height());
    connect(stale_num_spin_box, SIGNAL(valueChanged(qreal)),
            this, SLOT(set_stale_num(qreal)));
    QLabel *stale_num_label = new QLabel(tr("stale"), this);
    stale_for_radio = new QRadioButton(tr("for"), this);
    stale_for_radio->setChecked(true);
    connect(stale_for_radio, SIGNAL(toggled(bool)),
            this, SLOT(select_stale_type(bool)));
    stale_since_radio = new QRadioButton(tr("since"), this);
    connect(stale_since_radio, SIGNAL(toggled(bool)),
            this, SLOT(select_stale_type(bool)));

    stale_controls_layout->addStretch(1);
    stale_controls_layout->addWidget(stale_num_label);
    stale_controls_layout->addWidget(stale_for_radio);
    stale_controls_layout->addWidget(stale_since_radio);
    stale_controls_layout->addWidget(stale_num_spin_box);
    stale_controls_layout->addWidget(stale_spin_box_label);

    /* Zoom reset button */
    reset_graph_zoom_button = new QPushButton(tr("Reset Graph Zoom"));
    connect(reset_graph_zoom_button, SIGNAL(clicked()),
            this, SLOT(reset_graph_zoom()));

    /* Line check boxes */
    mem_alloc_check_box = new QCheckBox(tr("Memory allocated ("
                                           "requested) by process"),
                                        this);
    padding_check_box = new QCheckBox(tr("+ Padding"),
                                      this);
    headers_check_box = new QCheckBox(tr("+ Heap headers"),
                                      this);
    total_stale_check_box = new QCheckBox(tr("Total staleness"));
    /* Start with boxes checked */
    mem_alloc_check_box->setCheckState(Qt::Checked);
    padding_check_box->setCheckState(Qt::Checked);
    headers_check_box->setCheckState(Qt::Checked);
    total_stale_check_box->setCheckState(Qt::Checked);
    connect(mem_alloc_check_box, SIGNAL(stateChanged(int)),
            this, SLOT(change_lines()));
    connect(padding_check_box, SIGNAL(stateChanged(int)),
            this, SLOT(change_lines()));
    connect(headers_check_box, SIGNAL(stateChanged(int)),
            this, SLOT(change_lines()));
    connect(total_stale_check_box, SIGNAL(stateChanged(int)),
            this, SLOT(change_lines()));
    /* Color the check boxes */
    QPixmap icon_map(mem_alloc_check_box->height(),
                    mem_alloc_check_box->height());
    icon_map.fill(MEM_ALLOC_LINE_COLOR);
    mem_alloc_check_box->setIcon(icon_map);
    icon_map.fill(PADDING_LINE_COLOR);
    padding_check_box->setIcon(icon_map);
    icon_map.fill(HEADERS_LINE_COLOR);
    headers_check_box->setIcon(icon_map);
    icon_map.fill(STALENESS_LINE_COLOR);
    total_stale_check_box->setIcon(icon_map);

    control_layout->addLayout(stale_controls_layout, 0, 0, 1, 3);
    control_layout->addWidget(reset_graph_zoom_button, 0, 3);
    control_layout->addWidget(mem_alloc_check_box, 1, 0);
    control_layout->addWidget(padding_check_box, 1, 1);
    control_layout->addWidget(headers_check_box, 1, 2);
    control_layout->addWidget(total_stale_check_box, 1, 3);

    control_layout->setAlignment(Qt::AlignBottom);
    setLayout(control_layout);
}

/* Private
 * Sets heap data to be visualized
 */
void
dhvis_snapshot_graph_t::set_heap_data(QVector<dhvis_snapshot_listing_t *> *vec)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    /* Memory should be taken care of by tool */
    if (vec != NULL) {
        snapshots = vec;
        /* Get avg time between snapshots */
        avg_time_between_snapshots = 0;
        for (quint64 i = 0; i < snapshots->count() - 1; i++) {
            avg_time_between_snapshots += qAbs(snapshots->at(i + 1)->num_time -
                                               snapshots->at(i)->num_time);
        }
        avg_time_between_snapshots /= snapshots->count();
        /* Avoid integer division truncating to 0.
         * Note, this should not happen normally, and is only a corner-case
         * for very small apps.
         */
        if (avg_time_between_snapshots < snapshots->count())
            avg_time_between_snapshots = 1;
    }
    max_height();
    max_width();

    QFontMetrics fm(font());
    text_height = fm.height();
    int buffer = 0;
    if (options != NULL && options->format_bytes)
        buffer = AXIS_SUFFIX_PADDING;
    text_width = fm.width(maximum_value) + buffer;

    left_bound = graph_outer_margin + text_width + 5;
    right_bound = left_bound + x_axis_width();
    update();
}

/* Protected
 * Paints an empty canvis or loads data
 */
void
dhvis_snapshot_graph_t::paintEvent(QPaintEvent *event)
{
    QWidget::paintEvent(event);

    QPainter painter(this);

    /* Fix origin location */
    painter.translate(left_bound,
                      height() - 3 * reset_graph_zoom_button->height());
    painter.scale(1, -1);

    if (snapshots == NULL || snapshots->isEmpty())
        draw_empty_graph(&painter);
    else {
        if (current_graph_modified) {
            /* Update max height */
            max_height();
            QPainter data_painter(&current_graph);
            draw_x_axis(&data_painter);
            draw_y_axis(&data_painter);
            draw_heap_data(&data_painter);
            data_painter.end();
            current_graph_modified = false;
        }
        painter.drawPicture(0, 0, current_graph);
        draw_selection(&painter);
        draw_view_cursor(&painter);
    }
}

/* Protected
 * Interactivity for graph
 *   -Selection zoom
 *   -Snapshot highlighting
 */
void
dhvis_snapshot_graph_t::mousePressEvent(QMouseEvent *event)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    qreal x_val = event->pos().x();
    /* Check bounds */
    if (x_val < left_bound) {
        x_val = left_bound;
    } else if (x_val > right_bound) {
        x_val = right_bound;
    }
    /* Handle event */
    if (event->button() == Qt::LeftButton) {
        if (highlighted_point.x() != x_val - left_bound) {
            highlighted_point = event->pos();
            highlighted_point.setX(x_val-left_bound);
            highlighted_snapshot();
        }
    }
    if (event->button() == Qt::RightButton) {
        first_point = event->pos();
        first_point.setX(x_val - left_bound);
    }
}

/* Protected
 * Interactivity for graph
 *   -Selection Zoom
 */
void
dhvis_snapshot_graph_t::mouseReleaseEvent(QMouseEvent *event)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    if (event->button() == Qt::RightButton) {
        /* Set vars to adjust the graph,
         * then adjust graph
         */
        qreal temp_start = view_start_mark;
        qreal temp_end = view_end_mark;

        qreal bound_diff = (right_bound - left_bound);
        qreal percent_diff = (temp_end - temp_start);

        view_start_mark = temp_start + (first_point.x() / (bound_diff))
                                       * percent_diff;
        view_end_mark = temp_start + (last_point.x() / (bound_diff))
                                     * percent_diff;

        /* Switch if user went right to left */
        if (first_point.x() > last_point.x()) {
            qreal temp = view_start_mark;
            view_start_mark = view_end_mark;
            view_end_mark = temp;
        }
        /* Floating point exception with diff < 2
         * from drawing elongated tallies in draw_x_axis
         * (i % (int)round(diff / 4))
         */
        if (qAbs(view_start_mark - view_end_mark) < 2.0) {
            view_end_mark = view_start_mark + 2.0;
        }
        /* Handle limit */
        if (view_start_mark >= 98) {
            view_end_mark = 100.0;
            view_start_mark = 98.0;
        }
        current_graph_modified = true;
        /* Reset selection info */
        first_point.setX(0);
        first_point.setY(0);
        last_point.setX(0);
        last_point.setY(0);

        highlighted_snapshot();
        update();
    }
}

/* Protected
 * Interactivity for graph
 *   -Selection zoom
 *   -Snapshot Highlighting
 */
void
dhvis_snapshot_graph_t::mouseMoveEvent(QMouseEvent *event)
{
    qreal x_val = event->pos().x();
    /* Check bounds */
    if (event->pos().x() < left_bound)
        x_val = left_bound;
    else if (event->pos().x() > right_bound)
        x_val = right_bound;
    /* For selection zoom */
    if (event->buttons() & Qt::RightButton) {
        last_point = QPoint(x_val-left_bound,height());
    } /* For snapshot highlighting */
    else if (event->buttons() & Qt::LeftButton) {
        if (highlighted_point.x() != x_val - left_bound) {
            highlighted_point = event->pos();
            highlighted_point.setX(x_val-left_bound);
            highlighted_snapshot();
        }
    }
    update();
}

/* Private
 * Calculates max height of y-axis
 */
void
dhvis_snapshot_graph_t::max_height(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    qreal height = 0;
    qreal total_percent = 0;
    qreal prev_time = 0;
    if (snapshots != NULL &&
        !snapshots->isEmpty()) {
        foreach (dhvis_snapshot_listing_t *snapshot, *snapshots) {
            total_percent += ((snapshot->num_time - prev_time) /
                             ((double)width_max)) * 100;
            prev_time = snapshot->num_time;
            if (total_percent < view_start_mark)
                continue;
            if (total_percent > view_end_mark)
                break;

            if (snapshot->tot_bytes_occupied > height)
                height = snapshot->tot_bytes_occupied;
        }
    }
    maximum_value = QString::number(height);
    height_max = height;
}

/* Private
 * Calculates max width of x-axis
 */
void
dhvis_snapshot_graph_t::max_width(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    qreal width = 0;
    if (snapshots != NULL &&
        !snapshots->isEmpty()) {
        width = snapshots->back()->num_time;
    }
    width_max = width;
}

/* Private
 * Returns width of y_axis
 */
qreal
dhvis_snapshot_graph_t::x_axis_width(void)
{
    return width() - (text_width + EXTRA_AXIS_PADDING) -
           2 * graph_outer_margin;
}

/* Private
 * Returns height of x_axis
 */
qreal
dhvis_snapshot_graph_t::y_axis_height(void)
{
    return height() - (text_height + EXTRA_AXIS_PADDING) -
           3 * reset_graph_zoom_button->height();
}

/* Private
 * Calculates x-coord for given data
 */
qreal
dhvis_snapshot_graph_t::data_point_x(const qreal &x)
{
    qreal max_x = x_axis_width();
    return x * (max_x) / (double)(view_end_mark - view_start_mark);
}

/* Private
 * Calculates y-coord for given data
 */
qreal
dhvis_snapshot_graph_t::data_point_y(const quint64 &y)
{
    qreal max_y = y_axis_height();
    return y * (max_y) / height_max;
}

/* Private
 * Helps draw_heap_data() graph data
 */
void
dhvis_snapshot_graph_t::draw_helper(QPainter *painter, qreal &total_percent,
                                    QVector<QPoint> &prev_points, int loc,
                                    quint64 *data, bool first)
{
    static const int COINCIDENT_POINT_ADJUSTMENT = 3;
    static const int POINT_MARKER_DIAMETER = 3;
    QPoint *prev_point = &(prev_points[loc]);
    qreal dp_x = data_point_x(total_percent - view_start_mark);
    qreal dp_y = data_point_y(*data);

    /* Place first point at correct loc on y-axis */
    if (first) {
        if (!options->square_graph) {
            qreal slope = (dp_y - prev_point->y()) /
                          (double)(dp_x - prev_point->x());
            prev_point->setY(slope * (0 - prev_point->x()) + prev_point->y());
        } else {
            prev_point->setY(dp_y);
        }
        prev_point->setX(0);
    }

    /* Square graph */
    if (options->square_graph == true) {
        QPoint mid_point(prev_point->x(), dp_y);
        fix_point_coincidence(prev_points, &mid_point, COINCIDENT_POINT_ADJUSTMENT,
                              false);
        painter->drawLine(*prev_point, mid_point);
        painter->drawRect(prev_point->x() - (POINT_MARKER_DIAMETER / 2.0),
                          mid_point.y() - (POINT_MARKER_DIAMETER / 2.0),
                          POINT_MARKER_DIAMETER, POINT_MARKER_DIAMETER);
        prev_point->setX(mid_point.x());
        prev_point->setY(mid_point.y());
    }

    QPoint this_point(dp_x, dp_y);
    fix_point_coincidence(prev_points, &this_point, COINCIDENT_POINT_ADJUSTMENT,
                          true);

    painter->drawLine(*prev_point, this_point);
    painter->drawRect(this_point.x() - (POINT_MARKER_DIAMETER / 2.0),
                      this_point.y() - (POINT_MARKER_DIAMETER / 2.0),
                      POINT_MARKER_DIAMETER, POINT_MARKER_DIAMETER);
    prev_point->setX(this_point.x());
    prev_point->setY(this_point.y());
}

/* Private
 * Graphs data
 */
#define DHVIS_MAKE_PREV_POINTS(_prev_points, _loc, _start_x_val, _num) \
    do { \
        (_prev_points).data()[_loc] = QPoint((_start_x_val), data_point_y(_num)); \
    } while(0)

#define DHVIS_DRAW_POINTS(_pen, _color, _painter, _total_percent, _prev_points, \
                          _loc, _num, _first) \
    do { \
        (_pen).setColor(_color); \
        (_painter)->setPen(_pen); \
        draw_helper(_painter, _total_percent, \
                    _prev_points, _loc, \
                    _num, _first); \
    } while (0)

void
dhvis_snapshot_graph_t::draw_heap_data(QPainter *painter)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    painter->save();

    qreal total_percent = 0;
    qreal prev_time = 0;
    /* Need a first for each line */
    QVector<QPoint> prev_points;
    for (int i = 0; i < 4; i++)
        prev_points.append(QPoint());
    /* XXX i#1319: use preference for color */
    QBrush data_point_brush(Qt::red);
    QPen data_point_pen(Qt::white, 3, Qt::SolidLine,
                        Qt::RoundCap, Qt::RoundJoin);

    if (options->anti_aliasing_enabled)
        painter->setRenderHint(QPainter::Antialiasing);
    painter->setBrush(data_point_brush);
    painter->setPen(data_point_pen);

    bool first = true;
    bool last = false;
    foreach (dhvis_snapshot_listing_t *snapshot, *snapshots) {
        total_percent += ((snapshot->num_time - prev_time) /
                         ((double)width_max)) * 100;
        prev_time = snapshot->num_time;
        if (total_percent < view_start_mark) {
            qreal start_x_val = data_point_x(total_percent -
                                             view_start_mark);
            DHVIS_MAKE_PREV_POINTS(prev_points, 0, start_x_val,
                                   snapshot->tot_bytes_asked_for);
            DHVIS_MAKE_PREV_POINTS(prev_points, 1, start_x_val,
                                   snapshot->tot_bytes_usable);
            DHVIS_MAKE_PREV_POINTS(prev_points, 2, start_x_val,
                                   snapshot->tot_bytes_occupied);
            DHVIS_MAKE_PREV_POINTS(prev_points, 3, start_x_val,
                                   snapshot->tot_bytes_stale);
            continue;
        }

        if (last) {
            break;
        } else if (total_percent > view_end_mark) {
            last = true;
        }

        if (staleness_line == true) {
            DHVIS_DRAW_POINTS(data_point_pen, STALENESS_LINE_COLOR, painter,
                              total_percent, prev_points, 3,
                              &snapshot->tot_bytes_stale, first);
        }
        if (mem_alloc_line == true) {
            DHVIS_DRAW_POINTS(data_point_pen, MEM_ALLOC_LINE_COLOR, painter,
                              total_percent, prev_points, 0,
                              &snapshot->tot_bytes_asked_for, first);
        }
        if (padding_line == true) {
            DHVIS_DRAW_POINTS(data_point_pen, PADDING_LINE_COLOR, painter,
                              total_percent, prev_points, 1,
                              &snapshot->tot_bytes_usable, first);
        }
        if (headers_line == true) {
            DHVIS_DRAW_POINTS(data_point_pen, HEADERS_LINE_COLOR, painter,
                              total_percent, prev_points, 2,
                              &snapshot->tot_bytes_occupied, first);
        }
        first = false;

    }
    painter->restore();
}
#undef DHVIS_DRAW_POINTS
#undef DHVIS_MAKE_PREV_POINTS

/* Private
 * Finds which snapshot to highlight according to slider position
 */
void
dhvis_snapshot_graph_t::highlighted_snapshot(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    if (snapshots == NULL)
        return;
    qreal total_loc_lesser = view_start_mark;
    qreal total_loc_greater = view_start_mark;
    qreal total_percent = 0;
    qreal prev_time = 0;
    qreal percent_diff = view_end_mark - view_start_mark;
    /* Cursor */
    highlight_percent = view_start_mark + ((double)highlighted_point.x() /
                                           (right_bound - left_bound)) *
                                          percent_diff;
    qreal highlight_loc = data_point_x(highlight_percent - view_start_mark);

    for (quint64 i = 0; i < snapshots->count(); i++) {
        dhvis_snapshot_listing_t *snapshot =  snapshots->at(i);
        /* Snapshot locs */
        total_percent += ((snapshot->num_time - prev_time) /
                         ((double)width_max)) * 100;
        prev_time = snapshot->num_time;
        total_loc_greater = data_point_x(total_percent - view_start_mark);
        /* If found */
        if (highlight_loc >= total_loc_lesser &&
            highlight_loc <= total_loc_greater) {
            if (current_snapshot_num == snapshot->snapshot_num)
                return;
            emit highlight_changed(snapshot->snapshot_num, i);
            current_snapshot_num = snapshot->snapshot_num;
            current_snapshot_index = i;
            return;
        }
        total_loc_lesser = total_loc_greater;
    }
    return;
}

/* Public slots
 * Resets the selection zoom on the graph
 */
void
dhvis_snapshot_graph_t::reset_graph_zoom(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    if (is_null())
        return;
    view_start_mark = 0;
    view_end_mark = 100;
    current_graph_modified = true;
    highlighted_snapshot();
    update();
}

/* Private
 * Draws the view cursor
 */
void
dhvis_snapshot_graph_t::draw_view_cursor(QPainter *painter)
{
    painter->save();
    /* Draw cursor line */
    painter->drawLine(QPoint(highlighted_point.x(), 0),
                      QPoint(highlighted_point.x(), height()));
    /* Draw snapshot num above the graph and slightly left of the cursor. */
    QRectF text_space(highlighted_point.x() - 3 - text_width,
                      -(y_axis_height() + (text_height + EXTRA_AXIS_PADDING)),
                      text_width,
                      text_height);
    DHVIS_DRAW_TEXT(painter,
                    painter->drawText(text_space,
                                      "#" + QString::number(current_snapshot_num),
                                      QTextOption(Qt::AlignRight)));
    painter->restore();
}

/* Public Slot
 * Updates data when settings are updated
 */
void
dhvis_snapshot_graph_t::update_settings(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    if (is_null())
        return;
    highlighted_snapshot();
    current_graph_modified = true;
    num_tabs = options->snap_vertical_ticks;
    set_heap_data(snapshots);
    /* Update stale spin box */
    if (options->snap_stale_unit_num) {
        stale_num_spin_box->setMaximum(snapshots->size() - 1);
        stale_num_spin_box->setValue(stale_num /
                                     avg_time_between_snapshots);
        stale_spin_box_label->setText(create_stale_suffix(stale_num));
        stale_num_spin_box->setDecimals(1);
        stale_num_spin_box->setSingleStep(.1);
    } else {
        stale_num_spin_box->setMaximum(snapshots->back()->num_time);
        stale_num_spin_box->setValue(stale_num);
        stale_spin_box_label->setText(create_stale_suffix(stale_num));
        stale_num_spin_box->setDecimals(0);
        stale_num_spin_box->setSingleStep(1);
    }
}

/* Public
 * Returns true if the graph's data is NULL
 */
bool
dhvis_snapshot_graph_t::is_null(void) {
    return snapshots == NULL || options == NULL;
}

/* Private Slot
 * Updates which lines to graph
 */
void
dhvis_snapshot_graph_t::change_lines(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    QCheckBox *emitter = (QCheckBox *)sender();
    bool state = false;
    if (emitter->text().contains(tr("staleness")))
        staleness_line = total_stale_check_box->isChecked() == true;
    else if (emitter->text().contains(tr("Heap headers")))
        headers_line = headers_check_box->isChecked() == true;
    else if (emitter->text().contains(tr("Padding")))
        padding_line = padding_check_box->isChecked() == true;
    else if (emitter->text().contains(tr("requested")))
        mem_alloc_line = mem_alloc_check_box->isChecked() == true;

    current_graph_modified = true;
    update();
}

/* Private Slot
 * Changes stale view between for and since
 */
void
dhvis_snapshot_graph_t::select_stale_type(bool checked)
{
    if (is_null())
        return;
    qreal new_val = 0;
    if (sender() == stale_since_radio && checked) {
        stale_type = false;
        if (options->snap_stale_unit_num)
            new_val = snapshots->size() - 1;
        else
            new_val = snapshots->back()->num_time;
    }
    else if (sender() == stale_for_radio && checked) {
        stale_type = true;
        new_val = 0;
    } else
        return;
    stale_num_spin_box->setValue(new_val);
    current_graph_modified = true;
    set_heap_data(snapshots);
}

/* Private Slot
 * Adjusts for/since number value
 */
void
dhvis_snapshot_graph_t::set_stale_num(const qreal &new_num)
{
    if (is_null())
        return;
    if (stale_num != new_num) {
        QString stale_suffix;
        /* Keep everything else on a time_unit base */
        if (options->snap_stale_unit_num) {
            stale_num = new_num * avg_time_between_snapshots;
            stale_suffix = " snapshots";
        }
        else {
            stale_num = new_num;
            stale_suffix = *time_unit;
        }
        /* Calculate fitting sums of each snaphot */
        dhvis_snapshot_listing_t *snapshot;
        foreach (dhvis_snapshot_listing_t *snapshot, *snapshots) {
            snapshot->tot_bytes_stale = 0;
            foreach (dhvis_callstack_listing_t *c,
                     snapshot->stale_callstacks) {
                quint64 snap_num = snapshot->snapshot_num;
                foreach (stale_pair_t sp, c->staleness_info[snap_num]) {
                    bool add = false;
                    qreal stale_comp = sp.STALE_LAST_ACCESS;
                    /* Stale for */
                    if (stale_type) {
                        stale_comp = snapshot->num_time - stale_comp;
                        if (stale_comp >= stale_num)
                            add = true;
                    } /* Stale since */
                    else {
                        if (stale_comp <= stale_num)
                            add = true;
                    }
                    if (add)
                        snapshot->tot_bytes_stale += sp.STALE_BYTES;
                }
            }
        }
        /* The valueChanged(int) signal is only emitted if the value is different
         * from the last one, so it is safe to call setValue(int) here.
         */
        stale_num_spin_box->setValue(new_num);
        /* Modify the suffix */
        stale_spin_box_label->setText(create_stale_suffix(stale_num));
        current_graph_modified = true;
        set_heap_data(snapshots);
    }
}

/* Private
 * Creates a suffix for the staleness spin box
 */
QString
dhvis_snapshot_graph_t::create_stale_suffix(const qreal &num) {
    if (options->snap_stale_unit_num) {
        return QString(tr(" snapshots (%1 ticks)").arg(num, 0, 'f', 0));
    } else {
        return QString(tr(" ticks (%1 snapshots)")
                       .arg(num / avg_time_between_snapshots, 0, 'f', 1));
    }
}

/* Private
 * Checks for a pair of coincident points and adjusts the given point
 * by the given offset if such a pair is found.
 */
bool
dhvis_snapshot_graph_t::fix_point_coincidence(QVector<QPoint> &points, QPoint *next,
                                              int offset, bool exact)
{
    /* Check for a pair of coincident points and if one is found adjust the new point
     * to avoid overlapping lines.
     */
    for (int i = 0; i < points.size() && exact; i++) {
        if (points[i].x() + offset > next->x() &&
            points[i].x() - offset < next->x() &&
            points[i].y() + offset > next->y() &&
            points[i].y() - offset < next->y()) {
            next->setY(next->y() + offset);
            return true;
        }
    }

    /* For a square graph we do not store the previous mid_point, so we
     * just check the stored y-values against the y-value of the mid_point.
     */
    if (options->square_graph && !exact) {
        for (int i = 0; i < points.size(); i++) {
            if (points[i].y() == next->y()) {
                next->setY(next->y() + offset);
                return true;
            }
        }
    }
    return false;
}
