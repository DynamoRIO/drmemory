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

/* dhvis_stale_graph.cpp
 *
 * Provides the staleness data graph
 */

#ifdef __CLASS__
#  undef __CLASS__
#endif
#define __CLASS__ "dhvis_stale_graph_t::"

#include <QWidget>
#include <QPainter>
#include <QPicture>
#include <QStyleOptionGraphicsItem>
#include <QDebug>
#include <QMouseEvent>
#include <QLabel>
#include <QHBoxLayout>
#include <QPushButton>
#include <QSpinBox>
#include <QRadioButton>
#include <QToolButton>

#include <cmath>
#include <algorithm>

#include "dhvis_structures.h"
#include "dhvis_tool.h"
#include "dhvis_graph.h"
#include "dhvis_stale_graph.h"

/* Public
 * Constructor
 */
dhvis_stale_graph_t::dhvis_stale_graph_t(QVector<dhvis_callstack_listing_t *> *c_vec,
                                         QVector<dhvis_snapshot_listing_t *> *s_vec,
                                         QString *time_unit_,
                                         int cur_snap_num,
                                         int cur_snap_index,
                                         dhvis_options_t *options_)
    :  callstacks(NULL), snapshots(NULL)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    setAttribute(Qt::WA_DeleteOnClose);
    graph_outer_margin = 10;
    time_unit = time_unit_;
    stale_num = -1;
    stale_type = true;
    zooming = false;
    current_snapshot_num = cur_snap_num;
    current_snapshot_index = cur_snap_index;
    options = options_;
    if (options != NULL) {
        num_tabs = options->stale_vertical_ticks;
        callstacks_on_this_page = options->num_stale_per_page;
    }
    view_start_mark = 0;
    view_end_mark = 0;
    display_page = 0;
    highlighted_point = QPoint(0, 0);
    set_heap_data(c_vec, s_vec);
    create_layout();
    set_stale_num(0);
}

/* Private
 * Creates the widgets layout
 */
void
dhvis_stale_graph_t::create_layout(void)
{
    /* Stale controls */
    QHBoxLayout *stale_controls_layout = new QHBoxLayout;
    info_label = new QLabel(tr(""), this);
    stale_num_spin_box = new QDoubleSpinBox(this);
    stale_spin_box_label = new QLabel("");
    if (time_unit != NULL && options != NULL) {
        if (options->stale_stale_unit_num)
            stale_num_spin_box->setSingleStep(.1);
        stale_spin_box_label->setText(create_stale_suffix(0));
    }
    if (snapshots != NULL) {
        quint64 max;
        if (options->stale_stale_unit_num)
            max = snapshots->count();
        else
            max = snapshots->back()->num_time;
        stale_num_spin_box->setRange(0, max);
    }
    /* The spin box doesn't always resize properly to its contents, so we set the
     * minimum size to something big enough to contain most data.
     */
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

    /* Controls */
    reset_zoom_button = new QPushButton(tr("Reset Graph Zoom"), this);
    connect(reset_zoom_button, SIGNAL(clicked()),
            this, SLOT(reset_graph_zoom()));
    prev_page_button = new QToolButton(this);
    prev_page_button->setArrowType(Qt::LeftArrow);
    connect(prev_page_button, SIGNAL(clicked()),
            this, SLOT(show_prev_page()));
    page_label = new QLabel(tr("Page 1"), this);
    next_page_button = new QToolButton(this);
    next_page_button->setArrowType(Qt::RightArrow);
    connect(next_page_button, SIGNAL(clicked()),
            this, SLOT(show_next_page()));

    stale_controls_layout->addWidget(info_label);
    stale_controls_layout->addStretch(1);
    stale_controls_layout->addWidget(stale_num_label);
    stale_controls_layout->addWidget(stale_for_radio);
    stale_controls_layout->addWidget(stale_since_radio);
    stale_controls_layout->addWidget(stale_num_spin_box);
    stale_controls_layout->addWidget(stale_spin_box_label);
    stale_controls_layout->addWidget(reset_zoom_button);
    stale_controls_layout->addWidget(prev_page_button);
    stale_controls_layout->addWidget(page_label);
    stale_controls_layout->addWidget(next_page_button);
    info_label->setAlignment(Qt::AlignCenter);
    stale_controls_layout->setAlignment(Qt::AlignBottom);

    setLayout(stale_controls_layout);
}

/* Private
 * Sets staleness data to be visualized
 */
void
dhvis_stale_graph_t::set_heap_data(QVector<dhvis_callstack_listing_t *> *c_vec,
                                   QVector<dhvis_snapshot_listing_t *> *s_vec)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    /* Memory should be taken care of by tool */
    if (c_vec != NULL &&
        s_vec != NULL) {
        callstacks = c_vec;
        snapshots = s_vec;
        view_end_mark = options->num_stale_per_page;
        /* Get avg time between snapshots */
        avg_time_between_snapshots = 0;
        for (quint64 i = 0; i < snapshots->count() - 1; i++) {
            avg_time_between_snapshots +=
                qAbs(snapshots->at(i + 1)->num_time - snapshots->at(i)->num_time);
        }
        avg_time_between_snapshots /= snapshots->count();
        calc_visible_callstacks();
    }
    max_height();
    max_width();

    QFontMetrics fm(font());
    text_height = fm.height();
    int buffer = 0;
    if (options != NULL && options->format_bytes)
        buffer = AXIS_SUFFIX_PADDING;
    text_width = fm.width(maximum_value) + buffer;

    left_bound = graph_outer_margin + text_width + EXTRA_AXIS_PADDING;
    right_bound = left_bound + x_axis_width();

    update();
}

/* Protected
 * Paints an empty canvis or loads data
 */
void
dhvis_stale_graph_t::paintEvent(QPaintEvent *event)
{
    QWidget::paintEvent(event);

    QPainter painter(this);

    /* Fix origin location */
    painter.translate(left_bound,
                      height() - 2 * reset_zoom_button->height());
    painter.scale(1, -1);

    if (callstacks == NULL || callstacks->isEmpty())
        draw_empty_graph(&painter);
    else {
        if (current_graph_modified) {
            calc_visible_callstacks();
            max_height();
            max_width();
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

/* Private
 * Calculates max height of y-axis
 */
void
dhvis_stale_graph_t::max_height(void)
{
    qreal height = 0;
    if (callstacks != NULL &&
        !callstacks->isEmpty() &&
        !visible_callstacks.isEmpty()) {
        qreal callstack_count = -1;
        /* visible_callstacks is already sorted by stale_bytes */
        dhvis_callstack_listing_t *callstack = visible_callstacks[0];
        QVector<stale_pair_t> *stale_bytes;
        stale_bytes = &callstack->staleness_info[current_snapshot_num];
        /* Stale bytes are also sorted */
        height = stale_bytes->at(0).STALE_BYTES;
        if (options->stale_sum_enabled) {
            qreal sum = callstack->staleness_sum_info[current_snapshot_num];
            if (sum > height)
                height = sum;
        }
    }
    if (num_tabs > height)
        height = num_tabs;
    maximum_value = QString::number(height);
    height_max = height;
}

/* Private
 * Calculates max width of x-axis
 */
void
dhvis_stale_graph_t::max_width(void)
{
    qreal width = 0;
    if (callstacks != NULL &&
        !callstacks->isEmpty()) {
        width = callstacks_on_this_page;
    }
    width_max = width;
}

/* Private
 * Returns width of y_axis
 */
qreal
dhvis_stale_graph_t::x_axis_width(void)
{
    return width() - (text_width + EXTRA_AXIS_PADDING) - 2 * graph_outer_margin;
}

/* Private
 * Returns height of x_axis
 */
qreal
dhvis_stale_graph_t::y_axis_height(void)
{
    return height() - (text_height + EXTRA_AXIS_PADDING) -
        2 * reset_zoom_button->height();
}

/* Private
 * Calculates x-coord for given data
 */
qreal
dhvis_stale_graph_t::data_point_x(const qreal &x)
{
    qreal max_x = x_axis_width();
    return x * (max_x) / width_max;
}

/* Private
 * Calculates y-coord for given data
 */
qreal
dhvis_stale_graph_t::data_point_y(const quint64 &y)
{
    qreal max_y = y_axis_height();
    return y * (max_y) / height_max;
}

/* Private
 * Helps draw_heap_data() graph data
 */
void
dhvis_stale_graph_t::draw_helper(QPainter *painter, qreal &next_loc,
                                 qreal &prev_loc,
                                 dhvis_callstack_listing_t *callstack)
{
    if (options->stale_sum_enabled) {
        qreal sum = callstack->staleness_sum_info[current_snapshot_num];
        painter->drawRect(QRectF(QPointF(prev_loc, data_point_y(sum)),
                                 QPointF(next_loc, 0)));
    } else {
        static const qreal SPACING = 2;
        QVector<stale_pair_t> *stale_bytes;
        stale_bytes = &(callstack->staleness_info[current_snapshot_num]);
        qreal num_stales = stale_bytes->count();
        qreal small_area = (next_loc - prev_loc) / num_stales;

        for (qreal i = 0; i < num_stales; i++) {
            qreal dp_x = prev_loc + (small_area * i) + (SPACING / 2);
            qreal dp_y = data_point_y((*stale_bytes)[i].STALE_BYTES);
            painter->drawRect(QRectF(QPointF(dp_x, dp_y),
                                     QPointF(dp_x + small_area - (SPACING / 2),
                                             0)));
        }
    }
}

/* Private
 * Graphs data
 */
void
dhvis_stale_graph_t::draw_heap_data(QPainter *painter)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    painter->save();

    qreal next_loc = 0;
    qreal prev_loc = 0;
    /* XXX: use preference for color */
    QBrush data_point_brush(Qt::red);
    QPen data_point_pen(Qt::white, 3, Qt::SolidLine,
                        Qt::RoundCap, Qt::RoundJoin);
    data_point_pen.setColor(QColor(255, 102, 0));
    if (options->anti_aliasing_enabled)
        painter->setRenderHint(QPainter::Antialiasing);
    painter->setBrush(data_point_brush);
    painter->setPen(data_point_pen);

    const qreal INDEX_DIFF = callstacks_on_this_page;
    foreach (dhvis_callstack_listing_t *callstack, visible_callstacks) {
        next_loc += (right_bound - left_bound) / INDEX_DIFF;
        draw_helper(painter, next_loc, prev_loc, callstack);
        prev_loc = next_loc;
    }
    painter->restore();

    qreal upper_limit = display_page *
                        options->num_stale_per_page;
    /* Enable navigation buttons? */
    if (upper_limit + visible_callstacks.count() <
        (*snapshots)[current_snapshot_index]->stale_callstacks.count())
        next_page_button->setEnabled(true);
    else
        next_page_button->setEnabled(false);
    if (display_page == 0)
        prev_page_button->setEnabled(false);
    else
        prev_page_button->setEnabled(true);
    /* Set page display */
    page_label->setText("Page " + QString::number(display_page));
}

/* Protected
 * Interactivity for graph
 *   -Selection Zoom
 */
void
dhvis_stale_graph_t::mousePressEvent(QMouseEvent *event)
{
    if (is_null())
        return;
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
        }
    }
    if (event->button() == Qt::RightButton) {
        first_point = event->pos();
        first_point.setX(x_val - left_bound);
        qreal callstack_num;
        callstack_num = calc_callstack_index(first_point.x());
        /* The rest of the text is appended in mouseMoveEvent */
        info_label->setText(tr("Zoom from mark %3 to ").arg(callstack_num));
        zooming = true;
    }
}

/* Protected
 * Interactivity for graph
 *   -Selection Zoom
 */
void
dhvis_stale_graph_t::mouseReleaseEvent(QMouseEvent *event)
{
    if (is_null())
        return;
    if (event->button() == Qt::RightButton) {
        /* Use temp to avoid changing start for end's calc and vice versa */
        qreal temp_start = calc_callstack_index(first_point.x());
        qreal temp_end = calc_callstack_index(last_point.x());
        view_start_mark = temp_start;
        view_end_mark = temp_end;
        /* Switch if user went right to left */
        if (view_start_mark > view_end_mark) {
            qreal temp = view_start_mark;
            view_start_mark = view_end_mark;
            view_end_mark = temp;
        }
        /* Floating point exception with diff < 2
         * From drawing elongated tallies in draw_x_axis
         * (i % (int)round(diff / 4))
         */
        if (qAbs(view_start_mark - view_end_mark) < 2.0) {
            view_end_mark = view_start_mark + 2.0;
        }
        /* Limit */
        if (view_start_mark >= width_max - 2) {
            view_end_mark = width_max;
            view_start_mark = width_max - 2;
        }

        /* Reset selection info */
        zooming = false;
        first_point.setX(0);
        first_point.setY(0);
        last_point.setX(0);
        last_point.setY(0);
        info_label->setText("");
        current_graph_modified = true;
        update();
    }
}

/* Protected
 * Interactivity for graph
 *   -Selection Zoom
 *   -Snapshot Highlighting
 */
void
dhvis_stale_graph_t::mouseMoveEvent(QMouseEvent *event)
{
    if (is_null())
        return;
    qreal x_val = event->pos().x();
    /* Check bounds */
    if (event->pos().x() < left_bound) {
        x_val = left_bound;
    } else if (event->pos().x() > right_bound) {
        x_val = right_bound - 1;
    }
    /* For selection zoom */
    if (event->buttons() & Qt::RightButton) {
        last_point = QPoint(x_val-left_bound,height());
        QString text = info_label->text();
        text.truncate(text.indexOf("to ") + 3);
        qreal callstack_num;
        callstack_num = calc_callstack_index(last_point.x());
        text.append(tr("%1").arg(callstack_num));
        info_label->setText(text);
    } /* For snapshot highlighting */
    else if (event->buttons() & Qt::LeftButton) {
        if (highlighted_point.x() != x_val - left_bound) {
            highlighted_point = event->pos();
            highlighted_point.setX(x_val-left_bound);
        }
    }
    update();
}

/* Public slots
 * Resets the selection zoom on the graph
 */
void
dhvis_stale_graph_t::reset_graph_zoom(void)
{
    if (is_null())
        return;
    view_start_mark = 0;
    view_end_mark = options->num_stale_per_page;
    current_graph_modified = true;
    callstacks_on_this_page = options->num_stale_per_page;
    update();
}

/* Private
 * Draws the view cursor
 */
void
dhvis_stale_graph_t::draw_view_cursor(QPainter *painter)
{
    painter->save();
    /* Draw cursor line */
    painter->drawLine(QPoint(highlighted_point.x(), 0),
                      QPoint(highlighted_point.x(), height()));

    if (zooming) {
        painter->restore();
        return;
    }
    /* Put data text at bottom
     * Get callstack index
     */
    const qreal INDEX_DIFF = callstacks_on_this_page;
    qreal callstack_index = 0;
    callstack_index = calc_callstack_index(highlighted_point.x());
    if (visible_callstacks.count() < 1) {
        painter->restore();
        return;
    }
    qreal callstack_num = visible_callstacks.at(callstack_index)->callstack_num;
    qreal prev_loc = highlighted_point.x() * INDEX_DIFF /
                     (double)(right_bound-left_bound);
    /* Get stale_bytes index */
    const qreal MAX_STALE_INDEX = callstacks->at(callstack_num - 1)->
        staleness_info[current_snapshot_num].count();

    qreal stale_bytes_index = 0;
    stale_bytes_index =
        (prev_loc - (callstack_index - view_start_mark)) * MAX_STALE_INDEX;
    stale_bytes_index = floor(stale_bytes_index);
    /* check bounds */
    if (MAX_STALE_INDEX < 1) {
        painter->restore();
        return;
    }
    if (stale_bytes_index >= MAX_STALE_INDEX)
        stale_bytes_index = MAX_STALE_INDEX - 1;
    if (stale_bytes_index < 0)
        stale_bytes_index = 0;
    QString message;
    qreal bytes = 0;
    qreal last_access = 0;
    if (options->stale_sum_enabled) {
        bytes =
            callstacks->at(callstack_num - 1)->staleness_sum_info[current_snapshot_num];
    } else {
        bytes = callstacks->at(callstack_num - 1)->
            staleness_info[current_snapshot_num][stale_bytes_index].STALE_BYTES;
    }
    last_access = snapshots->at(current_snapshot_index)->num_time -
        callstacks->at(callstack_num - 1)->
            staleness_info[current_snapshot_num][stale_bytes_index].STALE_LAST_ACCESS;
    message = tr("%1 bytes untouched for %2 %3 in callstack #%4")
        .arg(bytes)
        .arg(last_access)
        .arg(*time_unit)
        .arg(callstack_num);
    info_label->setText(message);
    painter->restore();
}

/* Public Slot
 * Updates data when settings are updated
 */
void
dhvis_stale_graph_t::update_settings(void)
{
    if (is_null())
        return;
    current_graph_modified = true;
    display_page = 0;
    num_tabs = options->stale_vertical_ticks;
    callstacks_on_this_page = options->num_stale_per_page;
    /* Set max based on snapshot unit or time unit */
    if (options->snap_stale_unit_num) {
        stale_num_spin_box->setRange(0, snapshots->count());
        set_stale_num(stale_num / avg_time_between_snapshots);
    } else {
        stale_num_spin_box->setRange(0, snapshots->at(current_snapshot_index)->num_time);
        set_stale_num(stale_num);
    }
    calc_visible_callstacks();
    set_heap_data(callstacks, snapshots);
}

/* Public
 * Returns true if the graph's data is NULL
 */
bool
dhvis_stale_graph_t::is_null(void) {
    return callstacks == NULL || snapshots == NULL || options == NULL;
}

/* Private
 * Calculates the callstack index in visible_callstacks
 * of the given x position in the painter
 */
qreal
dhvis_stale_graph_t::calc_callstack_index(const qreal &x_val) {
    if (is_null())
        return 0;
    /* Get callstack index */
    const qreal INDEX_DIFF = callstacks_on_this_page;
    qreal callstack_index = floor(x_val * INDEX_DIFF /
                                  (double)(right_bound-left_bound));
    /* Check spaces */
    if (callstack_index >= visible_callstacks.count())
        callstack_index = visible_callstacks.count() - 1;
    else if (callstack_index < 0)
        callstack_index = 0;
    return callstack_index;
}

/* Public
 * Calculates callstacks to be graphed
 */
void
dhvis_stale_graph_t::calc_visible_callstacks(void)
{
    visible_callstacks.clear();
    int counter = -1;
    const int MAX = options->num_stale_per_page;
    foreach (dhvis_callstack_listing_t *this_callstack,
             snapshots->at(current_snapshot_index)->stale_callstacks) {
        counter++;
        if (counter < (display_page * MAX) + view_start_mark)
            continue;
        else if (counter >= ((display_page + 1) * MAX) -
            (MAX - view_end_mark))
            break;
        /* Show the sum of the staleness in each callstack */
        if (options->stale_sum_enabled) {
            if (this_callstack->staleness_sum_info[current_snapshot_num] != 0) {
                visible_callstacks.append(this_callstack);
            }
            continue;
        }
        /* Show individual staleness in each callstack */
        QVector<stale_pair_t> lasts;
        lasts = this_callstack->staleness_info[current_snapshot_num];
        /* Even though each callstack can have multiple stale
         * instaces per snapshot, we only care if one instance matches
         */
        bool add;
        qreal stale_comp;
        foreach (stale_pair_t info, lasts) {
            add = false;
            stale_comp = info.STALE_LAST_ACCESS;
            /* Stale for */
            if (stale_type) {
                stale_comp =
                    snapshots->at(current_snapshot_index)->num_time - stale_comp;
                if (stale_comp >= stale_num)
                    add = true;
            } else {
                /* Stale since */
                if (stale_comp <= stale_num)
                    add = true;
            }
            if (add) {
                this_callstack->cur_snap_num = current_snapshot_num;
                visible_callstacks.append(this_callstack);
                break;
            }
        }
    }
    /* Adjust to avoid empty space */
    if (callstacks_on_this_page > visible_callstacks.count() ||
        callstacks_on_this_page < options->num_stale_per_page)
        callstacks_on_this_page = visible_callstacks.count();
}

/* Private Slot
 * Decrements page for graph
 */
void
dhvis_stale_graph_t::show_prev_page(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    if (is_null())
        return;
    display_page--;
    current_graph_modified = true;
    calc_visible_callstacks();
    set_heap_data(callstacks, snapshots);
}

/* Private Slot
 * Increments page for graph
 */
void
dhvis_stale_graph_t::show_next_page(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    if (is_null())
        return;
    display_page++;
    current_graph_modified = true;
    calc_visible_callstacks();
    set_heap_data(callstacks, snapshots);
}

/* Private Slot
 * Changes stale view between for and since
 */
void
dhvis_stale_graph_t::select_stale_type(bool checked)
{
    if (is_null())
        return;
    qreal new_val = 0;
    if (sender() == stale_since_radio && checked) {
        stale_type = false;
        if (options->stale_stale_unit_num)
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
    set_heap_data(callstacks, snapshots);
}

/* Private Slot
 * Adjusts for/since number value
 */
void
dhvis_stale_graph_t::set_stale_num(const qreal &new_num)
{
    if (is_null())
        return;
    if (stale_num != new_num) {
        QString stale_suffix;
        /* Keep the back end on a time_unit base for simplicity */
        if (options->stale_stale_unit_num) {
            stale_num = new_num * avg_time_between_snapshots;
            stale_suffix = " snapshots";
        }
        else {
            stale_num = new_num;
            stale_suffix = *time_unit;
        }
        /* Calculate fitting sums of each callstack */
        dhvis_snapshot_listing_t *snapshot = snapshots->at(current_snapshot_index);
        if (options->stale_sum_enabled) {
            quint64 snap_num = snapshot->snapshot_num;
            foreach (dhvis_callstack_listing_t *c, snapshot->stale_callstacks) {
                c->staleness_sum_info[snap_num] = 0;
                /* stale_sum_sorter() relies on this being set */
                c->cur_snap_num = snap_num;
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
                        c->staleness_sum_info[snap_num] += sp.STALE_BYTES;
                }
            }
            /* Re-sort */
            std::sort(snapshot->stale_callstacks.begin(),
                      snapshot->stale_callstacks.end(),
                      stale_sum_sorter);
        } else {
            /* Re-sort */
            std::sort(snapshot->stale_callstacks.begin(),
                      snapshot->stale_callstacks.end(),
                      stale_callstacks_sorter);
        }

        /* Modify the suffix */
        stale_spin_box_label->setText(create_stale_suffix(stale_num));
        current_graph_modified = true;
        set_heap_data(callstacks, snapshots);
    }
}

/* Private
 * Creates a suffix for the staleness spin box
 */
QString
dhvis_stale_graph_t::create_stale_suffix(const qreal &num) {
    if (options->stale_stale_unit_num) {
        return QString(tr(" snapshots (%1 ticks)").arg(num, 0, 'f', 0));
    } else {
        return QString(tr(" ticks (%1 snapshots)")
                       .arg(num / avg_time_between_snapshots, 0, 'f', 1));
    }
}