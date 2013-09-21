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

/* dhvis_tool.h
 *
 * Defines the Dr. Heapstat visualizer
 */

#ifndef DHVIS_TOOL_H
#define DHVIS_TOOL_H

#include <QWidget>
#include <QUrl>
#include <QMap>

#include "dhvis_structures.h"

class QGraphicsView;
class QGraphicsScene;
class QDir;
class QFile;
class QTableWidget;
class QTextBrowser;
class QPushButton;
class QLineEdit;
class QGridLayout;
class QHBoxLayout;
class QLabel;
class QVBoxLayout;
class QCheckBox;
class QTabWidget;
class QTreeWidget;
class QTreeWidgetItem;
class QGroupBox;
class QStackedLayout;

class dhvis_tool_t : public QWidget
{
    Q_OBJECT

public:
    dhvis_tool_t(dhvis_options_t *options_);

    ~dhvis_tool_t(void);

private slots:
    void choose_dir(void);

    void dir_text_changed_slot(void);

private:
    void delete_data(void);

    void create_layout(void);

    bool dr_check_dir(QDir dir);

    bool dr_check_file(QFile& file);

    void read_log_data(void);

    void read_callstack_log(QFile &callstack_log);

    void read_snapshot_log(QFile &snapshot_log);

    /* GUI */
    QGridLayout *main_layout;

    QHBoxLayout *controls_layout;
    QLineEdit *log_dir_line_edit;
    bool log_dir_text_changed;
    QPushButton *load_results_button;

    QGridLayout *left_side;
    QLabel *graph_title;

    QTabWidget *dhrun_tab_widget;

    QGridLayout *right_side;
    QLabel *right_title;

    QTabWidget *frames_tab_area;

    QString log_dir_loc;

    /* Options */
    dhvis_options_t *options;

    /* Data */
    QVector<dhvis_callstack_listing_t *> callstacks;
    QVector<dhvis_snapshot_listing_t *> snapshots;
    QString time_unit;
    frame_map_t frames;
};

#endif
