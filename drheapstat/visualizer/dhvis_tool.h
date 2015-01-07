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
#include <QMap>
#include <QUrl>
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

class dhvis_snapshot_graph_t;
class dhvis_stale_graph_t;

typedef QPair<QString /* path */ , QString /* file_name */ > frame_tree_pair_t;
typedef QMap<frame_tree_pair_t,
             QVector<QStringList /* func_name, line_num, address, occur_num */ > >
        frame_tree_inner_map_t;
typedef QMap<QString /* exe_name */ , frame_tree_inner_map_t > frame_tree_map_t;

class dhvis_tool_t : public QWidget
{
    Q_OBJECT

public:
    dhvis_tool_t(dhvis_options_t *options_);

    ~dhvis_tool_t(void);

    void update_settings(void);

    void set_log_dir_loc(const QString &log_dir);

private slots:
    void choose_dir(void);

    void dir_text_changed_slot(void);

    void highlight_changed(quint64 snapshot, quint64 index);

    void show_prev_page(void);

    void show_next_page(void);

    void refresh_frames_text_edit(int current_row, int current_column,
                                  int previous_row, int previous_column);

    void anchor_clicked(QUrl link);

    void load_frames_tree(int new_index);

    void frames_tree_double_clicked(QTreeWidgetItem *item, int column);

    void reset_callstacks_view(void);

    void exec_dr_heap(void);

    void choose_file(void);

    void slot_table_clicked(int column);

signals:
    void code_editor_requested(QFile &file, int line_num);

    void new_instance_requested(QWidget *tool, QString tool_name);

    void load_log_dir(dhvis_tool_t *tool, QString log_dir);

private:
    void delete_data(void);

    void create_layout(void);

    bool dr_check_dir(QDir dir);

    bool dr_check_file(QFile& file);

    void read_log_data(void);

    void read_callstack_log(QFile &callstack_log);

    void read_snapshot_log(QFile &snapshot_log);

    void read_staleness_log(QFile &staleness_log);

    void sort_log_data(void);

    void sort_stale_data(void);

    void draw_snapshot_graph(void);

    void fill_callstacks_table(void);

    void load_frames_text_edit(int current_row);

    dhvis_frame_data_t *extract_frame_data(const QString &frame);

    void load_frames_tree(void);

    void fill_frames_tree(frame_tree_map_t &frame_data_map);

    void draw_staleness_graph(void);

    void insert_total_row(void);

    /* GUI */
    QGridLayout *main_layout;

    QHBoxLayout *controls_layout;
    QLineEdit *log_dir_line_edit;
    bool log_dir_text_changed;
    QPushButton *load_results_button;

    QGridLayout *left_side;
    QLabel *graph_title;
    dhvis_snapshot_graph_t *snapshot_graph;

    QTabWidget *dhrun_tab_widget;
    QWidget *dhrun_widget;
    QGridLayout *dhrun_layout;
    QLabel *dhrun_loc_label;
    QLineEdit *dhrun_loc_line_edit;
    QPushButton *dhrun_loc_button;
    bool dhrun_loc_text_changed;
    QString dh_loc;

    QLabel *dhrun_target_label;
    QLineEdit *dhrun_target_line_edit;
    QPushButton *dhrun_target_button;
    bool dhrun_target_text_changed;
    QString dh_target;

    QLabel *dh_args_label;
    QLineEdit *dh_args_line_edit;
    QLabel *target_args_label;
    QLineEdit *target_args_line_edit;
    QPushButton *dhrun_exec_push_button;

    QTextBrowser *dhrun_stdout_output_browser;
    QTextBrowser *dhrun_stderr_output_browser;

    QGridLayout *right_side;
    QLabel *right_title;

    QTableWidget *callstacks_table;
    Qt::SortOrder sort_order;
    int sorted_column;

    QHBoxLayout *callstacks_page_buttons;
    QPushButton *prev_page_button;
    QLabel *page_display_label;
    QPushButton *next_page_button;
    QPushButton *reset_visible_button;

    QTabWidget *frames_tab_area;
    QTextBrowser *frames_text_edit;

    QWidget *frames_tree_tab_widget;
    QVBoxLayout *frames_tree_layout;
    QStackedLayout *tree_stack;
    static const int TREE_TAB_INDEX = 1;
    QTreeWidget *frames_tree_widget;
    /* frames_tree_widget column indices */
    static const int NUM_COLUMNS = 5;
    static const int EXEC_INDEX = 0;
    static const int FILE_INDEX = 0;
    static const int FUNC_INDEX = 0;
    static const int LINE_NUM_INDEX = 1;
    static const int ADDRESS_INDEX = 2;
    static const int OCCUR_INDEX = 3;
    static const int PATH_INDEX = 4;

    QHBoxLayout *frames_tree_controls_layout;
    QPushButton *expand_all_button;
    QPushButton *collapse_all_button;

    dhvis_stale_graph_t *staleness_graph;

    QString log_dir_loc;

    /* Options */
    dhvis_options_t *options;

    /* Data */
    QVector<dhvis_callstack_listing_t *> visible_assoc_callstacks;
    QVector<dhvis_callstack_listing_t *> callstacks;
    QVector<dhvis_snapshot_listing_t *> snapshots;
    QMap<int, QTreeWidget *> frame_trees;
    QMap<quint64, dhvis_stale_graph_t *> stale_graphs;
    frame_map_t frames;
    QString time_unit;
    int current_snapshot_num;
    int current_snapshot_index;
    int callstacks_display_page;
    bool show_occur;
    /* For a given snapshot, file, or frame */
    quint64 total_requested_usage;
    quint64 total_pad_usage;
    quint64 total_header_usage;
};

#endif
