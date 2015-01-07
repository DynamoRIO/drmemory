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

/* dhvis_tool.cpp
 *
 * Provides the Dr. Heapstat visualizer
 */

#define __CLASS__ "dhvis_tool_t::"

#include <QApplication>
#include <QWidget>
#include <QGraphicsView>
#include <QGraphicsScene>
#include <QGridLayout>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QTextBrowser>
#include <QLabel>
#include <QTableWidget>
#include <QFileDialog>
#include <QLineEdit>
#include <QMessageBox>
#include <QHeaderView>
#include <QDebug>
#include <QCheckBox>
#include <QTabWidget>
#include <QTreeWidget>
#include <QMap>
#include <QGroupBox>
#include <QProcess>
#include <QStackedLayout>
#include <QUrl>

#include <algorithm>
#include <cmath>

#include "dhvis_snapshot_graph.h"
#include "dhvis_stale_graph.h"
#include "dhvis_tool.h"

/* Public
 * Constructor
 */
dhvis_tool_t::dhvis_tool_t(dhvis_options_t *options_)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    log_dir_text_changed = false;
    dhrun_loc_text_changed = false;
    dhrun_target_text_changed = false;
    log_dir_loc =  "";
    options = options_;
    current_snapshot_num = -1;
    current_snapshot_index= -1;
    show_occur = false;
    sorted_column = 0;
    sort_order = Qt::DescendingOrder;
    create_layout();
}

/* Public
 * Destructor
 */
dhvis_tool_t::~dhvis_tool_t(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    delete_data();
}

/* Private
 * Deletes all data
 */
void
dhvis_tool_t::delete_data(void)
{
    /* Manage memory */
    while (callstacks.count() > 0) {
        dhvis_callstack_listing_t *tmp = callstacks.back();
        callstacks.pop_back();
        delete tmp;
    }
    callstacks.clear();

    while (snapshots.count() > 0) {
        dhvis_snapshot_listing_t *tmp = snapshots.back();
        snapshots.pop_back();
        delete tmp;
    }
    snapshots.clear();

    delete snapshot_graph;

    frame_map_t::iterator frame_itr;
    frame_itr = frames.begin();
    while (frame_itr != frames.end()) {
        delete *frame_itr;
        frame_itr = frames.erase(frame_itr);
    }
    frames.clear();

    QMap<int, QTreeWidget *>::iterator tree_itr;
    tree_itr = frame_trees.begin();
    while (tree_itr != frame_trees.end()) {
        delete *tree_itr;
        tree_itr = frame_trees.erase(tree_itr);
    }

    frame_trees.clear();

    QMap<quint64, dhvis_stale_graph_t *>::iterator stale_itr;
    stale_itr = stale_graphs.begin();
    while (stale_itr != stale_graphs.end()) {
        delete *stale_itr;
        stale_itr = stale_graphs.erase(stale_itr);
    }

    stale_graphs.clear();

    /* Reset environment */
    callstacks_display_page = 0;
    current_snapshot_num = -1;
    current_snapshot_index= -1;

    snapshot_graph = NULL;
    frames_tree_widget = NULL;
    staleness_graph = NULL;
}

/* Private
 * Creates and connects the GUI
 */
void
dhvis_tool_t::create_layout(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    main_layout = new QGridLayout;

    /* Controls (top) */
    controls_layout = new QHBoxLayout;
    /* Logdir text box */
    log_dir_line_edit = new QLineEdit(this);
    connect(log_dir_line_edit, SIGNAL(textEdited(const QString &)),
            this, SLOT(dir_text_changed_slot()));
    controls_layout->addWidget(log_dir_line_edit);
    /* Load button */
    load_results_button = new QPushButton(tr("Load Results"), this);
    connect(load_results_button, SIGNAL(clicked()),
            this, SLOT(choose_dir()));
    controls_layout->addWidget(load_results_button);
    controls_layout->setAlignment(load_results_button, Qt::AlignLeft);

    main_layout->addLayout(controls_layout, 0, 0, 1, 2);

    /* Left side */
    left_side = new QGridLayout;
    /* Graph */
    graph_title = new QLabel(QString(tr("Memory consumption over "
                                        "full process lifetime")),
                             this);
    snapshot_graph = new dhvis_snapshot_graph_t(NULL, NULL, NULL);
    QSpacerItem *space_holder = new QSpacerItem(graph_title->width(),
                                                snapshot_graph->height());
    left_side->addWidget(graph_title, 0, 0);
    left_side->addWidget(snapshot_graph, 1, 0);
    left_side->setRowStretch(1, 4);

    /* Run Dr. Heapstat */
    dhrun_tab_widget = new QTabWidget(this);
    dhrun_widget = new QWidget(this);
    dhrun_layout = new QGridLayout;
    dhrun_loc_label = new QLabel(tr("Dr. Heapstat location"), this);
    dhrun_loc_line_edit = new QLineEdit(this);
    connect(dhrun_loc_line_edit, SIGNAL(textEdited(const QString &)),
            this, SLOT(dir_text_changed_slot()));
    dhrun_loc_button = new QPushButton(tr("Find"), this);
    connect(dhrun_loc_button, SIGNAL(clicked()),
            this, SLOT(choose_file()));

    dhrun_target_label = new QLabel(tr("Target location"), this);
    dhrun_target_line_edit = new QLineEdit(this);
    connect(dhrun_target_line_edit, SIGNAL(textEdited(const QString &)),
            this, SLOT(dir_text_changed_slot()));
    dhrun_target_button = new QPushButton(tr("Find"), this);
    connect(dhrun_target_button, SIGNAL(clicked()),
            this, SLOT(choose_file()));

    dh_args_label = new QLabel(tr("Dr. Heapstat options"), this);
    dh_args_line_edit = new QLineEdit(this);
    target_args_label = new QLabel(tr("Target options"));
    target_args_line_edit = new QLineEdit(this);
    dhrun_exec_push_button = new QPushButton(tr("Run"), this);
    connect(dhrun_exec_push_button, SIGNAL(clicked()),
            this, SLOT(exec_dr_heap()));

    int row = 0;
    dhrun_layout->addWidget(dhrun_loc_label, row++, 0);
    dhrun_layout->addWidget(dhrun_loc_line_edit, row, 0, 1, 2);
    dhrun_layout->addWidget(dhrun_loc_button, row++, 2);
    dhrun_layout->addWidget(dhrun_target_label, row++, 0);
    dhrun_layout->addWidget(dhrun_target_line_edit, row, 0, 1, 2);
    dhrun_layout->addWidget(dhrun_target_button, row++, 2);
    dhrun_layout->addWidget(dh_args_label, row, 0);
    dhrun_layout->addWidget(target_args_label, row++, 1);
    dhrun_layout->addWidget(dh_args_line_edit, row, 0);
    dhrun_layout->addWidget(target_args_line_edit, row, 1);
    dhrun_layout->addWidget(dhrun_exec_push_button, row++, 2);
    dhrun_widget->setLayout(dhrun_layout);

    /* Dr. Heapstat Output */
    dhrun_stdout_output_browser = new QTextBrowser(this);
    dhrun_stderr_output_browser = new QTextBrowser(this);

    dhrun_tab_widget->addTab(dhrun_widget, tr("Run Dr. Heapstat"));
    dhrun_tab_widget->addTab(dhrun_stdout_output_browser, tr("Output"));
    dhrun_tab_widget->addTab(dhrun_stderr_output_browser, tr("Errors"));

    left_side->addWidget(dhrun_tab_widget, 4, 0, 1, 2);

    /* Right side */
    right_side = new QGridLayout;
    right_title = new QLabel(QString(tr("Memory consumption at "
                                        "a given point: Individual "
                                        "callstacks")),
                             this);

    /* Set up callstack table*/
    callstacks_table = new QTableWidget(this);
    connect(callstacks_table, SIGNAL(currentCellChanged(int, int, int, int)),
            this, SLOT(refresh_frames_text_edit(int, int, int, int)));
    connect(callstacks_table->horizontalHeader(), SIGNAL(sectionClicked(int)),
            this, SLOT(slot_table_clicked(int)));

    /* Mid-layout buttons */
    callstacks_page_buttons = new QHBoxLayout;
    prev_page_button = new QPushButton(tr("Prev Page"), this);
    prev_page_button->setEnabled(false);
    page_display_label = new QLabel("", this);
    connect(prev_page_button, SIGNAL(clicked()),
            this, SLOT(show_prev_page()));
    next_page_button = new QPushButton(tr("Next Page"), this);
    next_page_button->setEnabled(false);
    connect(next_page_button, SIGNAL(clicked()),
            this, SLOT(show_next_page()));
    reset_visible_button = new QPushButton(tr("Reset visible"), this);
    connect(reset_visible_button, SIGNAL(clicked()),
            this, SLOT(reset_callstacks_view()));

    callstacks_page_buttons->addWidget(prev_page_button);
    callstacks_page_buttons->addWidget(page_display_label);
    callstacks_page_buttons->addStretch(1);
    callstacks_page_buttons->addWidget(reset_visible_button);
    callstacks_page_buttons->addWidget(next_page_button);

    right_side->addWidget(right_title, 0, 0);
    right_side->addWidget(callstacks_table, 1, 0);
    right_side->addLayout(callstacks_page_buttons, 2, 0);

    /* Frames tab area */
    frames_tab_area = new QTabWidget(this);
    connect(frames_tab_area, SIGNAL(currentChanged(int)),
            this, SLOT(load_frames_tree(int)));

    /* Frames text box */
    right_side->addLayout(callstacks_page_buttons,2,0);
    frames_text_edit = new QTextBrowser(this);
    frames_text_edit->setOpenLinks(false);
    frames_text_edit->setLineWrapMode(QTextEdit::NoWrap);
    connect(frames_text_edit, SIGNAL(anchorClicked(QUrl)),
            this, SLOT(anchor_clicked(QUrl)));

    /* Frames tree widget */
    frames_tree_tab_widget = new QWidget;
    frames_tree_layout = new QVBoxLayout(frames_tree_tab_widget);
    tree_stack = new QStackedLayout;
    frames_tree_widget = new QTreeWidget;
    connect(frames_tree_widget, SIGNAL(itemDoubleClicked(QTreeWidgetItem *, int)),
            this, SLOT(frames_tree_double_clicked(QTreeWidgetItem *, int)));
    frames_tree_widget->setHeaderHidden(true);

    /* Tree control buttons */
    frames_tree_controls_layout = new QHBoxLayout;
    expand_all_button = new QPushButton(tr("Expand all"), this);
    connect(expand_all_button, SIGNAL(clicked()),
            frames_tree_widget, SLOT(expandAll()));
    collapse_all_button = new QPushButton(tr("Collapse all"), this);
    connect(collapse_all_button, SIGNAL(clicked()),
            frames_tree_widget, SLOT(collapseAll()));
    frames_tree_controls_layout->addStretch(1);
    frames_tree_controls_layout->addWidget(expand_all_button);
    frames_tree_controls_layout->addWidget(collapse_all_button);
    frames_tree_layout->addLayout(tree_stack);
    frames_tree_layout->addLayout(frames_tree_controls_layout);

    /* Staleness graph */
    staleness_graph = new dhvis_stale_graph_t(NULL, NULL,
                                              NULL, -1,
                                              -1, NULL);

    frames_tab_area->addTab(frames_text_edit, tr("List View"));
    frames_tab_area->addTab(frames_tree_tab_widget, tr("Tree View"));
    frames_tab_area->addTab(staleness_graph, tr("Staleness Graph"));

    right_side->addWidget(frames_tab_area, 3, 0);
    right_side->setRowStretch(1, 3);
    right_side->setRowStretch(3, 5);

    main_layout->addLayout(left_side, 1, 0);
    main_layout->setColumnStretch(0, 3);
    main_layout->addLayout(right_side, 1, 1);
    main_layout->setColumnStretch(1, 5);
    setLayout(main_layout);
}

/* Private Slot
 * Chooses dirs for QLineEdit QPushButton pairs
 */
void
dhvis_tool_t::choose_dir(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    bool *dir_text_changed = NULL;
    QString *dir_loc = NULL;
    QLineEdit *line_edit = NULL;
    /* Determine which button sent signal */
    if (sender() == load_results_button) {
        dir_text_changed = &log_dir_text_changed;
        dir_loc = &log_dir_loc;
        line_edit = log_dir_line_edit;
    } else {
        return;
    }
    if (*dir_text_changed) /* enter dir_loc */ {
        QString test_dir = line_edit->text();
        if (dr_check_dir(QDir(test_dir))) {
            *dir_loc = test_dir;
        } else {
            /* Reset dir_text_changed */
            *dir_text_changed = false;
            return;
        }
    } else /* open dir_loc */ {
        QString test_dir;
        do {
        test_dir = QFileDialog::getExistingDirectory(this,
                                                     tr("Open Directory"),
                                                     options->def_load_dir,
                                                     0);
            if (test_dir.isEmpty())
                return;
        } while (!dr_check_dir(QDir(*dir_loc)));
        *dir_loc = test_dir;
        line_edit->setText(*dir_loc);
    }

    /* Reset dir_text_changed */
    *dir_text_changed = false;

    /* Perform specific actions */
    if (sender() == load_results_button) {
        read_log_data();
    }
}

/* Private Slot
 * Changes text_changed status of log_dir
 */
void
dhvis_tool_t::dir_text_changed_slot(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    /* Determine which button sent signal */
    if (sender() == log_dir_line_edit)
        log_dir_text_changed = true;
}

/* Private
 * Checks validity of directories
 */
bool
dhvis_tool_t::dr_check_dir(QDir dir)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    QString error_msg = "\'" + dir.canonicalPath() + "\'<br>";
    bool retVal = true;

    if (!dir.exists() ||
        !dir.isReadable()) {
        qDebug() << "WARNING: Failed to open directory: "
                 << dir.canonicalPath();
        error_msg += "is an invalid directory<br>";
        retVal = false;
    }
    if (!retVal) {
        QMessageBox msg_box(QMessageBox::Warning,
                            tr("Invalid Directory"),
                            error_msg, 0, this);
        msg_box.exec();
    }
    return retVal;
}

/* Private
 * Checks validity of files
 */
bool
dhvis_tool_t::dr_check_file(QFile &file)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    QString error_msg = "\'" + file.fileName() + "\'<br>";
    bool ret_val = true;

    if (!file.exists()) {
        qDebug() << "WARNING: Failed to open file: "
                 << file.fileName();
        error_msg += "File does not exist<br>";
        ret_val = false;
    }
    if (!ret_val) {
        QMessageBox msg_box(QMessageBox::Warning,
                            tr("Invalid File"),
                            error_msg, 0, this);
        msg_box.exec();
    }
    return ret_val;
}

/* Private
 * Reads the log files
 * XXX i#1319: optimize file reads
 */
void
dhvis_tool_t::read_log_data(void)
{
    /* Check log_dir */
    QDir dr_log_dir(log_dir_loc);
    if (!dr_check_dir(dr_log_dir))
        return;
    /* Find log files */
    QFile callstack_log(dr_log_dir.absoluteFilePath("callstack.log"));
    QFile snapshot_log(dr_log_dir.absoluteFilePath("snapshot.log"));
    QFile staleness_log(dr_log_dir.absoluteFilePath("staleness.log"));
    if (!dr_check_file(callstack_log) ||
        !dr_check_file(snapshot_log) ||
        !dr_check_file(staleness_log))
        return;

    /* Set cursor to hourglass */
    qApp->setOverrideCursor(Qt::WaitCursor);

    /* Delete current memory */
    delete_data();

    read_callstack_log(callstack_log);
    read_snapshot_log(snapshot_log);
    read_staleness_log(staleness_log);

    /* Sort all of the information properly */
    sort_log_data();

    /* Setup views and current_info */
    draw_snapshot_graph();

    qApp->restoreOverrideCursor();
}

/* Private
 * Processes callstack.log
 */
void
dhvis_tool_t::read_callstack_log(QFile &callstack_log)
{
    if (callstack_log.open(QFile::ReadOnly)) {
        quint64 file_entry = callstack_log.pos();
        QTextStream in_log(&callstack_log);
        QString line;
        /* Count number of callstacks */
        quint64 tot_callstacks = 0;
        do {
            line = in_log.readLine();
            if (line.contains("CALLSTACK"))
                tot_callstacks++;
        } while (!line.isNull());
        /* Allocate space now */
        callstacks.resize(tot_callstacks);
        for (quint64 i = 0; i < tot_callstacks; i++) {
            callstacks[i] = new dhvis_callstack_listing_t;
        }
        /* Reset log */
        if (!callstack_log.seek(file_entry)) {
            delete_data();
            return;
        }
        /* We assume that the snapshots are listed in increasing order
         * by their snapshot number.
         */
        quint64 counter = 0;
        line = "";
        do /* Read file */ {
            if (!line.contains("CALLSTACK")) {
                do /* Skip past any extra info */ {
                    line = in_log.readLine();
                } while (!line.contains("CALLSTACK") &&
                         !line.contains("LOG END") &&
                         !line.isNull());
            }
            /* EOF check */
            if (line.contains("LOG END") ||
                line.isNull()) {
                break;
            }
            dhvis_callstack_listing_t *this_callstack;
            this_callstack = callstacks.at(counter);
            /* The callstacks begin counting at 1, however they are stored in
             * an array which starts at index 0.
             */
            this_callstack->callstack_num = counter + 1;
#ifdef QT_DEBUG
            QRegExp reg_exp("^CALLSTACK\\s+(\\d+)",
                            Qt::CaseInsensitive);
            reg_exp.indexIn(line);
            if (this_callstack->callstack_num != reg_exp.cap(1).toULongLong()) {
                qCritical() << "CRITICAL: counter != callstack_num\n"
                            << callstack_log.fileName()
                            << "\nis not in the expected order.";
            }
#endif
            /* Read in frame data */
            while (!line.isNull()) {
                line = in_log.readLine();
                if (line.contains("<not in a module>"))
                    continue;
                if (line.contains("error end") ||
                    line.isNull() ||
                    line.contains("CALLSTACK")) {
                    break;
                }
                /* Example:
                 * '# num exe_name!func_name [path/to/file_name:line_num] (address)'
                 */
                if (line.contains(QRegExp("^#\\s*[0-9]+"))) {
                    /* Get address */
                    QString address = "";
                    QRegExp reg_exp("0x(\\w+) <.+0x\\w+>");
                    if (reg_exp.indexIn(line) < 0)
                        qDebug() << "Malformed frame: " << line;
                    else
                        address = reg_exp.cap(1);

                    bool ok;
                    quint64 int_addr = address.toULongLong(&ok, 16);
                    if (!ok) {
                        qDebug() << "Malformed address: " << address;
                        continue;
                    }
                    dhvis_frame_data_t *frame_data;
                    frame_map_t::iterator itr = frames.find(int_addr);
                    if (itr == frames.end()) {
                        frame_data = extract_frame_data(line);
                        frames[int_addr] = frame_data;
                    }
                    this_callstack->frame_data.append(frames[int_addr]);
                } else
                    qDebug() << "Malformed frame: " << line;
            }
            counter++;
        } while (!line.isNull() &&
                 !line.contains("LOG END"));
        callstack_log.close();
    }
    qDebug() << "INFO: callstack.log read";
}

/* Private
 * Processes snapshot.log
 */
void
dhvis_tool_t::read_snapshot_log(QFile &snapshot_log)
{
    /* Clear current snapshot data */
    snapshots.clear();
    if (snapshot_log.open(QFile::ReadOnly)) {
        dhvis_snapshot_listing_t *peak_snapshot = NULL;
        QTextStream in_log(&snapshot_log);
        QString line = in_log.readLine();
        /* We assume that the snapshots are listed in increasing order
         * by their snapshot number.
         */
        quint64 counter = 0;
        do /* Read file */ {
            /* Skip past any extra info */
            while (!line.contains("SNAPSHOT #") &&
                   !line.contains("LOG END")) {
                line = in_log.readLine();
            }
            /* Sanity check */
            if (line.contains("LOG END"))
                break;
            dhvis_snapshot_listing_t *this_snapshot;
            this_snapshot = new dhvis_snapshot_listing_t;
            this_snapshot->snapshot_num = counter;
            /* Get time and unit */
            QRegExp reg_exp("^SNAPSHOT\\s#\\s+(\\d+)\\s@\\s+(\\d+)\\s(\\w+).+$",
                            Qt::CaseInsensitive);
            reg_exp.indexIn(line);
            if (reg_exp.captureCount() != 3) {
                qDebug() << "Malformed snapshot: " << line;
                break;
            }
#ifdef QT_DEBUG
            if (counter != reg_exp.cap(1).toULongLong()) {
                qCritical() << "CRITICAL: counter != snapshot_num\n"
                            << snapshot_log.fileName()
                            << "\nis not in the expected order.";
            }
#endif
            this_snapshot->num_time = reg_exp.cap(2).toULongLong();
            time_unit = reg_exp.cap(3);
            do /* Skip past any extra info */ {
                line = in_log.readLine();
            } while (!line.contains("total: "));
            /* Get snapshot data
             * Example: 'total: 40,1615,3399,3559'
             */
            reg_exp.setPattern("^total:\\s+(\\d+),(\\d+),(\\d+),(\\d+)$");
            reg_exp.indexIn(line);
            if (reg_exp.captureCount() != 4) {
                qDebug() << "Malformed snapshot: " << line;
                break;
            }
            this_snapshot->tot_mallocs = reg_exp.cap(1).toULongLong();
            this_snapshot->tot_bytes_asked_for = reg_exp.cap(2).toULongLong();
            this_snapshot->tot_bytes_usable = reg_exp.cap(3).toULongLong();
            this_snapshot->tot_bytes_occupied = reg_exp.cap(4).toULongLong();
            this_snapshot->is_peak = false;
            if (peak_snapshot == NULL ||
                this_snapshot->tot_bytes_occupied > peak_snapshot->tot_bytes_occupied)
                peak_snapshot = this_snapshot;
            /* Add new data to callstacks */
            for (unsigned int i = 0; i < this_snapshot->tot_mallocs;) {
                line = in_log.readLine();
                /* tot_mallocs counts reallocs, while instances do not;
                 * so we can't assume that they will sum properly.
                 */
                if (line.contains("SNAPSHOT #") ||
                    line.contains("LOG END")) {
                    break;
                }
                /* Example: '27,1,124,124,4' */
                reg_exp.setPattern("^(\\d+),(\\d+),(\\d+),(\\d+),(\\d+)$");
                reg_exp.indexIn(line);
                if (reg_exp.captureCount() != 5) {
                    qDebug() << "Malformed snapshot: " << line;
                    break;
                }
                /* Get referenced callstack and subtract 1 since the
                 * callstack # starts at 1 in the logfile; while the array
                 * index starts at 0.
                 */
                quint64 callstack_index = reg_exp.cap(1).toULongLong() - 1;
                dhvis_callstack_listing_t *this_callstack;
                this_callstack = callstacks.at(callstack_index);
                this_callstack->instances = reg_exp.cap(2).toULongLong();
                this_callstack->bytes_asked_for = reg_exp.cap(3).toULongLong();
                this_callstack->extra_usable = reg_exp.cap(4).toULongLong()
                                             + this_callstack->bytes_asked_for;
                this_callstack->extra_occupied = reg_exp.cap(5).toULongLong()
                                               + this_callstack->extra_usable;
                /* Ensure proper counting */
                i += this_callstack->instances;
                /* Callstacks listed high to low in log,
                 * prepending reverses the order
                 */
                this_snapshot->assoc_callstacks.prepend(this_callstack);
            }
            snapshots.append(this_snapshot);
            counter++;
        } while (!line.isNull() &&
                 !line.contains("LOG END"));
        snapshot_log.close();
        peak_snapshot->is_peak = true;
    }
    qDebug() << "INFO: snapshot.log read";
}

/* Private
 * Processes snapshot.log
 */
void
dhvis_tool_t::read_staleness_log(QFile &staleness_log)
{
    if (staleness_log.open(QFile::ReadOnly)) {
        QTextStream in_log(&staleness_log);
        QString line = "";
        quint64 counter = 0;
        do /* Read file */ {
            while (!line.isNull() &&
                   !line.contains("SNAPSHOT #") &&
                   !line.contains("LOG END")) {
                line = in_log.readLine();
            }
            if (line.isNull())
                break;
            /* Read in data for callstacks */
            do {
                line = in_log.readLine();
                if (line.contains("SNAPSHOT #") ||
                    line.contains("LOG END"))
                    break;
                /* Example: 27,35,300 */
                QRegExp reg_exp("^(\\d+),(\\d+),(\\d+)$");
                reg_exp.indexIn(line);
                if (reg_exp.captureCount() != 3) {
                    qDebug() << "Malformed staleness: " << line;
                    break;
                }
                /* Get referenced callstack and subtract 1 since the
                 * callstack # starts at 1 in the logfile; while the array
                 * index starts at 0.
                 */
                quint64 callstack_index = reg_exp.cap(1).toULongLong() - 1;
                dhvis_callstack_listing_t *this_callstack;
                this_callstack = callstacks.at(callstack_index);
                /* Add to snapshot's vector */
                if (!snapshots[counter]->stale_callstacks
                                       .contains(this_callstack)) {
                    snapshots[counter]->stale_callstacks
                                      .append(this_callstack);
                }
                /* Map with snapshot_num as key */
                quint64 num_bytes = reg_exp.cap(2).toULongLong();
                quint64 last_access = reg_exp.cap(3).toULongLong();
                stale_pair_t tmp_pair(num_bytes, last_access);
                this_callstack->staleness_info[counter].append(tmp_pair);
            }  while (!line.contains("SNAPSHOT #") &&
                      !line.contains("LOG END"));

            counter++;
        } while (!line.isNull() &&
                 !line.contains("LOG END"));

        staleness_log.close();
    }
    qDebug() << "INFO: staleness.log read";
}

/* Private
 * Sorts the log data properly
 */
void
dhvis_tool_t::sort_log_data(void)
{
    /* Sort snapshots by time */
    std::sort(snapshots.begin(),
              snapshots.end(),
              sort_snapshots);
    /* Sort each callstack's staleness info (greatest first) */
    foreach (dhvis_callstack_listing_t *c, callstacks) {
        stale_map_t::iterator itr = c->staleness_info.begin();
        while (itr != c->staleness_info.end()) {
            std::sort(itr.value().begin(),
                      itr.value().end(),
                      stale_pair_sorter);
            ++itr;
        }
    }
    sort_stale_data();
}

/* Private
 * Sort staleness info
 */
void
dhvis_tool_t::sort_stale_data(void)
{
    /* Sort each snapshots stale_callstacks by stale_bytes
     * for staleness_graphing (greatest first)
     */
    for (quint64 i = 0; i < snapshots.count(); i++) {
        dhvis_snapshot_listing_t *s = snapshots[i];
        foreach (dhvis_callstack_listing_t *c, s->stale_callstacks) {
            c->cur_snap_num = s->snapshot_num;
        }
        std::sort(s->stale_callstacks.begin(),
                  s->stale_callstacks.end(),
                  stale_callstacks_sorter);
    }
}

/* Public
 * Updates widgets after a settings change
 */
void
dhvis_tool_t::update_settings(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    snapshot_graph->update_settings();
    staleness_graph->update_settings();
    if (snapshot_graph != NULL && !snapshot_graph->is_null())
        highlight_changed(current_snapshot_num, current_snapshot_index);
}

/* Private Slot
 * Handles creation/deletion of the snapshot graph
 */
void
dhvis_tool_t::draw_snapshot_graph(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    /* Remove */
    left_side->removeWidget(snapshot_graph);
    /* Create (previous is deleted in read_log_data()) */
    snapshot_graph = new dhvis_snapshot_graph_t(&snapshots, &time_unit,
                                                options);
    /* Format(QWidget*, row, col, row_span, col_span) */
    left_side->addWidget(snapshot_graph, 1, 0, 1, 2);
    connect(snapshot_graph, SIGNAL(highlight_changed(quint64, quint64)),
            this, SLOT(highlight_changed(quint64, quint64)));

    snapshot_graph->update_settings();
}

/* Private Slot
 * Updates widgets dependent on current_snapshot_num
 */
void
dhvis_tool_t::highlight_changed(quint64 snapshot, quint64 index)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    if (current_snapshot_num != snapshot && current_snapshot_index != index) {
        current_snapshot_num = snapshot;
        current_snapshot_index = index;
        callstacks_display_page = 0;
        fill_callstacks_table();
        load_frames_tree(frames_tab_area->currentIndex());
        draw_staleness_graph();
    }
}

/* Static
 * Private sorting functions for use only by std::sort.
 * Note the reversed comparisons, as we want the default sort to be by Descending Order.
 */
static bool
sort_by_callstack(const dhvis_callstack_listing_t * v1,
                  const dhvis_callstack_listing_t * v2)
{
    return v1->callstack_num > v2->callstack_num;
}

static bool
sort_by_symbol(const dhvis_callstack_listing_t * v1, const dhvis_callstack_listing_t * v2)
{

    QString symbol_display1;
    const QList<dhvis_frame_data_t *> *frames1 = &(v1->frame_data);
    /* Only show first 3 (skip 0) frames' func_name.
     * We skip 0 because it is always Dr. Heapstat's replace_* function.
     */
    static const unsigned int LAST_FUNC = 3;
    for (unsigned int i = 1; i <= LAST_FUNC && i < frames1->count(); i++) {
        dhvis_frame_data_t *frame = frames1->at(i);
        symbol_display1.append(frame->func_name);
        if (i != LAST_FUNC)
            symbol_display1.append(" <-- ");
    }

    QString symbol_display2;
    const QList<dhvis_frame_data_t *> *frames2 = &(v2->frame_data);
    for (unsigned int i = 1; i <= LAST_FUNC && i < frames2->count(); i++) {
        dhvis_frame_data_t *frame = frames2->at(i);
        symbol_display2.append(frame->func_name);
        if (i != LAST_FUNC)
            symbol_display2.append(" <-- ");
    }

    return symbol_display1 > symbol_display2;
}

static bool
sort_by_alloc(const dhvis_callstack_listing_t * v1, const dhvis_callstack_listing_t * v2)
{
    return v1->bytes_asked_for > v2->bytes_asked_for;
}

static bool
sort_by_pad(const dhvis_callstack_listing_t * v1, const dhvis_callstack_listing_t * v2)
{
    return v1->extra_usable > v2->extra_usable;
}

static bool
sort_by_head(const dhvis_callstack_listing_t * v1, const dhvis_callstack_listing_t * v2)
{
    return v1->extra_occupied > v2->extra_occupied;
}


/* Private Slot
 * Fills callstacks_table with gathered data
 */
void
dhvis_tool_t::fill_callstacks_table(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    if (current_snapshot_index < 0 ||
        current_snapshot_index >= snapshots.count())
        return;
    /* Settings */
    callstacks_table->clear();
    callstacks_table->setRowCount(0);
    callstacks_table->setColumnCount(5);
    QStringList table_headers;
    table_headers << tr("Call Stack") << tr("Symbol") << tr("Alloc")
                  << tr("+Pad") << tr("+Head");
    callstacks_table->setHorizontalHeaderLabels(table_headers);
    callstacks_table->setSortingEnabled(false);
    callstacks_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    callstacks_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    callstacks_table->setSelectionMode(QAbstractItemView::SingleSelection);
    callstacks_table->verticalHeader()->hide();
    callstacks_table->horizontalHeader()
                    ->setSectionResizeMode(QHeaderView::ResizeToContents);
    callstacks_table->horizontalHeader()
                    ->setSectionResizeMode(1, QHeaderView::Stretch);

    /* Put data into callstack_table */
    int row_count = -1;
    int max_rows = options->num_callstacks_per_page;
    QVector<dhvis_callstack_listing_t *> *vec;
    if (show_occur)
        vec = &visible_assoc_callstacks;
    else
        vec = &snapshots[current_snapshot_index]->assoc_callstacks;

    /* Presorting vec before we refill callstacks table based on column */
    bool (*sorting_function)(const dhvis_callstack_listing_t *,
                             const dhvis_callstack_listing_t *);

    switch (sorted_column) {
    default:
    case 0:
        sorting_function = &sort_by_callstack;
        break;
    case 1:
        sorting_function = &sort_by_symbol;
        break;
    case 2:
        sorting_function = &sort_by_alloc;
        break;
    case 3:
        sorting_function = &sort_by_pad;
        break;
    case 4:
        sorting_function = &sort_by_head;
        break;
    }

    if (sort_order == Qt::DescendingOrder)
        std::sort(vec->begin(), vec->end(), *sorting_function);
    else {
        /* We are guaranteed that if we have to sort by ascending order
         * then the vector is already sorted in descending order, so a simple
         * reverse is all we need.
         */
        std::reverse(vec->begin(), vec->end());
    }

    total_requested_usage = 0;
    total_pad_usage = 0;
    total_header_usage = 0;
    const int MAX = options->num_callstacks_per_page;
    foreach (dhvis_callstack_listing_t *this_callstack, *vec) {
        row_count++;
        if (row_count < callstacks_display_page * MAX)
            continue;
        else if (row_count >= (callstacks_display_page + 1) * MAX)
            break;
        callstacks_table->insertRow(row_count % max_rows);
        /* Callstack number */
        QTableWidgetItem *num = new QTableWidgetItem;
        num->setData(Qt::DisplayRole, this_callstack->callstack_num);
        callstacks_table->setItem(row_count % max_rows, 0, num);
        /* Symbols */
        QTableWidgetItem *symbols = new QTableWidgetItem;
        QString symbol_display;
        const QList<dhvis_frame_data_t *> *frames = &(this_callstack->frame_data);
        /* Only show first 3 (skip 0) frames' func_name
         * We skip 0 because it is always Dr. Heapstat's replace_malloc() function
         */
        static const unsigned int LAST_FUNC = 3;
        for (unsigned int i = 1; i <= LAST_FUNC && i < frames->count(); i++) {
            dhvis_frame_data_t *frame = frames->at(i);
            symbol_display.append(frame->func_name);
            if (i != LAST_FUNC)
                symbol_display.append(" <-- ");
        }
        symbols->setData(Qt::DisplayRole, symbol_display);
        callstacks_table->setItem(row_count % max_rows, 1, symbols);
        /* Memory data */
        QTableWidgetItem *asked = new QTableWidgetItem;
        asked->setData(Qt::DisplayRole,
                       this_callstack->bytes_asked_for);
        callstacks_table->setItem(row_count % max_rows, 2, asked);

        QTableWidgetItem *padding = new QTableWidgetItem;
        padding->setData(Qt::DisplayRole,
                         this_callstack->extra_usable);
        callstacks_table->setItem(row_count % max_rows, 3, padding);

        QTableWidgetItem *headers = new QTableWidgetItem;
        headers->setData(Qt::DisplayRole,
                         this_callstack->extra_occupied);
        callstacks_table->setItem(row_count % max_rows, 4, headers);

        if (show_occur) {
            total_requested_usage += this_callstack->bytes_asked_for;
            total_pad_usage += this_callstack->extra_usable;
            total_header_usage += this_callstack->extra_occupied;
        }
    }
    /* Insert a row at the top with the total usage information */
    insert_total_row();
    /* Current page info */
    qreal display_num = callstacks_display_page *
                        options->num_callstacks_per_page;
    qreal total =  vec->count();
    if (total == 0) {
        page_display_label->setText(tr("No callstacks in snapshot %1")
                                    .arg(current_snapshot_num));
    } else {
        /* +1 to adjust base from 0 to 1 for display */
        page_display_label->setText(tr("Displaying callstacks %1 to %2 of %3")
                                    .arg(display_num + 1)
                                    .arg(display_num +
                                         callstacks_table->rowCount())
                                    .arg(total));
    }
    /* Enable navigation buttons? */
    next_page_button->setEnabled(display_num + callstacks_table->rowCount() <  total);
    prev_page_button->setEnabled(callstacks_display_page != 0);
    reset_visible_button->setEnabled(show_occur);
    /* Select first frame (skip the total) */
    callstacks_table->setCurrentCell(1, 0);
}

/* Private Slot
 * Decrements page for callstacks_table
 */
void
dhvis_tool_t::show_prev_page(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    callstacks_display_page--;
    fill_callstacks_table();
}

/* Private Slot
 * Increments page for callstacks_table
 */
void
dhvis_tool_t::show_next_page(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    callstacks_display_page++;
    fill_callstacks_table();
}

/* Private Slot
 * Refreshes the frame views with data from the new callstack
 */
void
dhvis_tool_t::refresh_frames_text_edit(int current_row, int current_column,
                                       int previous_row, int previous_column)
{
    Q_UNUSED(current_column);
    Q_UNUSED(previous_column);
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    if (current_row != previous_row &&
        callstacks_table->selectedItems().size() != 0) {
        load_frames_text_edit(current_row);
    }
}

/* Private
 * Loads frame data into frames_text_edit for requested callstack
 */
void
dhvis_tool_t::load_frames_text_edit(int current_row)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;

    frames_text_edit->clear();
    /* Again, -1 since callstack_num starts at 1, index starts at 0 */
    int callstack_index = callstacks_table->item(current_row,0)
                                          ->data(Qt::DisplayRole)
                                          .toInt() - 1;
    if (callstack_index == -1)
        return;
    QList<dhvis_frame_data_t *> frames = callstacks.at(callstack_index)->frame_data;
    frames_text_edit->insertPlainText(QString(tr("Callstack #")));
    frames_text_edit->insertPlainText(QString::number(callstack_index + 1));
    frames_text_edit->insertHtml(QString("<br>"));
    /* Add frame data */
    for (int i = 0; i < frames.size(); i++) {
        const dhvis_frame_data_t *frame = frames[i];
        /* Change file name and line number to a link
         * Example [path/file_name:line_num]
         */
        QString file_name = "";
        if (frame->file_path != "?" && frame->file_name != "?" &&
            frame->line_num != "?") {
            file_name = frame->file_path + frame->file_name + ":" +
                        frame->line_num;
            file_name = "[<a href=\"" + file_name + "\">" + file_name +
                        "</a>] ";
        }
        QString data = "# " + QString::number(i) + " " +
                       frame->exec_name + "!" +
                       frame->func_name + " " +
                       file_name;
        frames_text_edit->insertHtml(QString("<br>") + data);
        /* Since the address contains '<', we can't use insertHTML. */
        frames_text_edit->insertPlainText("(" + frame->address + ")");
    }
}

/* Private Slot
 * Open code editor from frames_text_browser
 */
void
dhvis_tool_t::anchor_clicked(QUrl link)
{
    QStringList data = link.path().split(':');
    /* Get the file_name and line_num */
    QFile file_name(data.at(0));
    int line_num = data.at(1).toInt();

    emit code_editor_requested(file_name, line_num);
}

/* Private
 * Extracts important info from a frame
 * XXX i#1332: This function will not be needed after this issue is resolved.
 */
dhvis_frame_data_t *
dhvis_tool_t::extract_frame_data(const QString &frame)
{
    /*              1     2     |----------------3----------------|     4
     * Example: '# num exe_name!func_name [path/file_name:line_num] (address)'
     */
    QRegExp reg_exp("#\\s*(\\d+)\\s+(.+)\\!(.*(?!(?:\\s+\\[)|(?:\\s+\\()))"
                    ".*\\((0x\\w+ <.+0x\\w+>)\\)");
    reg_exp.indexIn(frame);
    dhvis_frame_data_t *frame_data = new dhvis_frame_data_t;
    /* Because callstacks share frames, but the frame is likely to be in a different
     * position across callstacks, we do not save the position in the callstack. We
     * use the order they are read to determine they're position.
     */
    frame_data->exec_name = reg_exp.cap(2);
    int index = reg_exp.cap(3).lastIndexOf('[');
    /* Cover case where func is 'operator new []' with no symbols after */
    if (index == reg_exp.cap(3).lastIndexOf("[]"))
        index++;
    /* Trimming removes leading and trailing spaces */
    frame_data->func_name = reg_exp.cap(3).left(index - 1).trimmed();
    /* Frame may not be symbolized */
    if (index > frame_data->func_name.size()) {
        /* Remove the leading and trailing brackets and spaces */
        QString full_path = reg_exp.cap(3).mid(index + 1);
        full_path = full_path.left(full_path.lastIndexOf(']'));
        /* We do not check the OS here because a user may load a data_set
         * that was collected from a different computer.
         */
        int last_index = full_path.lastIndexOf('\\');
        if (last_index == -1)
            last_index = full_path.lastIndexOf('/');
        /* +1 to include the / or \ in the path */
        frame_data->file_path = full_path.left(last_index + 1);
        frame_data->file_name = full_path.mid(last_index + 1);
        index = frame_data->file_name.lastIndexOf(':');
        frame_data->line_num = frame_data->file_name.mid(index + 1);
        frame_data->file_name = frame_data->file_name.left(index);
    } else {
        frame_data->file_path = frame_data->file_name
                              = frame_data->line_num = "?";
    }
    frame_data->address = reg_exp.cap(4);

    return frame_data;
}

/* Private Slot
 * Used to restrict loading the frames_tree when it is requested in the
 * tab interface. This reduces lag while highlighting snapshots if the
 * 'Tree View' tab is not open.
 */
void
dhvis_tool_t::load_frames_tree(int new_index)
{
    if (frames_tab_area->currentIndex() == TREE_TAB_INDEX)
        load_frames_tree();
}

/* Private
 * Loads frame data into frames_tree_widget for requested callstack
 * XXX i#1332: All of the processing here can take a while on large data sets.
 * XXX i#1319: Currently, the tree copies the data, using extra resources.
               This also creates a siginificant lag.
 */
void
dhvis_tool_t::load_frames_tree(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    if (snapshots.isEmpty() || callstacks.isEmpty())
        return;
    /* Disconnect from buttons */
    if (frames_tree_widget != NULL) {
        disconnect(expand_all_button, SIGNAL(clicked()),
                   frames_tree_widget, SLOT(expandAll()));
        disconnect(collapse_all_button, SIGNAL(clicked()),
                   frames_tree_widget, SLOT(collapseAll()));
    }
    /* Load if available */
    if (frame_trees.find(current_snapshot_num) != frame_trees.end()) {
        frames_tree_widget = *frame_trees.find(current_snapshot_num);
    } else {
        frames_tree_widget = new QTreeWidget;
        tree_stack->addWidget(frames_tree_widget);
        connect(frames_tree_widget,
                SIGNAL(itemDoubleClicked(QTreeWidgetItem *, int)),
                this,
                SLOT(frames_tree_double_clicked(QTreeWidgetItem *, int)));
        /* Settings */
        frames_tree_widget->setColumnCount(NUM_COLUMNS);
        frames_tree_widget->setAnimated(true);
        frames_tree_widget->setHeaderHidden(false);
        frames_tree_widget->setAlternatingRowColors(true);
        frames_tree_widget->setSortingEnabled(true);
        /* Set header labels */
        QStringList header_labels;
        header_labels.insert(EXEC_INDEX, QString(50, ' '));
        header_labels.insert(LINE_NUM_INDEX, tr("Line #"));
        header_labels.insert(ADDRESS_INDEX, tr("Address%1")
                                            .arg(QString(6, ' ')));
        header_labels.insert(OCCUR_INDEX, tr("Occurrences"));
        header_labels.insert(PATH_INDEX,  tr("Path"));
        frames_tree_widget->setHeaderLabels(header_labels);
        frames_tree_widget->header()
                          ->resizeSections(QHeaderView::ResizeToContents);

        const dhvis_snapshot_listing_t *this_snapshot =
            snapshots.at(current_snapshot_index);
        frame_tree_map_t frame_data_map;
        foreach (dhvis_callstack_listing_t *this_callstack,
                 this_snapshot->assoc_callstacks) {
            /* Again, -1 since callstack_num starts at 1, index starts at 0. */
            quint64 callstack_index = this_callstack->callstack_num - 1;
            const QList<dhvis_frame_data_t *> &frames = this_callstack->frame_data;
            /* Gather data */
            foreach (dhvis_frame_data_t *frame, frames) {
                frame_tree_map_t::iterator exec_itr;
                exec_itr = frame_data_map.find(frame->exec_name);
                /* With QMap a found insert is replaced, which we do not want. */
                if (exec_itr == frame_data_map.end()) {
                    exec_itr = frame_data_map.insert(frame->exec_name,
                                                     frame_tree_inner_map_t());
                }
                /* Store */
                frame_tree_pair_t tmp_pair(frame->file_path, frame->file_name);
                QStringList tmp_list;
                tmp_list.insert(FUNC_INDEX, frame->func_name);
                tmp_list.insert(LINE_NUM_INDEX, frame->line_num);
                tmp_list.insert(ADDRESS_INDEX, frame->address);
                tmp_list.insert(OCCUR_INDEX, QString::number(1));
                frame_tree_inner_map_t::iterator pair_itr = exec_itr->find(tmp_pair);
                QVector<dhvis_callstack_listing_t *> &assoc =
                    frame->assoc_callstacks[current_snapshot_num];
                /* Insert a file underneath an executable. */
                if (pair_itr == exec_itr->end()) {
                    QVector<QStringList> tmp_vec;
                    tmp_vec.append(tmp_list);
                    exec_itr->insert(tmp_pair, tmp_vec);
                } else {
                    /* The file already exists, so insert a frame underneath
                     * the file.
                     */
                    int i;
                    for (i = 0; i < pair_itr->count(); i++) {
                        /* If the frame already exists then append this callstack
                         * to the assoc_callstacks list for the frame.
                         */
                        if (pair_itr->at(i)[ADDRESS_INDEX] == tmp_list[ADDRESS_INDEX] ) {
                            if (!assoc.contains(this_callstack)) {
                                assoc.append(this_callstack);
                                quint64 size = assoc.size();
                                (*pair_itr)[i][OCCUR_INDEX] = QString::number(size);
                            }
                            break;
                        }
                    }
                    if (i == pair_itr->count()) {
                        pair_itr->append(tmp_list);
                        assoc.append(this_callstack);
                    }
                }
            }
        }
        fill_frames_tree(frame_data_map);
    }
    /* Connect viewable widget */
    connect(expand_all_button, SIGNAL(clicked()),
            frames_tree_widget, SLOT(expandAll()));
    connect(collapse_all_button, SIGNAL(clicked()),
            frames_tree_widget, SLOT(collapseAll()));
    /* Show the widget */
    tree_stack->setCurrentWidget(frames_tree_widget);
}

/* Private
 * Fills the frames tree with newly loaded data
 */
void
dhvis_tool_t::fill_frames_tree(frame_tree_map_t &frame_data_map)
{
    /* Put into tree
     * Example
     * + exec_name
     *     + file_name                               tot_occur     path
     *         + func_name    line_num    address    occurences
     */
    frame_tree_map_t::const_iterator exec_itr;
    exec_itr = frame_data_map.constBegin();
    while (exec_itr != frame_data_map.constEnd()) {
        QTreeWidgetItem *exec_name;
        exec_name = new QTreeWidgetItem((QTreeWidget *)NULL,
                                        QStringList(exec_itr.key()));
        frame_tree_inner_map_t::const_iterator file_itr;
        file_itr = exec_itr.value().constBegin();
        /* File names */
        while (file_itr != exec_itr.value().constEnd()) {
            QStringList tmp_list;
            tmp_list.insert(FILE_INDEX, file_itr.key().second);
            tmp_list.insert(PATH_INDEX, file_itr.key().first);
            /* Insert buffer space between columns */
            while (PATH_INDEX != tmp_list.count() - 1) {
                tmp_list.insert(tmp_list.count() - 1, QString());
            }
            QTreeWidgetItem *file_name;
            file_name = new QTreeWidgetItem((QTreeWidget *)NULL,
                                            tmp_list);
            /* Function names */
            /* XXX i#1319: Do not double count callstacks for the total */
            quint64 tot_occur = 0;
            QFont link_font;
            link_font.setUnderline(true);
            foreach (QStringList info, file_itr.value()) {
                QTreeWidgetItem *func_name;
                func_name = new QTreeWidgetItem((QTreeWidget *)NULL,
                                                info);
                /* Make line_num and num_occur look like links */
                func_name->setForeground(LINE_NUM_INDEX, QBrush(Qt::blue));
                func_name->setForeground(OCCUR_INDEX, QBrush(Qt::blue));
                func_name->setFont(LINE_NUM_INDEX, link_font);
                func_name->setFont(OCCUR_INDEX, link_font);
                /* Add tool tips */
                func_name->setToolTip(LINE_NUM_INDEX,
                                      "Opens an editor at this line");
                func_name->setToolTip(OCCUR_INDEX,
                                      "View occurrences in the callstacks "
                                      "table");
                file_name->addChild(func_name);
                tot_occur += info[OCCUR_INDEX].toULongLong();
            }
            file_name->setData(OCCUR_INDEX, Qt::DisplayRole, tot_occur);
            /* Set tot_occur font */
            file_name->setForeground(OCCUR_INDEX, QBrush(Qt::blue));
            file_name->setFont(OCCUR_INDEX, link_font);
            /* Add tool tip */
            file_name->setToolTip(OCCUR_INDEX,
                                  "View all occurrences in the callstacks "
                                  "table");
            exec_name->addChild(file_name);
            ++file_itr;
        }
        frames_tree_widget->addTopLevelItem(exec_name);
        ++exec_itr;
    }
    /* Select first */
    frames_tree_widget->setCurrentItem(frames_tree_widget->itemAt(0, 0));

    /* Add to map */
    frame_trees[current_snapshot_num] = frames_tree_widget;
}

/* Private Slot
 * Specifies behavior of an item in frames_tree_widget when it is
 * double clicked
 */
void
dhvis_tool_t::frames_tree_double_clicked(QTreeWidgetItem *item,
                                         int column)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    /* Open line num */
    if (item->childCount() == 0 && column == LINE_NUM_INDEX) {
        /* Open file with path/file_name */
        QFile code_file(item->parent()->text(PATH_INDEX)
                            .append(item->parent()->text(FILE_INDEX)));
        int line_num = item->text(LINE_NUM_INDEX).toInt();
        emit code_editor_requested(code_file, line_num);
        return;
    } else if (column == OCCUR_INDEX && item->text(OCCUR_INDEX) > 0) {
        /* Set callstacks_table to show specific occurrences */
        show_occur = true;
        callstacks_display_page = 0;
        /* Display a file's associated callstacks */
        if (item->childCount() > 0) {
            quint64 false_count = 0;
            total_requested_usage = 0;
            total_pad_usage = 0;
            total_header_usage = 0;
            visible_assoc_callstacks.clear();
            foreach (QTreeWidgetItem *child, item->takeChildren()) {
                /* Unfortuantely, the only way to access the children of
                 * an item is to remove them with takeChildren(), so we must
                 * re-add each child.
                 */
                item->addChild(child);
                QString tmp_addr = child->text(ADDRESS_INDEX).split(" ").at(0);
                tmp_addr.remove(0,2);
                bool ok;
                quint64 addr_int = tmp_addr.toULongLong(&ok, 16);
                if (!ok) {
                    false_count++;
                    continue;
                }
                foreach (dhvis_callstack_listing_t *c,
                         frames[addr_int]->assoc_callstacks[current_snapshot_num]) {
                    if (!visible_assoc_callstacks.contains(c)) {
                        visible_assoc_callstacks.append(c);
                        total_requested_usage += c->bytes_asked_for;
                        total_pad_usage += c->extra_usable;
                        total_header_usage += c->extra_occupied;
                    }
                }
            }
            if (false_count == item->childCount())
                show_occur = false;
        } else {
            /* Display a frame's associated callstacks */
            QString tmp_addr = item->text(ADDRESS_INDEX).split(" ").at(0);
            tmp_addr.remove(0,2);
            bool ok;
            quint64 addr_int = tmp_addr.toULongLong(&ok, 16);
            if (!ok) {
                show_occur = false;
            } else {
                visible_assoc_callstacks =
                    frames[addr_int]->assoc_callstacks[current_snapshot_num];
            }
        }
        fill_callstacks_table();
        return;
    }
    /* Determine if an item should be modifiable when double clicked, or
     * display its children. The purpose of is to allow a user to select the text
     * in an item. Unfortunately, the only way to do this is to make the item modifiable
     * as the ItemIsSelectable flag refers to the item as a whole, and not the text
     * that it contains.
     * N.B. Editing the text does NOT modify the data, it ONLY modifies the view.
     */
    Qt::ItemFlags cur_flags = item->flags();
    if (item->childCount() == 0 || column == PATH_INDEX) {
        item->setFlags(cur_flags | Qt::ItemIsEditable);
    } else if ((cur_flags & Qt::ItemIsEditable) != 0) {
        item->setFlags(cur_flags ^ Qt::ItemIsEditable);
    }
}

/* Private Slot
 * Resets the callstacks table to show all callstacks for a given snapshot
 */
void
dhvis_tool_t::reset_callstacks_view(void)
{
    show_occur = false;
    callstacks_display_page = 0;
    fill_callstacks_table();
    sort_order = Qt::DescendingOrder;
    sorted_column = 0;
}

/* Private
 * Loads and displays the staleness graph
 */
void
dhvis_tool_t::draw_staleness_graph(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    /* Remove */
    int old_tab_index = frames_tab_area->currentIndex();
    frames_tab_area->removeTab(2);
    if (staleness_graph != NULL &&
        staleness_graph->is_null())
        delete staleness_graph;
    /* Create a staleness graph for the snapshot if there isn't one already. */
    int index = current_snapshot_num;
    if (!stale_graphs.contains(index)) {
        stale_graphs[index] = new dhvis_stale_graph_t(&callstacks,
                                                      &snapshots,
                                                      &time_unit,
                                                      current_snapshot_num,
                                                      current_snapshot_index,
                                                      options);
    }
    /* Load and display the graph */
    staleness_graph = stale_graphs[index];
    frames_tab_area->addTab(staleness_graph, tr("Staleness Graph"));
    frames_tab_area->setCurrentIndex(old_tab_index);

    staleness_graph->update_settings();
}

/* Private Slot
 * Launches the target under Dr. Heapstat
 */
void
dhvis_tool_t::exec_dr_heap(void)
{
    QProcess *drh_process = new QProcess(this);
    QStringList args;
    /* Prepare args */
    if (!dh_args_line_edit->text().isEmpty())
        args << dh_args_line_edit->text();
    args << QString("-logdir ").append(options->dhrun_log_dir);
    args << "--";
    if (!dh_target.isEmpty())
        args << dh_target;
    if (!target_args_line_edit->text().isEmpty())
        args << target_args_line_edit->text();

    /* Set cursor to hourglass */
    qApp->setOverrideCursor(Qt::WaitCursor);

    /* Start and wait to finish */
    drh_process->start(dh_loc, args);
    if (!drh_process->waitForStarted()) {
        qApp->restoreOverrideCursor();
        return;
    } if (!drh_process->waitForFinished()) {
        qApp->restoreOverrideCursor();
        return;
    }

    /* Get and display output from streams */
    QByteArray stdout_result = drh_process->readAllStandardOutput();
    QByteArray stderr_result = drh_process->readAllStandardError();
    dhrun_stdout_output_browser->clear();
    dhrun_stdout_output_browser->insertPlainText(stdout_result);
    dhrun_stderr_output_browser->clear();
    dhrun_stderr_output_browser->insertPlainText(stderr_result);

    qApp->restoreOverrideCursor();

    /* Ask to load log data in this tab or in a new one */
    QMessageBox msg_box;
    msg_box.setText(tr("Dr. Heapstat was executed successfully."));
    msg_box.setInformativeText(tr("Where do you want to load the log data?"));
    QAbstractButton *new_tab = msg_box.addButton(tr("New tab"), QMessageBox::YesRole);
    QAbstractButton *this_tab = msg_box.addButton(tr("This tab"), QMessageBox::NoRole);
    msg_box.setStandardButtons(QMessageBox::Cancel);

    /* Extract and load a log directory for each process launched by the app */
    QString log_out(stderr_result);
    QStringList log_dirs;
    int last_index_of_log = 0;
    QRegExp reg_exp("log dir is ([^~]+)");
    while ((last_index_of_log = reg_exp.indexIn(log_out, last_index_of_log)) != -1) {
        log_dirs.push_back(reg_exp.cap(1));
        last_index_of_log += reg_exp.matchedLength();
    }
    if (log_dirs.count() == 0) {
        QMessageBox::warning(this, "Unable to find log directory",
            "The log directory was not successfully extracted from "
            "Dr. Heapstat's output. Please load the data manually",
            QMessageBox::Ok);
        return;
    }
    /* Ask to load each of the found log directories */
    int cap_count = 0;
    foreach (QString log_dir, log_dirs) {
        QString trimmed_log = log_dir.trimmed();
        msg_box.exec();
        if (msg_box.clickedButton() == new_tab) {
            dhvis_tool_t *new_tool = new dhvis_tool_t(options);
            emit new_instance_requested(new_tool, "Dr. Heapstat Visualizer");
            emit load_log_dir(new_tool, trimmed_log);
        } else if (msg_box.clickedButton() == this_tab) {
            set_log_dir_loc(trimmed_log);
        }
        cap_count++;
    }
}

/* Private Slot
 * Chooses files for QLineEdit QPushButton pairs
 */
void
dhvis_tool_t::choose_file(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    bool *file_text_changed = NULL;
    QString *file_loc = NULL;
    QString file_types;
    QLineEdit *line_edit = NULL;
    /* Determine which button sent signal */
    if (sender() == dhrun_loc_button) {
        file_text_changed = &dhrun_loc_text_changed;
        file_loc = &dh_loc;
        line_edit = dhrun_loc_line_edit;
        file_types = tr("Executables (*.exe *.pl);;All Files (*)");
    } else if (sender() == dhrun_target_button) {
        file_text_changed = &dhrun_target_text_changed;
        file_loc = &dh_target;
        line_edit = dhrun_target_line_edit;
        file_types = tr("Executables (*.exe *.pl);;All Files (*)");
    } else {
        return;
    }

    if (*file_text_changed) /* Enterered file */ {
        QFile test_file(line_edit->text());
        if (dr_check_file(test_file)) {
            *file_loc = line_edit->text();
        } else {
            /* Reset file_text_changed */
            *file_text_changed = false;
            return;
        }
    } else /* Navigate to file_loc */ {
        QFileDialog file_dialog;
        QFile test_file;
        do {
            test_file.setFileName(
                file_dialog.getOpenFileName(this,
                                            tr("Open File"),
                                            options->def_load_dir,
                                            file_types,
                                            NULL,
                                            QFileDialog::DontUseNativeDialog));
            if (test_file.fileName().isEmpty())
                return;
        } while (!dr_check_file(test_file));
        *file_loc = test_file.fileName();
        line_edit->setText(*file_loc);
    }

    /* Reset file_text_changed */
    *file_text_changed = false;
}

/* Private Slot
 * Sorts the callstack table by appropriate column and resets to first page
 */
void
dhvis_tool_t::slot_table_clicked(int column)
{
    callstacks_display_page = 0;
    if (sort_order == Qt::DescendingOrder && column == sorted_column)
        sort_order = Qt::AscendingOrder;
    else
        sort_order = Qt::DescendingOrder;
    sorted_column = column;
    fill_callstacks_table();
}

/* Public
 * Sets log_dir_loc and loads the log data
 */
void
dhvis_tool_t::set_log_dir_loc(const QString &log_dir)
{
    log_dir_loc = log_dir;
    log_dir_line_edit->setText(log_dir_loc);
    read_log_data();
}

/* Private
 * Inserts a row at the top of the callstacks table which displays total memory usage
 */
void
dhvis_tool_t::insert_total_row(void)
{
    if (!show_occur) {
        total_requested_usage = snapshots[current_snapshot_index]->tot_bytes_asked_for;
        total_pad_usage = snapshots[current_snapshot_index]->tot_bytes_usable;
        total_header_usage = snapshots[current_snapshot_index]->tot_bytes_occupied;
    }
    callstacks_table->insertRow(0);
    QTableWidgetItem *num = new QTableWidgetItem;
    num->setData(Qt::DisplayRole, "--");
    callstacks_table->setItem(0, 0, num);
    QTableWidgetItem *label = new QTableWidgetItem;
    label->setData(Qt::DisplayRole,
                   "Total Memory Usage");
    callstacks_table->setItem(0, 1, label);
    QTableWidgetItem *asked = new QTableWidgetItem;
    asked->setData(Qt::DisplayRole,
                   total_requested_usage);
    callstacks_table->setItem(0, 2, asked);

    QTableWidgetItem *padding = new QTableWidgetItem;
    padding->setData(Qt::DisplayRole,
                     total_pad_usage);
    callstacks_table->setItem(0, 3, padding);

    QTableWidgetItem *headers = new QTableWidgetItem;
    headers->setData(Qt::DisplayRole,
                     total_header_usage);
    callstacks_table->setItem(0, 4, headers);
}
