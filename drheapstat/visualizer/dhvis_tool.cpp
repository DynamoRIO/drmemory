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
#include "dhvis_tool.h"

/* Public
 * Constructor
 */
dhvis_tool_t::dhvis_tool_t(dhvis_options_t *options_)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    log_dir_text_changed = false;
    log_dir_loc =  "";
    options = options_;
    current_snapshot_num = -1;
    current_snapshot_index= -1;
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

    /* Reset environment */
    callstacks_display_page = 0;
    current_snapshot_num = -1;
    current_snapshot_index= -1;

    snapshot_graph = NULL;
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
    left_side->addItem(space_holder, 2, 0);
    left_side->setRowStretch(1, 5);
    left_side->setRowStretch(2, 5);

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

    callstacks_page_buttons->addWidget(prev_page_button);
    callstacks_page_buttons->addWidget(page_display_label);
    callstacks_page_buttons->addStretch(1);
    callstacks_page_buttons->addWidget(next_page_button);

    right_side->addWidget(right_title, 0, 0);
    right_side->addWidget(callstacks_table, 1, 0);
    right_side->addLayout(callstacks_page_buttons,2,0);

    /* Frames tab area */
    frames_tab_area = new QTabWidget(this);

    /* Frames text box */
    right_side->addLayout(callstacks_page_buttons,2,0);
    frames_text_edit = new QTextBrowser(this);
    frames_text_edit->setOpenLinks(false);
    frames_text_edit->setLineWrapMode(QTextEdit::NoWrap);
    connect(frames_text_edit, SIGNAL(anchorClicked(QUrl)),
            this, SLOT(anchor_clicked(QUrl)));

    frames_tab_area->addTab(frames_text_edit, tr("List View"));

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
    if (*dir_text_changed) /* enter dir_loc */{
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
    /* Set cursor to hourglass */
    qApp->setOverrideCursor(Qt::WaitCursor);
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
    }
}

/* Private Slot
 * Fills callstacks_table with gathered data
 */
void
dhvis_tool_t::fill_callstacks_table(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;

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
    vec = &snapshots[current_snapshot_index]->assoc_callstacks;

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
                      (double)(this_callstack->bytes_asked_for));
        callstacks_table->setItem(row_count % max_rows, 2, asked);

        QTableWidgetItem *padding = new QTableWidgetItem;
        padding->setData(Qt::DisplayRole,
                        (double)(this_callstack->extra_usable));
        callstacks_table->setItem(row_count % max_rows, 3, padding);

        QTableWidgetItem *headers = new QTableWidgetItem;
        headers->setData(Qt::DisplayRole,
                        (double)(this_callstack->extra_occupied));
        callstacks_table->setItem(row_count % max_rows, 4, headers);
    }
    /* Re-sort added data (descending bytes alloc'd)*/
    callstacks_table->setSortingEnabled(true);
    callstacks_table->sortItems(2, Qt::DescendingOrder);
    /* Current page info */
    qreal display_num = callstacks_display_page *
                        options->num_callstacks_per_page;
    qreal total = snapshots[current_snapshot_index]->assoc_callstacks.count();
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
    if (display_num + callstacks_table->rowCount() <  total)
        next_page_button->setEnabled(true);
    else
        next_page_button->setEnabled(false);
    if (callstacks_display_page == 0)
        prev_page_button->setEnabled(false);
    else
        prev_page_button->setEnabled(true);
    /* Select first row */
    callstacks_table->setCurrentCell(0, 0);
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
