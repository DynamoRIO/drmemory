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

#include <algorithm>
#include <cmath>

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
    left_side->addWidget(graph_title, 0, 0);
    left_side->setRowStretch(1, 5);

    /* Right side */
    right_side = new QGridLayout;
    right_title = new QLabel(QString(tr("Memory consumption at "
                                        "a given point: Individual "
                                        "callstacks")),
                             this);
    right_side->addWidget(right_title, 0, 0);

    /* Frames tab area */
    frames_tab_area = new QTabWidget(this);

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
    if (!dr_check_file(callstack_log) ||
        !dr_check_file(snapshot_log))
        return;
    /* Delete current memory */
    delete_data();

    read_callstack_log(callstack_log);
    read_snapshot_log(snapshot_log);

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
        for (int i = 0; i < tot_callstacks; i++) {
            callstacks[i] = new dhvis_callstack_listing_t;
        }
        /* Reset log */
        if (!callstack_log.seek(file_entry)) {
            delete_data();
            return;
        }
        /* We assume that the snapshots are listed in increasing order
         * by their snapshot number
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
                    QRegExp reg_exp;
                    reg_exp.setPattern("0x(\\w+) <.+0x\\w+>");
                    if (reg_exp.indexIn(line) < 0)
                        qDebug() << "Malformed frame: " << line;
                    else
                        address = reg_exp.cap(1);
                    /* The frame number is not necessarily the same between callstacks,
                     * so we strip it and use the index of the frame in the callstack's
                     * list to regenerate it for display
                     */
                    line.remove(QRegExp("#\\s*[0-9]+"));

                    bool ok;
                    frames[address.toULongLong(&ok, 16)] = line;
                    this_callstack->frame_data
                                  .append(&frames[address.toULongLong(&ok, 16)]);
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
         * by their snapshot number
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
                 * so we can't assume that they will sum properly
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
