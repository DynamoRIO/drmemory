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
 * Provides the DR. Heapstat visualizer
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

#include "dhvis_structures.h"
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
        /* XXX i#1319: read log data */
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
    QString error_msg = "\'"; 
    error_msg += dir.canonicalPath() + "\'<br>";
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
