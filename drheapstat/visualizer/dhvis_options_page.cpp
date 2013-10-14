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

/* dhvis_options_page.cpp
 *
 * Provides the Dr. Heapstat visualizer options page
 */

#include <QGroupBox>
#include <QLineEdit>
#include <QPushButton>
#include <QGridLayout>
#include <QVBoxLayout>
#include <QSettings>
#include <QLabel>
#include <QFileDialog>
#include <QCheckBox>
#include <QSpinBox>

#include "dhvis_options_page.h"

/* Public
 * Constructor
 */
dhvis_options_page_t::dhvis_options_page_t(void)
{
    create_layout();
}

/* Public
 * Returns provided tool names during loading
 */
QStringList
dhvis_options_page_t::tool_names(void) const
{
    return QStringList() << "Dr. Heapstat Visualizer";
}

/* Private
 * Writes settings from the options struct
 */
void
dhvis_options_page_t::write_settings(void)
{
    QSettings settings("DynamoRIO", "DrGUI");
    settings.beginGroup("Dr._Heapstat_Visualizer");
    settings.setValue("Default_load_directory",
                      def_load_dir_line_edit->text());
    settings.setValue("Square_graph",
                      square_graph_check_box->isChecked());
    settings.setValue("Anti-aliasing",
                      anti_aliasing_check_box->isChecked());
    settings.setValue("Snapshot_graph_stale_unit_is_num_snaps",
                      snap_stale_unit_num_check_box->isChecked());
    settings.setValue("Snapshot_vertical_ticks",
                      snap_num_tabs_spin_box->value());
    settings.setValue("Number_of_callstacks_per_page",
                      num_callstacks_per_page_spin_box->value());
    settings.setValue("Sum_stale_blocks",
                      stale_sum_check_box->isChecked() == true);
    settings.setValue("Staleness_vertical_ticks",
                      stale_num_tabs_spin_box->value());
    settings.setValue("Number_of_stale_bars_per_page",
                      num_stale_per_page_spin_box->value());
    settings.setValue("Staleness_graph_stale_unit_is_num_snaps",
                      stale_stale_unit_num_check_box->isChecked());
    settings.setValue("Default_Dr._Heapstat_log_dir",
                      exec_log_dir_line_edit->text());
    settings.setValue("Format_bytes_for_display",
                      format_bytes_check_box->isChecked());
    settings.endGroup();

    /* Adjust info */
    read_settings();
    emit settings_changed();
}

/* Private
 * Reads settings into the options struct
 */
void
dhvis_options_page_t::read_settings(void)
{
    if (options == NULL)
        return;
    QSettings settings("DynamoRIO", "DrGUI");
    settings.beginGroup("Dr._Heapstat_Visualizer");
    options->def_load_dir = settings.value("Default_load_directory",
                                           QString("")).toString();
    options->square_graph = settings.value("Square_graph", false).toBool();
    options->anti_aliasing_enabled = settings.value("Anti-aliasing", true).toBool();
    options->snap_stale_unit_num = settings.value("Snapshot_graph_"
                                                  "stale_unit_is_num_snaps",
                                                   true).toBool();
    options->snap_vertical_ticks = settings.value("Snapshot_vertical_ticks",
                                                  10).toInt();
    options->num_callstacks_per_page = settings.value("Number_of_"
                                                      "callstacks_per_page",
                                                      50).toInt();
    options->stale_sum_enabled = settings.value("Sum_stale_blocks", true).toBool();
    options->stale_vertical_ticks = settings.value("Staleness_vertical_ticks",
                                                   10).toInt();
    options->num_stale_per_page = settings.value("Number_of_stale_bars_per_page",
                                                 50).toInt();
    options->stale_stale_unit_num = settings.value("Staleness_graph_"
                                                   "stale_unit_is_num_snaps",
                                                    true).toBool();
    options->dhrun_log_dir = settings.value("Default_Dr._Heapstat_log_dir",
                                            QString("")).toString();
    options->format_bytes = settings.value("Format_bytes_for_display", false).toBool();
    settings.endGroup();

    /* Adjust GUI to reflect new settings */
    def_load_dir_line_edit->setText(options->def_load_dir);
    square_graph_check_box->setChecked(options->square_graph);
    anti_aliasing_check_box->setChecked(options->anti_aliasing_enabled);
    snap_stale_unit_num_check_box->setChecked(options->snap_stale_unit_num);
    snap_num_tabs_spin_box->setValue(options->snap_vertical_ticks);
    num_callstacks_per_page_spin_box->setValue(options->num_callstacks_per_page);
    stale_sum_check_box->setChecked(options->stale_sum_enabled);
    stale_num_tabs_spin_box->setValue(options->stale_vertical_ticks);
    num_stale_per_page_spin_box->setValue(options->num_stale_per_page);
    stale_stale_unit_num_check_box->setChecked(options->stale_stale_unit_num);
    exec_log_dir_line_edit->setText(options->dhrun_log_dir);
    format_bytes_check_box->setChecked(options->format_bytes);
}

/* Private
 * Reads settings into the options struct
 */
void
dhvis_options_page_t::set_options(dhvis_options_t *options_)
{
    options = options_;
    read_settings();
}

/* Private
 * Creates and connects the GUI
 */
void
dhvis_options_page_t::create_layout(void)
{
    /* General */
    QGroupBox *general_group = new QGroupBox(tr("General"), this);
    QLabel *load_dir_label = new QLabel(tr("Default loading directory:"));
    def_load_dir_line_edit = new QLineEdit(this);
    find_def_load_dir_button = new QPushButton(tr("Select"));
    connect(find_def_load_dir_button, SIGNAL(clicked()),
            this, SLOT(choose_dir()));

    anti_aliasing_check_box = new QCheckBox(tr("Anti-aliasing"));

    format_bytes_check_box = new QCheckBox(tr("Format bytes for display"));

    num_callstacks_per_page_spin_box = new QSpinBox(this);
    QLabel *callstack_spin_box_label = new QLabel(tr(" callstacks per page"));
    num_callstacks_per_page_spin_box->setMinimum(1);
    num_callstacks_per_page_spin_box->setMaximum(500);

    /* Snapshot Graph */
    QGroupBox *snap_graph_group = new QGroupBox(tr("Snapshot Graph"), this);
    square_graph_check_box = new QCheckBox(tr("Square graph"));
    QString snap_stale_unit_label(tr("Use elapsed snapshots as the stale "
                                     "for/since unit"));
    snap_stale_unit_num_check_box = new QCheckBox(snap_stale_unit_label);
    snap_num_tabs_spin_box = new QSpinBox(this);
    QLabel *tabs_spin_box_label = new QLabel(tr(" vertical scale ticks"));
    snap_num_tabs_spin_box->setMinimum(1);

    /* Staleness Graph*/
    QGroupBox *stale_graph_group = new QGroupBox(tr("Staleness Graph"), this);
    stale_sum_check_box = new QCheckBox(tr("Graph sum of stale blocks"));

    stale_num_tabs_spin_box = new QSpinBox(this);
    QLabel *tabs_spin_box_label_ = new QLabel(tr(" vertical scale ticks"));
    stale_num_tabs_spin_box->setMinimum(1);
    QString stale_stale_unit_label(tr("Use elapsed snapshots as the stale "
                                     "for/since unit"));
    stale_stale_unit_num_check_box = new QCheckBox(stale_stale_unit_label);

    num_stale_per_page_spin_box = new QSpinBox(this);
    QLabel *stale_spin_box_label = new QLabel(tr(" callstacks per page"));
    num_stale_per_page_spin_box->setMinimum(1);
    num_stale_per_page_spin_box->setMaximum(500);

    /* Run Dr. Heapstat */
    QGroupBox *dhrun_group = new QGroupBox(tr("Run Dr. Heapsat"), this);
    QLabel *exec_log_dir_label = new QLabel(tr("Dr. Heapstat log directory:"));
    exec_log_dir_line_edit = new QLineEdit(this);
    exec_log_dir_button = new QPushButton(tr("Select"));
    connect(exec_log_dir_button, SIGNAL(clicked()),
            this, SLOT(choose_dir()));

    /* Layout */
    QVBoxLayout *main_layout = new QVBoxLayout;

    QGridLayout *general_layout = new QGridLayout;
    general_layout->addWidget(load_dir_label, 0, 0);
    general_layout->addWidget(def_load_dir_line_edit, 1, 0);
    general_layout->addWidget(find_def_load_dir_button, 1, 1);
    general_layout->addWidget(anti_aliasing_check_box, 2, 0);
    general_layout->addWidget(format_bytes_check_box, 3, 0);
    general_layout->addWidget(num_callstacks_per_page_spin_box, 4, 0);
    general_layout->addWidget(callstack_spin_box_label, 4, 1);
    general_group->setLayout(general_layout);

    QGridLayout *snap_graph_layout = new QGridLayout;
    snap_graph_layout->addWidget(square_graph_check_box, 0, 0);
    snap_graph_layout->addWidget(snap_stale_unit_num_check_box, 1, 0);
    snap_graph_layout->addWidget(snap_num_tabs_spin_box, 2, 0);
    snap_graph_layout->addWidget(tabs_spin_box_label, 2, 1);
    snap_graph_group->setLayout(snap_graph_layout);

    QGridLayout *stale_graph_layout = new QGridLayout;
    stale_graph_layout->addWidget(stale_sum_check_box, 1, 0);
    stale_graph_layout->addWidget(stale_stale_unit_num_check_box, 2, 0);
    stale_graph_layout->addWidget(stale_num_tabs_spin_box, 3, 0);
    stale_graph_layout->addWidget(tabs_spin_box_label_, 3, 1);
    stale_graph_layout->addWidget(num_stale_per_page_spin_box, 4, 0);
    stale_graph_layout->addWidget(stale_spin_box_label, 4, 1);
    stale_graph_group->setLayout(stale_graph_layout);

    QGridLayout *dhrun_layout = new QGridLayout;
    dhrun_layout->addWidget(exec_log_dir_label, 0, 0);
    dhrun_layout->addWidget(exec_log_dir_line_edit, 1, 0);
    dhrun_layout->addWidget(exec_log_dir_button, 1, 1);
    dhrun_group->setLayout(dhrun_layout);

    main_layout->addWidget(general_group);
    main_layout->addWidget(snap_graph_group);
    main_layout->addWidget(stale_graph_group);
    main_layout->addWidget(dhrun_group);
    main_layout->addStretch(1);

    setLayout(main_layout);
}

/* Private Slot
 * Does basic checking on a user selected directory
 */
void
dhvis_options_page_t::choose_dir(void)
{
    QString test_dir;
    test_dir = QFileDialog::getExistingDirectory(this,
                                                 tr("Open Directory"),
                                                 options->def_load_dir,
                                                 QFileDialog::ShowDirsOnly);
    if (test_dir.isEmpty()) {
        return;
    }
    /* Set text box text */
    if (sender() == find_def_load_dir_button)
        def_load_dir_line_edit->setText(test_dir);
    else if (sender() == exec_log_dir_button)
        exec_log_dir_line_edit->setText(test_dir);
}
