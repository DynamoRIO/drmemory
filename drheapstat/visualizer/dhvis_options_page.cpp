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
    settings.endGroup();

    /* Adjust GUI to reflect new settings */
    def_load_dir_line_edit->setText(options->def_load_dir);
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
    QPushButton *find_def_load_dir_button = new QPushButton(tr("Select"));
    connect(find_def_load_dir_button, SIGNAL(clicked()),
            this, SLOT(choose_def_load_dir()));

    /* Layout */
    QVBoxLayout *main_layout = new QVBoxLayout;

    QGridLayout *general_layout = new QGridLayout;
    general_layout->addWidget(load_dir_label, 0, 0);
    general_layout->addWidget(def_load_dir_line_edit, 1, 0);
    general_layout->addWidget(find_def_load_dir_button, 1, 1);
    general_group->setLayout(general_layout);

    main_layout->addWidget(general_group);
    main_layout->addStretch(1);

    setLayout(main_layout);
}

/* Private Slot
 * User chooses def_load_dir
 */
void
dhvis_options_page_t::choose_def_load_dir(void)
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
   def_load_dir_line_edit->setText(test_dir);
}
