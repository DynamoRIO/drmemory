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

/* dhvis_options_page.h
 *
 * Defines the Dr. Heapstat visualizer options page
 */

#ifndef DHVIS_OPTIONS_H
#define DHVIS_OPTIONS_H

#include "drgui_options_interface.h"
#include "dhvis_structures.h"

class QSpinBox;
class QLineEdit;
class QCheckBox;
class QPushButton;

class dhvis_options_page_t : public drgui_options_interface_t
{
    Q_OBJECT
    Q_INTERFACES(drgui_options_interface_t)

public:
    dhvis_options_page_t(void);

    QStringList tool_names(void) const;

    void set_options(dhvis_options_t *options);

signals:
    void settings_changed(void);

private slots:
    void choose_dir(void);

private:
    void create_layout(void);

    void write_settings(void);

    void read_settings(void);

    dhvis_options_t *options;

    /* GUI */
    QLineEdit *def_load_dir_line_edit;
    QLineEdit *exec_log_dir_line_edit;
    QCheckBox *square_graph_check_box;
    QCheckBox *anti_aliasing_check_box;
    QCheckBox *snap_stale_unit_num_check_box;
    QCheckBox *stale_sum_check_box;
    QCheckBox *stale_stale_unit_num_check_box;
    QCheckBox *format_bytes_check_box;
    QSpinBox *snap_num_tabs_spin_box;
    QSpinBox *stale_num_tabs_spin_box;
    QSpinBox *num_callstacks_per_page_spin_box;
    QSpinBox *num_stale_per_page_spin_box;

    QPushButton *find_def_load_dir_button;
    QPushButton *exec_log_dir_button;
};

#endif
