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

/* dhvis_factory.h
 *
 * Defines the Dr. Heapstat visualizer factory
 */

#ifndef DHVIS_FACTORY_H
#define DHVIS_FACTORY_H
#define DrHeapstat_Visualizer_iid "DrMemory.DrHeapstat.Visualizer"

#include "drgui_tool_interface.h"
#include "drgui_options_interface.h"

class dhvis_tool_t;
class dhvis_options_page_t;
struct dhvis_options_t;

class dhvis_factory_t : public drgui_tool_interface_t
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID DrHeapstat_Visualizer_iid)
    Q_INTERFACES(drgui_tool_interface_t)

public:
    dhvis_factory_t(void);

    ~dhvis_factory_t(void);

    QStringList tool_names(void) const;

    QWidget *create_instance(const QStringList &args = QStringList());

    drgui_options_interface_t *create_options_page(void);

    void open_file(const QString &path, int line_num);

public slots:
    void update_settings(void);

private slots:
    void new_tool_instance(QWidget *tool, QString tool_name);

    void load_log_dir(dhvis_tool_t *tool, const QString &log_dir);

private:
    /* GUI */
    QVector<dhvis_tool_t *> tool_instances;

    /* Options */
    dhvis_options_t *options;
    dhvis_options_page_t *options_page;
};

#endif
