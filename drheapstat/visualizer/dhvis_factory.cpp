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

/* dhvis_factory.cpp
 *
 * Provides the Dr. Heapstat visualizer factory
 */

#define __CLASS__ "dhvis_factory_t::"

#include <QDebug>

#include "drgui_tool_interface.h"
#include "drgui_options_interface.h"
#include "dhvis_options_page.h"
#include "dhvis_tool.h"
#include "dhvis_factory.h"

/* Public
 * Constructor
 */
dhvis_factory_t::dhvis_factory_t(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    options_page = new dhvis_options_page_t;
    connect(options_page, SIGNAL(settings_changed()),
            this, SLOT(update_settings()));
    options = new dhvis_options_t;
    /* loads settings */
    create_options_page();
}

/* Public
 * Destructor
 */
dhvis_factory_t::~dhvis_factory_t(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    delete options_page;
    delete options;
    while (tool_instances.count() > 0) {
        dhvis_tool_t *tmp = tool_instances.back();
        tool_instances.pop_back();
        delete tmp;
    }
}

/* Public
 * Returns provided tool names during loading
 */
QStringList
dhvis_factory_t::tool_names(void) const
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    return QStringList() << "Dr. Heapstat Visualizer";
}

/* Public
 * Returns a new instance of the tool
 */
QWidget *
dhvis_factory_t::create_instance(const QStringList &args)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    new_tool_instance(new dhvis_tool_t(options), tool_names().at(0));
    /* Automatically load the requested logs */
    if (args.count() == 1)
        load_log_dir(tool_instances.back(), args.at(0));
    return tool_instances.back();
}

/* Public
 * Refreshes and returns the options page
 */
drgui_options_interface_t *
dhvis_factory_t::create_options_page(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    options_page->set_options(options);
    return options_page;
}

/* Public
 * Unused virtual implementation
 */
void
dhvis_factory_t::open_file(const QString &path, int line_num)
{
    Q_UNUSED(path);
    Q_UNUSED(line_num);
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
}

/* Public slot
 * Tells each tab to update after settings change
 */
void
dhvis_factory_t::update_settings(void)
{
    qDebug().nospace() << "INFO: Entering " << __CLASS__ << __FUNCTION__;
    foreach (dhvis_tool_t *tool, tool_instances) {
        tool->update_settings();
    }
}

/* Private Slot
 * Adds a new tool to the list
 */
void
dhvis_factory_t::new_tool_instance(QWidget *tool, QString tool_name)
{
    connect(tool, SIGNAL(new_instance_requested(QWidget *, QString)),
            this, SLOT(new_tool_instance(QWidget *, QString)));
    connect(tool, SIGNAL(load_log_dir(dhvis_tool_t *, QString)),
            this, SLOT(load_log_dir(dhvis_tool_t *, QString)));
    tool_instances.append((dhvis_tool_t *)tool);

    emit new_instance_requested(tool, tool_name);
}

/* Private Slot
 * Loads the data into the tool
 */
void
dhvis_factory_t::load_log_dir(dhvis_tool_t *tool, const QString &log_dir)
{
    tool->set_log_dir_loc(log_dir);
}
