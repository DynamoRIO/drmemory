/* **********************************************************
 * Copyright (c) 2013 Google, Inc.  All rights reserved.
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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#define AUTHOR "Dimitrios Tatsis <dtouch3d@gmail.com>"
#define DESC "A test module for DrMemory, printing a message to the system log"
#define LICENSE "LGPL"

static char*  param = "dummy";

static int __init
drmem_test_init(void)
{
    printk(KERN_INFO "DrMemory test kernel module init \n");
    printk(KERN_INFO "DrMemory test kernel module param: %s", param);
    return 0;
}

static void __exit
drmem_test_cleanup(void)
{
    printk(KERN_INFO "DrMemory test kernel module exit \n");
}

MODULE_LICENSE(LICENSE);
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESC);
module_param(param, charp, 0000);
MODULE_PARM_DESC(param, "A dummy string");

module_init(drmem_test_init);
module_exit(drmem_test_cleanup);
