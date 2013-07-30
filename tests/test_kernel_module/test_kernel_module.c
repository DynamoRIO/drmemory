#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#define AUTHOR "Dimitrios Tatsis <dtouch3d@gmail.com>"
#define DESC "A test module for DrMemory, printing a message to the system log"
#define LICENSE "GPL"

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
