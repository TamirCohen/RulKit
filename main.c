#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <asm/syscall.h>
#include "hook.h"

MODULE_LICENSE("GPL");

HOOK__hook_t hook = {};

long handler(const struct pt_regs * regs)
{
    // sys_call_ptr_t * syscall_table_address = (sys_call_ptr_t *)kallsyms_lookup_name("sys_call_table");
    printk(KERN_INFO "HOOKED FUNCTION !\n");
    return ((sys_call_ptr_t)hook.original_function)(regs);
}

static int __init lkm_example_init(void)
{
    sys_call_ptr_t * syscall_table_address = (sys_call_ptr_t *)kallsyms_lookup_name("sys_call_table");
    HOOK__init(&hook, (void *)handler, (void **)&syscall_table_address[83]);
    HOOK__attach(&hook);

    printk(KERN_INFO "Finished INIT !\n");


    return 0;
}

static void __exit lkm_example_exit(void)
{
    printk(KERN_INFO "Goodbye, World !\n");
    HOOK__detach(&hook);
}

module_init(lkm_example_init);
module_exit(lkm_example_exit);