#include "hook.h"
#include <asm/paravirt.h>
#include <asm/special_insns.h>
#include <linux/kallsyms.h>
#include <uapi/asm-generic/errno-base.h>
#include <linux/list.h>
#include <linux/slab.h>

inline void mywrite_cr0(unsigned long cr0) {
    asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}

void enable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    mywrite_cr0(cr0);
}

void disable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    mywrite_cr0(cr0);
}

void hook__init_address(HOOK__hook_t * hook, void * handler, void ** hook_address)
{
    hook->hook_address = hook_address;
    hook->original_function = *hook_address;
    hook->new_function = handler;
}

void HOOK__detach(HOOK__hook_t * hook)
{
    disable_write_protection();
    *(hook->hook_address) = hook->original_function;
    printk(KERN_INFO "DEATACHING HOOK at address %p. OLD Function: %p. New Function: %p",
        hook->hook_address,
        hook->original_function,
        hook->new_function
        );
    enable_write_protection();
    list_del(&hook->list_node);
}

HOOK__hook_t * HOOK__attach_to_syscall(struct list_head * hook_list, sys_call_ptr_t * handler, __u32 syscall_index)
{
    sys_call_ptr_t * syscall_table_address = (sys_call_ptr_t *)kallsyms_lookup_name("sys_call_table");
    if (syscall_index >= NR_syscalls)
    {
        return NULL;
    }
    return HOOK__attach(hook_list, handler, (void **)&syscall_table_address[syscall_index]);
}

HOOK__hook_t * HOOK__attach(struct list_head * hook_list, void * handler, void ** hook_address)
{
    HOOK__hook_t * hook = (HOOK__hook_t * )kmalloc(sizeof(*hook), GFP_KERNEL);
    if (NULL == hook)
    {
        return NULL;
    }
    hook__init_address(hook, handler, hook_address);
    disable_write_protection();
    printk(KERN_INFO "ATTACHING HOOK at address %p. OLD Function: %p. New Function: %p",
        hook->hook_address,
        hook->original_function,
        hook->new_function
        );
    *(hook->hook_address) = hook->new_function;
    enable_write_protection();

    list_add(&hook->list_node, hook_list);
    return hook;
}