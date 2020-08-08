#include "hook.h"
#include <asm/paravirt.h>
#include <asm/special_insns.h>

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


void HOOK__init(HOOK__hook_t * hook, void * handler, void ** hook_address)
{
    hook->hook_address = hook_address;
    hook->original_function = *hook_address;
    hook->new_function = handler;
    hook->status = HOOK__DETACHED;
}

void HOOK__detach(HOOK__hook_t * hook)
{
    if (HOOK__DETACHED == hook->status)
    {
        return;
    }
    disable_write_protection();
    *(hook->hook_address) = hook->original_function;
    printk(KERN_INFO "DEATACHING HOOK at address %p. OLD Function: %p. New Function: %p",
        hook->hook_address,
        hook->original_function,
        hook->new_function
        );
    enable_write_protection();
    hook->status = HOOK__DETACHED;
}

void HOOK__attach(HOOK__hook_t * hook)
{
    if (HOOK__ATTACHED == hook->status)
    {
        return;
    }
    disable_write_protection();
    printk(KERN_INFO "ATTACHING HOOK at address %p. OLD Function: %p. New Function: %p",
        hook->hook_address,
        hook->original_function,
        hook->new_function
        );
    *(hook->hook_address) = hook->new_function;
    enable_write_protection();
    hook->status = HOOK__ATTACHED;
}
