#pragma once

#include <asm/syscall.h>
#include <linux/types.h>
#include <linux/list.h>

typedef struct{
    void ** hook_address;
    void * original_function;
    void * new_function;
    struct list_head list_node;
} HOOK__hook_t;

void HOOK__detach(HOOK__hook_t * hook);
HOOK__hook_t * HOOK__attach_to_syscall(struct list_head * hook_list, sys_call_ptr_t * handler, __u32 syscall_index);
HOOK__hook_t * HOOK__attach(struct list_head * hook_list, void * handler, void ** hook_address);
struct list_head HOOK__init_list(void);