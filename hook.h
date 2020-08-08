#pragma once

typedef enum{
    HOOK__ATTACHED,
    HOOK__DETACHED
} HOOK__status_t;

typedef struct{
    void ** hook_address;
    void * original_function;
    void * new_function;
    HOOK__status_t status;
} HOOK__hook_t;

void HOOK__init(HOOK__hook_t * hook, void * handler, void ** hook_address);
void HOOK__detach(HOOK__hook_t * hook);
void HOOK__attach(HOOK__hook_t * hook);