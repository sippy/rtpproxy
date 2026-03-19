#pragma once

struct SPMCQueue;

typedef struct SPMCQueue SPMCQueue;

SPMCQueue* create_queue(size_t capacity);
void destroy_queue(SPMCQueue* queue);

bool try_push(SPMCQueue* queue, void* value);
bool try_pop(SPMCQueue* queue, void** value);
size_t try_pop_many(SPMCQueue* queue, void** values, size_t howmany);
