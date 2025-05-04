#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdlib.h>

#include "SPMCQueue.h"

#if !defined(CACHE_LINE_SIZE)
#define CACHE_LINE_SIZE 64 // Common cache line size
#endif

#define RESERVED_BITS 4

struct SPMCQueue {
    size_t capacity;
    uint64_t mask;
    _Alignas(CACHE_LINE_SIZE) _Atomic uint64_t writeIdx;
    _Alignas(CACHE_LINE_SIZE) uint64_t readIdxCache;
    _Alignas(CACHE_LINE_SIZE) _Atomic uint64_t readIdx;
    _Alignas(CACHE_LINE_SIZE) _Atomic uint64_t writeIdxCache;
    _Alignas(CACHE_LINE_SIZE) void* slots[0]; // FAM for void pointer type slots
};

// Function to create a new queue
SPMCQueue *
create_queue(size_t capacity)
{
    SPMCQueue* queue = (SPMCQueue*) aligned_alloc(CACHE_LINE_SIZE, sizeof(SPMCQueue) + sizeof(void*) * capacity);
    if (queue == NULL) {
        return NULL;
    }
    queue->capacity = capacity;
    queue->mask = capacity - 1;
    atomic_init(&queue->writeIdx, 0);
    atomic_init(&queue->readIdx, 0);
    atomic_init(&queue->writeIdxCache, 0);
    queue->readIdxCache = 0;
    return queue;
}

// Function to destroy a queue
void destroy_queue(SPMCQueue* queue) {
    free(queue);
}

#define LOAD_R_IDX(q, mo) \
    (atomic_load_explicit(&(q)->readIdx,             (mo)))
#define LOAD_W_IDX(q, mo) \
    (atomic_load_explicit(&(q)->writeIdx,            (mo)))
#define LOAD_W_CACHE(q)   \
    (atomic_load_explicit(&(q)->writeIdxCache,       memory_order_relaxed))
#define UPDATE_R_IDX(q, ov, nv) \
    (atomic_compare_exchange_weak_explicit(&(q)->readIdx, &(ov), (nv), \
                                                     memory_order_release, \
                                                     memory_order_relaxed))
#define UPDATE_W_IDX(q, v) \
    (atomic_store_explicit(&(q)->writeIdx,      (v), memory_order_release))
#define UPDATE_W_CACHE(q, v) \
    (atomic_store_explicit(&(q)->writeIdxCache, (v), memory_order_relaxed))

// Function to push an element into the queue.
// This should be called from a single producer thread.
bool
try_push(SPMCQueue* queue, void* value)
{
    uint64_t writeIdx = LOAD_W_IDX(queue, memory_order_relaxed);
    uint64_t nextWriteIdx = writeIdx + 1;
    // If the queue is not full
    uint64_t newsize = nextWriteIdx - queue->readIdxCache;
    if(newsize <= queue->capacity) {
        queue->slots[writeIdx & queue->mask] = value;
        UPDATE_W_IDX(queue, nextWriteIdx);
        return true;
    }
    // Update the cached index and retry
    queue->readIdxCache = LOAD_R_IDX(queue, memory_order_acquire);
    newsize = nextWriteIdx - queue->readIdxCache;
    if (newsize <= queue->capacity) {
        queue->slots[writeIdx & queue->mask] = value;
        UPDATE_W_IDX(queue, nextWriteIdx);
        return true;
    }
    // Queue was full
    return false;
}

// Function to pop an element from the queue.
// This can be called from multiple consumer threads.
bool
try_pop(SPMCQueue* queue, void** value)
{
    uint64_t readIdx, newReadIdx;
    void *rval;
    do {
        readIdx = LOAD_R_IDX(queue, memory_order_relaxed);
        // If the queue is not empty
        uint64_t writeIdxCache = LOAD_W_CACHE(queue);
        if (readIdx >= writeIdxCache) {
            // Update the cached index and retry
            writeIdxCache = LOAD_W_IDX(queue, memory_order_acquire);
            UPDATE_W_CACHE(queue, writeIdxCache);
            if(readIdx == writeIdxCache) {
                // Queue was empty
                return 0;
            }
            assert(readIdx < writeIdxCache);
        }
        newReadIdx = readIdx + 1;
        rval  = queue->slots[readIdx & queue->mask];
    } while (!UPDATE_R_IDX(queue, readIdx, newReadIdx));
    *value = rval;
    return true;
}

size_t
try_pop_many(SPMCQueue* queue, void** values, size_t howmany)
{
    uint64_t readIdx, newReadIdx;

    do {
        readIdx = LOAD_R_IDX(queue, memory_order_relaxed);
        // If the queue is not empty
        uint64_t writeIdxCache = LOAD_W_CACHE(queue);
        if (readIdx >= writeIdxCache) {
            // Update the cached index and retry
            writeIdxCache = LOAD_W_IDX(queue, memory_order_acquire);
            UPDATE_W_CACHE(queue, writeIdxCache);
            if(readIdx == writeIdxCache) {
                // Queue was empty
                return 0;
            }
            assert(readIdx < writeIdxCache);
        }
        newReadIdx = readIdx + howmany;
        if (newReadIdx > writeIdxCache)
            newReadIdx = writeIdxCache;
        for (uint64_t i = readIdx; i < newReadIdx; i++) {
            values[i - readIdx] = queue->slots[i & queue->mask];
        }
    } while (!UPDATE_R_IDX(queue, readIdx, newReadIdx));
    return (newReadIdx - readIdx);
}
