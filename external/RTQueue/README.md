# RTQueue - Lock-Free SPMC Queue

A high-performance, lock-free Single Producer Multiple Consumers (SPMC) queue
implementation for real-time applications. The queue is "lossy" by design -
when full, the producer automatically drops the oldest items to make room for
new ones, ensuring non-blocking operation.

## Features

- **Lock-free**: Uses atomic operations for thread-safe access without locks
- **SPMC**: Single producer, multiple consumers architecture
- **Lossy by design**: Automatically drops old items when full to maintain
real-time performance
- **Cache-aligned**: Internal structure optimized to prevent false sharing
- **Cross-platform**: Supports Linux, macOS, Windows, and FreeBSD
- **Dual API**: Available as both C library and Python module

## Requirements

### Python
- Python 3.6 or higher
- C11-compatible compiler

### C
- C11-compatible compiler with atomics support
- CMake 3.10 or higher (for building tests and benchmarks)

## Installation

### Python Module

Install directly from source:

```bash
pip install .
```

Or for development:

```bash
pip install -e .
```

### C Library

Include the source files directly in your project:

```c
#include "src/SPMCQueue.h"
```

Link with `src/SPMCQueue.c` during compilation.

For building tests and benchmarks:

```bash
mkdir build
cd build
cmake ..
make
```

## Python API

### Basic Usage

```python
from LossyQueue import LossyQueue

# Create a queue (size must be a power of 2)
queue = LossyQueue(64)

# Producer: Put items into the queue
queue.put("message 1")
queue.put("message 2")
queue.put({"key": "value"})

# Consumer: Get items from the queue
item = queue.get()  # Returns the item or None if queue is empty
if item is not None:
    print(f"Received: {item}")
```

### Multi-threaded Example

```python
from LossyQueue import LossyQueue
import threading
import time

queue = LossyQueue(256)

def producer():
    """Single producer thread"""
    for i in range(1000):
        queue.put(f"message-{i}")
        time.sleep(0.001)

def consumer(name):
    """Multiple consumer threads"""
    while True:
        item = queue.get()
        if item is not None:
            print(f"{name} received: {item}")
        else:
            time.sleep(0.001)

# Start producer
producer_thread = threading.Thread(target=producer)
producer_thread.start()

# Start multiple consumers
consumers = []
for i in range(3):
    t = threading.Thread(target=consumer, args=(f"Consumer-{i}",), daemon=True)
    t.start()
    consumers.append(t)

producer_thread.join()
```

### API Reference

#### `LossyQueue(size)`
Constructor to create a new queue.

- **Parameters:**
  - `size` (int): Queue capacity. Must be a power of 2 (e.g., 64, 128, 256, 1024).
- **Raises:**
  - `ValueError`: If size is not a power of 2.
  - `RuntimeError`: If queue initialization fails.

#### `put(item)`
Add an item to the queue. If the queue is full, automatically removes the oldest item.

- **Parameters:**
  - `item`: Any Python object to store in the queue.
- **Returns:** None

#### `get()`
Retrieve and remove an item from the queue.

- **Returns:** The next item from the queue, or `None` if the queue is empty.

## C API

### Basic Usage

```c
#include <stdio.h>
#include "SPMCQueue.h"

int main() {
    // Create a queue (size must be a power of 2)
    SPMCQueue* queue = create_queue(64);
    if (queue == NULL) {
        fprintf(stderr, "Failed to create queue\n");
        return 1;
    }

    // Push items
    int value1 = 42;
    int value2 = 100;

    if (try_push(queue, &value1)) {
        printf("Pushed value1\n");
    }

    if (try_push(queue, &value2)) {
        printf("Pushed value2\n");
    }

    // Pop items
    void* item;
    if (try_pop(queue, &item)) {
        printf("Popped: %d\n", *(int*)item);
    }

    // Clean up
    destroy_queue(queue);
    return 0;
}
```

### Multi-threaded Example

```c
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include "SPMCQueue.h"

#define QUEUE_SIZE 1024
#define NUM_CONSUMERS 4

SPMCQueue* queue;

void* producer_thread(void* arg) {
    for (uintptr_t i = 0; i < 10000; i++) {
        while (!try_push(queue, (void*)i)) {
            // Queue full, try again (or handle overflow)
        }
    }
    return NULL;
}

void* consumer_thread(void* arg) {
    int id = *(int*)arg;
    size_t count = 0;

    while (1) {
        void* value;
        if (try_pop(queue, &value)) {
            printf("Consumer %d got: %lu\n", id, (uintptr_t)value);
            count++;
        }
    }
    return NULL;
}

int main() {
    queue = create_queue(QUEUE_SIZE);

    pthread_t prod, cons[NUM_CONSUMERS];
    int ids[NUM_CONSUMERS];

    // Start consumers
    for (int i = 0; i < NUM_CONSUMERS; i++) {
        ids[i] = i;
        pthread_create(&cons[i], NULL, consumer_thread, &ids[i]);
    }

    // Start producer
    pthread_create(&prod, NULL, producer_thread, NULL);

    pthread_join(prod, NULL);
    destroy_queue(queue);
    return 0;
}
```

### Batch Operations

```c
#include <stdio.h>
#include "SPMCQueue.h"

#define BATCH_SIZE 16

void batch_consumer_example(SPMCQueue* queue) {
    void* items[BATCH_SIZE];

    // Pop multiple items at once for better performance
    size_t count = try_pop_many(queue, items, BATCH_SIZE);

    printf("Popped %zu items in one batch\n", count);
    for (size_t i = 0; i < count; i++) {
        // Process items[i]
        printf("Item %zu: %lu\n", i, (uintptr_t)items[i]);
    }
}
```

### API Reference

#### `SPMCQueue* create_queue(size_t capacity)`
Create a new SPMC queue.

- **Parameters:**
  - `capacity`: Queue capacity. Must be a power of 2.
- **Returns:** Pointer to the queue, or `NULL` on failure.

#### `void destroy_queue(SPMCQueue* queue)`
Destroy a queue and free its memory.

- **Parameters:**
  - `queue`: Queue to destroy.

#### `bool try_push(SPMCQueue* queue, void* value)`
Attempt to push a value onto the queue.

- **Parameters:**
  - `queue`: The queue.
  - `value`: Pointer to store in the queue.
- **Returns:** `true` if successful, `false` if queue is full.

#### `bool try_pop(SPMCQueue* queue, void** value)`
Attempt to pop a value from the queue.

- **Parameters:**
  - `queue`: The queue.
  - `value`: Pointer to store the retrieved value.
- **Returns:** `true` if successful, `false` if queue is empty.

#### `size_t try_pop_many(SPMCQueue* queue, void** values, size_t howmany)`
Attempt to pop multiple values at once (batch operation).

- **Parameters:**
  - `queue`: The queue.
  - `values`: Array to store retrieved values.
  - `howmany`: Maximum number of items to pop.
- **Returns:** Number of items actually popped (0 to `howmany`).

## Performance Considerations

- Queue size should be a power of 2 for optimal performance
- Use larger queue sizes to reduce the chance of dropped items
- The `try_pop_many()` function is more efficient for high-throughput scenarios
- Internal structures are cache-line aligned to prevent false sharing
- No dynamic memory allocation during operation (all allocations happen at queue creation)

## License

BSD 2-Clause License

Copyright (c) 2023, Maksym Sobolyev

See [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

## Testing

Run Python tests:

```bash
python -m pytest python/test_lossyqueue.py
```

Run C benchmarks:

```bash
cd build
make
./spmc_bench_test
```
