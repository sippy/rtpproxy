#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "SPMCQueue.h"

static void
expect_pop_many(SPMCQueue* queue, uintptr_t start, size_t count)
{
    void* values[16] = {0};
    size_t total = 0;

    while (total < count) {
        size_t popped = try_pop_many(queue, values, count - total);

        assert(popped > 0);
        for (size_t i = 0; i < popped; i++) {
            assert((uintptr_t)values[i] == start + total + i);
        }
        total += popped;
    }
}

struct pre_push_ctx {
    uintptr_t seen[16];
    size_t count;
};

struct kv_push_ctx {
    uintptr_t seen[16];
    size_t count;
};

static void
record_pre_push(void *cb_arg, void *value)
{
    struct pre_push_ctx *ctx;

    ctx = cb_arg;
    ctx->seen[ctx->count++] = (uintptr_t)value;
}

static void *
get_even_value(void *cb_arg, void *key)
{
    struct kv_push_ctx *ctx;
    uintptr_t value;

    ctx = cb_arg;
    value = (uintptr_t)key;
    ctx->seen[ctx->count++] = value;
    if ((value & 1) != 0) {
        return NULL;
    }
    return (void *)(value + 100);
}

static void
test_try_push_many_basic(void)
{
    SPMCQueue* queue = create_queue(8);
    void* values[] = {(void*)1, (void*)2, (void*)3};

    assert(queue != NULL);
    assert(try_push_many(queue, values, 0) == 0);
    assert(try_push_many(queue, values, 3) == 3);
    expect_pop_many(queue, 1, 3);
    destroy_queue(queue);
}

static void
test_try_push_many_partial_refresh_and_wrap(void)
{
    SPMCQueue* queue = create_queue(8);
    void* first[] = {
        (void*)1, (void*)2, (void*)3, (void*)4,
        (void*)5, (void*)6, (void*)7, (void*)8,
    };
    void* second[] = {(void*)9, (void*)10, (void*)11, (void*)12, (void*)13};

    assert(queue != NULL);
    assert(try_push_many(queue, first, 8) == 8);
    expect_pop_many(queue, 1, 5);

    assert(try_push_many(queue, second, 5) == 5);
    expect_pop_many(queue, 6, 8);
    destroy_queue(queue);
}

static void
test_try_push_many_partial_when_full(void)
{
    SPMCQueue* queue = create_queue(4);
    void* first[] = {(void*)1, (void*)2, (void*)3};
    void* second[] = {(void*)4, (void*)5, (void*)6};

    assert(queue != NULL);
    assert(try_push_many(queue, first, 3) == 3);
    assert(try_push_many(queue, second, 3) == 1);
    expect_pop_many(queue, 1, 4);
    assert(try_pop_many(queue, second, 1) == 0);
    destroy_queue(queue);
}

static void
test_try_push_many_pre_wrap(void)
{
    SPMCQueue* queue = create_queue(4);
    void* first[] = {(void*)1, (void*)2, (void*)3};
    void* second[] = {(void*)4, (void*)5, (void*)6};
    struct pre_push_ctx ctx = {0};

    assert(queue != NULL);
    assert(try_push_many(queue, first, 3) == 3);
    expect_pop_many(queue, 1, 2);

    assert(try_push_many_pre(queue, second, 3, record_pre_push, &ctx) == 3);
    assert(ctx.count == 3);
    assert(ctx.seen[0] == 4);
    assert(ctx.seen[1] == 5);
    assert(ctx.seen[2] == 6);

    expect_pop_many(queue, 3, 4);
    destroy_queue(queue);
}

static void
test_try_push_many_pre_partial_when_full(void)
{
    SPMCQueue* queue = create_queue(4);
    void* first[] = {(void*)1, (void*)2, (void*)3};
    void* second[] = {(void*)4, (void*)5, (void*)6};
    struct pre_push_ctx ctx = {0};

    assert(queue != NULL);
    assert(try_push_many(queue, first, 3) == 3);
    assert(try_push_many_pre(queue, second, 3, record_pre_push, &ctx) == 1);
    assert(ctx.count == 1);
    assert(ctx.seen[0] == 4);

    expect_pop_many(queue, 1, 4);
    assert(try_pop_many(queue, second, 1) == 0);
    destroy_queue(queue);
}

static void
test_try_push_many_kv_filters_and_consumes_all(void)
{
    SPMCQueue* queue = create_queue(8);
    void* keys[] = {
        (void*)1, (void*)2, (void*)3, (void*)4,
        (void*)5, (void*)6,
    };
    void* values[8] = {0};
    struct kv_push_ctx ctx = {0};

    assert(queue != NULL);
    assert(try_push_many_kv(queue, keys, 6, get_even_value, &ctx) == 6);
    assert(ctx.count == 6);
    assert(try_pop_many(queue, values, 8) == 3);
    assert((uintptr_t)values[0] == 102);
    assert((uintptr_t)values[1] == 104);
    assert((uintptr_t)values[2] == 106);
    destroy_queue(queue);
}

static void
test_try_push_many_kv_stops_at_capacity(void)
{
    SPMCQueue* queue = create_queue(4);
    void* first[] = {(void*)1, (void*)2, (void*)3};
    void* keys[] = {(void*)4, (void*)5, (void*)6};
    struct kv_push_ctx ctx = {0};

    assert(queue != NULL);
    assert(try_push_many(queue, first, 3) == 3);
    assert(try_push_many_kv(queue, keys, 3, get_even_value, &ctx) == 1);
    assert(ctx.count == 1);
    expect_pop_many(queue, 1, 3);
    expect_pop_many(queue, 104, 1);
    destroy_queue(queue);
}

int
main(void)
{
    test_try_push_many_basic();
    test_try_push_many_partial_refresh_and_wrap();
    test_try_push_many_partial_when_full();
    test_try_push_many_pre_wrap();
    test_try_push_many_pre_partial_when_full();
    test_try_push_many_kv_filters_and_consumes_all();
    test_try_push_many_kv_stops_at_capacity();
    return 0;
}
