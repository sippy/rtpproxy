#pragma once

#include <stdbool.h>
#include <stddef.h>

#if defined(_WIN32) || defined(__CYGWIN__)
# if defined(SPMC_BUILD_SHARED)
#  if defined(SPMC_EXPORTS)
#   define SPMC_API __declspec(dllexport)
#  else
#   define SPMC_API __declspec(dllimport)
#  endif
# else
#  define SPMC_API
# endif
#elif defined(SPMC_BUILD_SHARED)
# define SPMC_API __attribute__((visibility("default")))
#else
# define SPMC_API
#endif

struct SPMCQueue;

typedef struct SPMCQueue SPMCQueue;
typedef void (*SPMCPrePushFunc)(void *cb_arg, void *value);
typedef void *(*SPMCGetPushFunc)(void *cb_arg, void *key);

SPMC_API SPMCQueue* create_queue(size_t capacity);
SPMC_API void destroy_queue(SPMCQueue* queue);

SPMC_API bool try_push(SPMCQueue* queue, void* value);
SPMC_API size_t try_push_many(SPMCQueue* queue, void** values, size_t howmany);
SPMC_API size_t try_push_many_pre(SPMCQueue* queue, void** values, size_t howmany,
  SPMCPrePushFunc pre_queue, void *cb_arg);
SPMC_API size_t try_push_many_kv(SPMCQueue* queue, void** keys, size_t howmany,
  SPMCGetPushFunc get_value, void *cb_arg);
SPMC_API bool try_pop(SPMCQueue* queue, void** value);
SPMC_API size_t try_pop_many(SPMCQueue* queue, void** values, size_t howmany);
