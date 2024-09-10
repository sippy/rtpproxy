#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "fuzz_standalone.h"
#include "rfz_utils.h"
#include "rfz_command.h"
#include "rfz_chunk.h"

int
LLVMFuzzerInitialize(int *_argc, char ***_argv)
{

    return RTPPInitialize();
}

int
LLVMFuzzerTestOneInput(const char *data, size_t size)
{
    struct rfz_chunk chunk = {.rem_size = size, .rem_data = data};

    do {
        chunk = rfz_get_chunk(chunk.rem_data, chunk.rem_size);
        ExecuteRTPPCommand(&gconf, chunk.data, chunk.size, 0);
    } while (chunk.rem_size > 1);
    assert(ExecuteRTPPCommand(&gconf, "X", 1, 0) == 0);
    return (0);
}
