#include "fuzz_standalone.h"
#include "fuzz_rtpp_utils.h"

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
        ExecuteRTPPCommand(&gconf, chunk.data, chunk.size);
    } while (chunk.rem_size > 1);
    assert(ExecuteRTPPCommand(&gconf, "X", 1) == 0);
    return (0);
}
