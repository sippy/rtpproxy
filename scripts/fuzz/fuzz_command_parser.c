#include "fuzz_standalone.h"
#include "fuzz_rtpp_utils.h"

int
LLVMFuzzerInitialize(int *_argc, char ***_argv)
{

    return RTPPInitialize();
}

int
LLVMFuzzerTestOneInput(const char *data, size_t size)
{

    ExecuteRTPPCommand(&gconf, data, size);
    return (0);
}
