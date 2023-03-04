#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "rtpp_sbuf.h"
#include "rtcp2json.h"

#include "fuzz_standalone.h"

int
LLVMFuzzerTestOneInput(const char *rtcp_data, size_t rtcp_dlen)
{
    struct rtpp_sbuf *sbp;

    sbp = rtpp_sbuf_ctor(512);
    assert (sbp != NULL);
#if 0
    for (size_t i = 0; i < rtcp_dlen; i++) {
        char bf[3];
        sprintf(bf, "%.2x", rtcp_data[i]);
        write(STDERR_FILENO, bf, 2);
    }
    write(STDERR_FILENO, "\n", 1);
    fsync(STDERR_FILENO);
#endif
    rtcp2json(sbp, rtcp_data, rtcp_dlen);
    rtpp_sbuf_dtor(sbp);

    return (0);
}
