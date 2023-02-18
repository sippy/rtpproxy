#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

#include "rtpp_sbuf.h"
#include "rtcp2json.h"

int
LLVMFuzzerTestOneInput(const char *rtcp_data, size_t rtcp_dlen)
{
    struct rtpp_sbuf *sbp;

    sbp = rtpp_sbuf_ctor(512);
    assert (sbp != NULL);
    rtcp2json(sbp, rtcp_data, rtcp_dlen);
    rtpp_sbuf_dtor(sbp);

    exit(0);
}
