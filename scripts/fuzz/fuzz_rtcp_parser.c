#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "rtpp_types.h"
#include "rtp_packet.h"
#include "rtpp_module.h"
#include "rtpp_module_if_static.h"
#include "rtpp_sbuf.h"
#include "rtcp2json.h"

#include "fuzz_standalone.h"

static const struct rtpp_minfo_fset minfo_fset = {
    ._malloc = &malloc,
    ._realloc = &realloc,
    ._free  = &free
};

__attribute__((constructor)) void
fuzz_rtcp_parser_init()
{
    const struct rtpp_minfo *mip;

    mip = rtpp_static_modules_lookup("acct_rtcp_hep");
    assert(mip != NULL);
    *mip->fn = minfo_fset;
}

int
LLVMFuzzerTestOneInput(const char *rtcp_data, size_t rtcp_dlen)
{
    struct rtpp_sbuf *sbp;

    if (rtcp_dlen > MAX_RPKT_LEN)
        return (0);

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
