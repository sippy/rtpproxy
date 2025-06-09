#include <sys/socket.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <threads.h>
#include <unistd.h>

#include "rtpp_types.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_log_stand.h"
#include "rtpp_log_obj.h"
#include "rtpp_endian.h"
#include "rtpp_time.h"
#include "rtpp_ssrc.h"
#include "rtp_info.h"
#include "rtp.h"
#include "rtp_packet.h"
#include "rtp_analyze.h"
#include "rtpp_analyzer.h"

#include "fuzz_standalone.h"

int
LLVMFuzzerTestOneInput(const char *data, size_t size)
{
    static thread_local struct rtpp_log *log;
    static thread_local struct rtpp_analyzer *rap;
    struct rtp_packet *pktp;

    if (size > MAX_RPKT_LEN)
        return (0);

    if (log == NULL) {
        log = rtpp_log_ctor("rtpproxy", NULL, LF_REOPEN);
        assert(log != NULL);
        rap = rtpp_analyzer_ctor(log);
        assert(rap != NULL);
    }

    pktp = rtp_packet_alloc();
    assert(pktp != NULL);
    pktp->size = size;
    memcpy(pktp->data.buf, data, size);

    CALL_SMETHOD(rap, update, pktp);
    RTPP_OBJ_DECREF(pktp);
    return (0);
}
