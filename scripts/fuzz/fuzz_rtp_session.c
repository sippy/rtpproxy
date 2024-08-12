#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <semaphore.h>

#include "fuzz_standalone.h"
#include "fuzz_rtpp_utils.h"

#include "rtp.h"
#include "rtp_packet.h"
#include "rtpp_session.h"
#include "rtpp_pipe.h"
#include "rtpp_proc.h"
#include "rtpp_stream.h"
#include "advanced/packet_processor.h"
#include "advanced/pproc_manager.h"

static struct {
    sem_t wi_proc_done;
} fuzz_ctx;

static void
fuzz_ctx_dtor(void)
{
    sem_destroy(&fuzz_ctx.wi_proc_done);
}

int
LLVMFuzzerInitialize(int *_argc, char ***_argv)
{
    char line[RTPP_CMD_BUFLEN];
    RTPPInitializeParams.debug_level = "dbug";
    int r = RTPPInitialize();
    if (r != 0)
        goto e0;
    FILE *file = fopen("fuzz_rtp_session.setup", "r");
    if (file == NULL)
        goto e0;
    if (sem_init(&fuzz_ctx.wi_proc_done, 0, 0) != 0)
	goto e1;
    while (fgets(line, sizeof(line), file)) {
        int size = strlen(line);
        r = ExecuteRTPPCommand(&gconf, line, size);
        if (r != 0)
            goto e2;
    }
    fclose(file);
    atexit(fuzz_ctx_dtor);
    return (0);
e2:
    sem_destroy(&fuzz_ctx.wi_proc_done);
e1:
    fclose(file);
e0:
    return (-1);
}

struct foreach_args {
    struct rtp_packet *pktp;
    struct rtpp_proc_rstats *rsp;
};

static int
proc_foreach(void *dp, void *ap)
{
    const struct foreach_args *fap;
    const struct rtpp_session *sp;

    fap = (const struct foreach_args *)ap;
    /*
     * This method does not need us to bump ref, since we are in the
     * locked context of the rtpp_hash_table, which holds its own ref.
     */
    sp = (const struct rtpp_session *)dp;

    for (int i=0; i < 2; i++) {
        struct rtpp_stream *istp = sp->rtp->stream[i],
                           *ostp = sp->rtp->stream[i ^ 1];
        struct pkt_proc_ctx pktx = {.strmp_in = istp,
                                    .strmp_out = ostp,
                                    .rsp = fap->rsp,
                                    .pktp = fap->pktp};
        RTPP_OBJ_INCREF(fap->pktp);
        CALL_SMETHOD(istp->pproc_manager, handleat, &pktx, _PPROC_ORD_EMPTY);
    }
    return (RTPP_HT_MATCH_CONT);
}

static void
wi_proc_complete(void *arg)
{
    sem_post(&fuzz_ctx.wi_proc_done);
}

int
LLVMFuzzerTestOneInput(const char *data, size_t size)
{
    struct foreach_args fa;
    static struct rtpp_proc_rstats rs = {0};
    rtpp_refcnt_dtor_t wpd_f = (rtpp_refcnt_dtor_t)&wi_proc_complete;
    sem_t *wpdp = &fuzz_ctx.wi_proc_done;

    if (size <= sizeof(struct sockaddr_in))
        return (0);
    if (size > sizeof(struct sockaddr_in) + MAX_RPKT_LEN)
        return (0);

    fa.pktp = rtp_packet_alloc();
    assert (fa.pktp != NULL);
    void *olddata = CALL_SMETHOD(fa.pktp->rcnt, getdata);
    CALL_SMETHOD(fa.pktp->rcnt, attach, wpd_f, olddata);
    fa.rsp = &rs;
    memcpy(&fa.pktp->raddr, data, sizeof(struct sockaddr_in));
    size -= sizeof(struct sockaddr_in);
    data += sizeof(struct sockaddr_in);
    fa.pktp->size = size;
    memcpy(fa.pktp->data.buf, data, size);

    CALL_SMETHOD(gconf.cfsp->sessions_ht, foreach, proc_foreach, (void *)&fa, NULL);
    RTPP_OBJ_DECREF(fa.pktp);
    sem_wait(wpdp);
    return (0);
}
