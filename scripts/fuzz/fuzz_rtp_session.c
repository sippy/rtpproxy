#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz_standalone.h"

#define HAVE_CONFIG_H 1
#include "config_pp.h"

#include "rtpp_types.h"
#include "rtpp_cfg.h"
#include "rtp.h"
#include "rtpp_time.h"
#include "rtpp_codeptr.h"
#include "rtp_packet.h"
#include "rtpp_session.h"
#include "rtpp_pipe.h"
#include "rtpp_proc.h"
#include "rtpp_network.h"
#include "rtpp_stream.h"
#include "rtpp_ttl.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_command.h"
#include "rtpp_weakref.h"
#include "rtpp_hash_table.h"
#include "advanced/packet_processor.h"
#include "advanced/pproc_manager.h"

#include "rfz_chunk.h"
#include "rfz_utils.h"
#include "rfz_command.h"

static struct {
    sem_t wi_proc_done;
} fuzz_ctx;

static void
fuzz_ctx_dtor(void)
{
    ExecuteRTPPCommand(&gconf, "X", 1, 0);
    sem_destroy(&fuzz_ctx.wi_proc_done);
}

static const char * const setup_script[] = {
    #include "fuzz_rtp_session.setup"
    NULL
};

static int
ExecuteScript(void)
{
    char line[RTPP_CMD_BUFLEN];

    for (int i = 0; setup_script[i] != NULL; i++) {
        const char *cp = setup_script[i];
        int size = strlen(cp);
        memcpy(line, cp, size + 1);
        int r = ExecuteRTPPCommand(&gconf, line, size, 0);
        if (r != 0)
            return (-1);
    }
    return (0);
}

int
LLVMFuzzerInitialize(int *_argc, char ***_argv)
{
    RTPPInitializeParams.ttl = "60";
    int r = RTPPInitialize();

    if (r != 0)
        goto e0;
    if (sem_init(&fuzz_ctx.wi_proc_done, 0, 0) != 0)
        goto e0;
    if (ExecuteScript() != 0)
        goto e1;
    if (ExecuteRTPPCommand(&gconf, "X", 1, 0) != 0)
        goto e1;
    atexit(fuzz_ctx_dtor);
    return (0);
e1:
    sem_destroy(&fuzz_ctx.wi_proc_done);
e0:
    return (-1);
}

struct foreach_args {
    const char *data;
    size_t size;
    struct rtpp_proc_rstats *rsp;
    int nwait;
};

static void
wi_proc_complete(void *arg)
{
    sem_post(&fuzz_ctx.wi_proc_done);
}

static int
proc_foreach(void *dp, void *ap)
{
    struct foreach_args *fap;
    const struct rtpp_session *sp;
    rtpp_refcnt_dtor_t wpd_f = (rtpp_refcnt_dtor_t)&wi_proc_complete;

    fap = (struct foreach_args *)ap;
    /*
     * This method does not need us to bump ref, since we are in the
     * locked context of the rtpp_hash_table, which holds its own ref.
     */
    sp = (const struct rtpp_session *)dp;

    for (int i=0; i < 2; i++) {
        struct sockaddr *rap;
        struct rtp_packet *pktp = rtp_packet_alloc();
        assert (pktp != NULL);
        void *olddata = CALL_SMETHOD(pktp->rcnt, getdata);
        CALL_SMETHOD(pktp->rcnt, attach, wpd_f, olddata);
        rap = sstosa(&pktp->raddr);
        memcpy(rap, fap->data, sizeof(struct sockaddr_in));
        rap->sa_family = AF_INET;
        pktp->size = fap->size - sizeof(struct sockaddr_in);
        memcpy(pktp->data.buf, fap->data + sizeof(struct sockaddr_in), pktp->size);
        struct rtpp_stream *istp = sp->rtp->stream[i],
                           *ostp = sp->rtp->stream[i ^ 1];
        struct pkt_proc_ctx pktx = {.strmp_in = istp,
                                    .strmp_out = ostp,
                                    .rsp = fap->rsp,
                                    .pktp = pktp};
        CALL_SMETHOD(istp->pproc_manager, handleat, &pktx, _PPROC_ORD_EMPTY);
        fap->nwait += 1;
    }
    return (RTPP_HT_MATCH_CONT);
}

int
LLVMFuzzerTestOneInput(const char *data, size_t size)
{
    static struct rtpp_proc_rstats rs = {0};
    sem_t *wpdp = &fuzz_ctx.wi_proc_done;
    struct {
        union {
            struct {
                uint8_t reseed:1;
            };
            uint8_t value;
        };
    } op_flags;

    if (size < 2)
        return (0);

    op_flags.value = data[0];
    data += 1;
    size -= 1;

    if (op_flags.reseed) {
        SeedRNGs();
    }

    assert(ExecuteScript() == 0);

    struct rfz_chunk chunk = {.rem_size = size, .rem_data = data};
    struct foreach_args fa = {.rsp = &rs};

    do {
        chunk = rfz_get_chunk(chunk.rem_data, chunk.rem_size);
        if (chunk.size < sizeof(struct sockaddr_in))
            break;
        if (chunk.size > sizeof(struct sockaddr_in) + MAX_RPKT_LEN)
            break;
        fa.data = chunk.data;
        fa.size = chunk.size;
        CALL_SMETHOD(gconf.cfsp->sessions_ht, foreach, proc_foreach, (void *)&fa, NULL);
    } while (chunk.rem_size > 1);
    for (int i = 0; i < fa.nwait; i++)
        sem_wait(wpdp);

    assert(ExecuteRTPPCommand(&gconf, "X", 1, 0) == 0);
    return (0);
}
