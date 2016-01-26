#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>
#include <inttypes.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rtpp_monotime.h"
#include "rtpp_types.h"
#include "rtpp_pcount.h"
#include "rtpp_pcnt_strm.h"
#include "rtpp_acct.h"
#include "rtpp_module.h"

struct rtpp_module_priv {
   int fd;
   pid_t pid;
   int foo;
   char *baz;
};

static struct rtpp_module_priv *rtpp_csv_acct_ctor(struct rtpp_cfg_stable *);
static void rtpp_csv_acct_dtor(struct rtpp_module_priv *);
static void rtpp_csv_acct_do(struct rtpp_module_priv *, struct rtpp_acct *);

#define API_FUNC(fname, asize) {.func = (fname), .argsize = (asize)}

struct rtpp_minfo rtpp_module = {
    .name = "csv_acct",
    .ver = MI_VER_INIT(),
    .ctor = rtpp_csv_acct_ctor,
    .dtor = rtpp_csv_acct_dtor,
    .on_session_end = API_FUNC(rtpp_csv_acct_do, rtpp_acct_OSIZE())
};

static struct rtpp_module_priv *
rtpp_csv_acct_ctor(struct rtpp_cfg_stable *cfsp)
{
    struct rtpp_module_priv *pvt;
    char *buf;
    int len;

    pvt = mod_zmalloc(sizeof(struct rtpp_module_priv));
    if (pvt == NULL) {
        goto e0;
    }
    pvt->fd = open("rtpproxy_acct.csv", O_WRONLY | O_APPEND | O_CREAT, DEFFILEMODE);
    if (pvt->fd == -1) {
        goto e1;
    }
    pvt->pid = getpid();
    pvt->foo = 123456;
    pvt->baz = mod_strdup("hello, world!");
    buf = NULL;
    len = mod_asprintf(&buf, "rtpp_pid,sess_uid,call_id,from_tag,setup_ts,"
      "teardown_ts,first_rtp_ts_ino,last_rtp_ts_ino,first_rtp_ts_ina,"
      "last_rtp_ts_ina,rtp_npkts_ina,rtp_npkts_ino,rtp_nrelayed,rtp_ndropped,"
      "rtcp_npkts_ina,rtcp_npkts_ino,rtcp_nrelayed,rtcp_ndropped\n");
    if (len <= 0) {
        if (len == 0 && buf != NULL) {
            goto e3;            
        }
        goto e2;
    }
    write(pvt->fd, buf, len);
    mod_free(buf);
    return (pvt);

e3:
    mod_free(buf);
e2:
    close(pvt->fd);
e1:
    mod_free(pvt);
e0:
    return (NULL);
}

static void
rtpp_csv_acct_dtor(struct rtpp_module_priv *pvt)
{

    assert(pvt->foo == 123456);
    assert(strcmp(pvt->baz, "hello, world!") == 0);
    mod_free(pvt->baz);
    close(pvt->fd);
    mod_free(pvt);
    return;
}

#define ES_IF_NULL(s) ((s) == NULL ? "" : s)
#define MT2RT_NZ(mt) ((mt) == 0.0 ? 0.0 : dtime2rtime(mt))

static void
rtpp_csv_acct_do(struct rtpp_module_priv *pvt, struct rtpp_acct *acct)
{
    char *buf;
    int len;

    buf = NULL;
    len = mod_asprintf(&buf, "%d,%" PRId64 ",%s,%s,%f,%f,%f,%f,%f,%f,%lu,%lu,"
      "%lu,%lu,%lu,%lu,%lu,%lu\n",
      pvt->pid, acct->seuid, ES_IF_NULL(acct->call_id), ES_IF_NULL(acct->from_tag),
      MT2RT_NZ(acct->init_ts), MT2RT_NZ(acct->destroy_ts), MT2RT_NZ(acct->pso_rtp->first_pkt_rcv),
      MT2RT_NZ(acct->pso_rtp->last_pkt_rcv), MT2RT_NZ(acct->psa_rtp->first_pkt_rcv),
      MT2RT_NZ(acct->psa_rtp->last_pkt_rcv), acct->psa_rtp->npkts_in, acct->pso_rtp->npkts_in,
      acct->pcnts_rtp->nrelayed, acct->pcnts_rtp->ndropped, acct->psa_rtcp->npkts_in,
      acct->pso_rtcp->npkts_in, acct->pcnts_rtcp->nrelayed, acct->pcnts_rtcp->ndropped);
    if (len <= 0) {
        if (len == 0 && buf != NULL) {
            mod_free(buf);
        }
        return;
    }
    write(pvt->fd, buf, len);
    mod_free(buf);
}
