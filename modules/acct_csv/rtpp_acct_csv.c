/*
 * Copyright (c) 2006-2016 Sippy Software, Inc., http://www.sippysoft.com
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <inttypes.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

#include "rtpp_ssrc.h"
#include "rtpa_stats.h"
#include "rtpp_monotime.h"
#include "rtpp_types.h"
#include "rtpp_analyzer.h"
#include "rtpp_pcount.h"
#include "rtpp_pcnt_strm.h"
#include "rtpp_acct_pipe.h"
#include "rtpp_acct.h"
#include "rtpp_module.h"
#include "rtpp_netaddr.h"
#include "rtpp_network.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_log.h"
#include "rtpp_log_obj.h"

#define SSRC_STRLEN 11

struct rtpp_mod_acct_face {
   char rtp_adr[MAX_AP_STRBUF];
   char rtcp_adr[MAX_AP_STRBUF];
   char ssrc[SSRC_STRLEN];
};

struct rtpp_module_priv {
   int fd;
   pid_t pid;
   struct stat stt;
   char fname[MAXPATHLEN + 1];
   double next_hupd_ts;
   char node_id[_POSIX_HOST_NAME_MAX + 1];
   struct rtpp_mod_acct_face o;
   struct rtpp_mod_acct_face a;
};

/* Bump this when some changes are made */
#define RTPP_METRICS_VERSION	"1.2"

#define HNAME_REFRESH_IVAL	1.0

static struct rtpp_module_priv *rtpp_acct_csv_ctor(struct rtpp_cfg_stable *);
static void rtpp_acct_csv_dtor(struct rtpp_module_priv *);
static void rtpp_acct_csv_do(struct rtpp_module_priv *, struct rtpp_acct *);
static off_t rtpp_acct_csv_lockf(int);
static void rtpp_acct_csv_unlockf(int, off_t);

#define API_FUNC(fname, asize) {.func = (fname), .argsize = (asize)}

struct rtpp_minfo rtpp_module = {
    .name = "acct_csv",
    .ver = MI_VER_INIT(),
    .ctor = rtpp_acct_csv_ctor,
    .dtor = rtpp_acct_csv_dtor,
    .on_session_end = API_FUNC(rtpp_acct_csv_do, rtpp_acct_OSIZE())
};

#if 0
/* Quick hack to check and see if periodic updates work as expected */
static int
gethostname_test(char *name, size_t namelen)
{
    static int i = 0;

    if (i < 2) {
        strcpy(name, "foo.bar.com");
        i++;
        return 0;
    }
    return (gethostname(name, namelen));
}

#define gethostname gethostname_test
#endif

static const char *
rtpp_acct_get_nid(struct rtpp_module_priv *pvt, struct rtpp_acct *ap)
{

    if (pvt->next_hupd_ts == 0.0 || pvt->next_hupd_ts < ap->destroy_ts) {
        if (gethostname(pvt->node_id, sizeof(pvt->node_id)) == 0) {
            pvt->next_hupd_ts = ap->destroy_ts + HNAME_REFRESH_IVAL;
        }
    }
    return (pvt->node_id);
}

#define SFX_INO "_ino"
#define SFX_INA "_ina"

#define SFX_O   "_o"
#define SFX_A   "_a"

#define PFX_GEN "rtpp_"


#define RVER_NM     "rec_ver"
#define NID_NM      PFX_GEN "node_id"
#define PID_NM      PFX_GEN "pid"
#define SID_NM      "sess_uid"
#define CID_NM      "call_id"
#define PT_NAME     "rtpa_pt_last"
#define PT_NM_O     PT_NAME SFX_INO
#define PT_NM_A     PT_NAME SFX_INA
#define PFX_RTP     "rtp_"
#define PFX_RTCP    "rtcp_"
#define RM_IP_NM "rmt_ip"
#define RM_PT_NM "rmt_pt"
#define R_RM_NM_O PFX_GEN PFX_RTP RM_IP_NM SFX_O
#define R_RM_NM_A PFX_GEN PFX_RTP RM_IP_NM SFX_A
#define C_RM_NM_O PFX_GEN PFX_RTCP RM_IP_NM SFX_O
#define C_RM_NM_A PFX_GEN PFX_RTCP RM_IP_NM SFX_A
#define R_RM_PT_NM_O PFX_GEN PFX_RTP RM_PT_NM SFX_O
#define R_RM_PT_NM_A PFX_GEN PFX_RTP RM_PT_NM SFX_A
#define C_RM_PT_NM_O PFX_GEN PFX_RTCP RM_PT_NM SFX_O
#define C_RM_PT_NM_A PFX_GEN PFX_RTCP RM_PT_NM SFX_A

#define HLD_CNT_NM   "hld_cnt"
#define HLD_STS_NM   "hld_sts"
#define HLD_CNT_NM_O PFX_GEN HLD_CNT_NM SFX_O
#define HLD_CNT_NM_A PFX_GEN HLD_CNT_NM SFX_A
#define HLD_STS_NM_O PFX_GEN HLD_STS_NM SFX_O
#define HLD_STS_NM_A PFX_GEN HLD_STS_NM SFX_A

#define RVER_FMT    "%s"
#define NID_FMT     "%s"
#define PID_FMT     "%d"
#define SID_FMT     "%" PRId64
#define PT_FMT      "%d"
#define LSSRC_FMT   "%s"
#define SNCHG_FMT   "%lu"
#define RM_FMT      "%s"
#define SEP         ","
#define HLD_STS_FMT "%s"
#define HLD_CNT_FMT "%d"

static int
rtpp_acct_csv_open(struct rtpp_module_priv *pvt)
{
    char *buf;
    int len, pos;

    if (pvt->fd != -1) {
        close(pvt->fd);
    }
    pvt->fd = open(pvt->fname, O_WRONLY | O_APPEND | O_CREAT, DEFFILEMODE);
    if (pvt->fd == -1) {
        mod_elog(RTPP_LOG_ERR, "can't open '%s' for writing", pvt->fname);
        goto e0;
    }
    pos = rtpp_acct_csv_lockf(pvt->fd);
    if (pos < 0) {
        mod_elog(RTPP_LOG_ERR, "can't lock '%s'", pvt->fname);
        goto e1;
    }
    if (fstat(pvt->fd, &pvt->stt) < 0) {
        mod_elog(RTPP_LOG_ERR, "can't get stats for '%s'", pvt->fname);
        goto e2;
    }
    if (pvt->stt.st_size == 0) {
        buf = NULL;
        len = mod_asprintf(&buf, RVER_NM SEP NID_NM SEP PID_NM SEP SID_NM
          SEP CID_NM SEP
          "from_tag,setup_ts,teardown_ts,first_rtp_ts_ino,last_rtp_ts_ino,"
          "first_rtp_ts_ina,last_rtp_ts_ina,rtp_npkts_ina,rtp_npkts_ino,"
          "rtp_nrelayed,rtp_ndropped,rtcp_npkts_ina,rtcp_npkts_ino,"
          "rtcp_nrelayed,rtcp_ndropped,rtpa_nsent_ino,rtpa_nrcvd_ino,"
          "rtpa_ndups_ino,rtpa_nlost_ino,rtpa_perrs_ino,"
          "rtpa_ssrc_last_ino,rtpa_ssrc_cnt_ino" SEP PT_NM_O SEP
          "rtpa_nsent_ina,rtpa_nrcvd_ina,rtpa_ndups_ina,rtpa_nlost_ina,"
          "rtpa_perrs_ina,rtpa_ssrc_last_ina,rtpa_ssrc_cnt_ina" SEP PT_NM_A SEP
          "rtpa_jitter_last_ino,rtpa_jitter_max_ino,rtpa_jitter_avg_ino,"
          "rtpa_jitter_last_ina,rtpa_jitter_max_ina,rtpa_jitter_avg_ina" SEP
          R_RM_NM_O SEP R_RM_PT_NM_O SEP R_RM_NM_A SEP R_RM_PT_NM_A SEP
          C_RM_NM_O SEP C_RM_PT_NM_O SEP C_RM_NM_A SEP C_RM_PT_NM_A SEP
          HLD_STS_NM_O SEP HLD_STS_NM_A SEP HLD_CNT_NM_O SEP HLD_CNT_NM_A "\n");
        if (len <= 0) {
            if (len == 0 && buf != NULL) {
                goto e3;
            }
            goto e2;
        }
        write(pvt->fd, buf, len);
        mod_free(buf);
    }
    rtpp_acct_csv_unlockf(pvt->fd, pos);
    return (0);

e3:
    mod_free(buf);
e2:
    rtpp_acct_csv_unlockf(pvt->fd, pos);
e1:
    close(pvt->fd);
e0:
    return (-1);
}

static struct rtpp_module_priv *
rtpp_acct_csv_ctor(struct rtpp_cfg_stable *cfsp)
{
    struct rtpp_module_priv *pvt;

    pvt = mod_zmalloc(sizeof(struct rtpp_module_priv));
    if (pvt == NULL) {
        goto e0;
    }
    pvt->pid = getpid();
    if (cfsp->cwd_orig == NULL) {
        snprintf(pvt->fname, sizeof(pvt->fname), "%s", "rtpproxy_acct.csv");
    } else {
        snprintf(pvt->fname, sizeof(pvt->fname), "%s/%s", cfsp->cwd_orig,
          "rtpproxy_acct.csv");
    }
    if (gethostname(pvt->node_id, sizeof(pvt->node_id)) != 0) {
        strcpy(pvt->node_id, "UNKNOWN");
    }
    pvt->fd = -1;
    if (rtpp_acct_csv_open(pvt) == -1) {
        goto e1;
    }
    return (pvt);

e1:
    mod_free(pvt);
e0:
    return (NULL);
}

static void
rtpp_acct_csv_dtor(struct rtpp_module_priv *pvt)
{

    close(pvt->fd);
    mod_free(pvt);
    return;
}

#define ES_IF_NULL(s) ((s) == NULL ? "" : s)
#define MT2RT_NZ(mt) ((mt) == 0.0 ? 0.0 : dtime2rtime(mt))

static void
format_ssrc(struct rtpp_ssrc *sp, char *sbuf, size_t sblen)
{

    if (sp->inited) {
        snprintf(sbuf, sblen, SSRC_FMT, sp->val);
    } else {
        sbuf[0] = '\0';
    }
}

static void
format_netaddr(struct rtpp_netaddr *nap_rtp, struct rtpp_netaddr *nap_rtcp,
  struct rtpp_mod_acct_face *afp)
{

    if (CALL_SMETHOD(nap_rtp, isempty)) {
        sprintf(afp->rtp_adr, ",");
    } else {
        CALL_SMETHOD(nap_rtp, sip_print, afp->rtp_adr, sizeof(afp->rtp_adr),
          ',');
    }
    if (CALL_SMETHOD(nap_rtcp, isempty)) {
        sprintf(afp->rtcp_adr, ",");
    } else {
        CALL_SMETHOD(nap_rtcp, sip_print, afp->rtcp_adr, sizeof(afp->rtcp_adr),
          ',');
    }
}

#define FMT_BOOL(x) ((x == 0) ? "f" : "t")

static void
rtpp_acct_csv_do(struct rtpp_module_priv *pvt, struct rtpp_acct *acct)
{
    char *buf;
    int len, pos, rval;
    struct stat stt;

    buf = NULL;
    rval = stat(pvt->fname, &stt);
    if (rval != -1) {
        if (stt.st_dev != pvt->stt.st_dev || stt.st_ino != pvt->stt.st_ino) {
            rtpp_acct_csv_open(pvt);
        }
    } else if (rval == -1 && errno == ENOENT) {
        rtpp_acct_csv_open(pvt);
    }
    pos = rtpp_acct_csv_lockf(pvt->fd);
    if (pos < 0) {
        return;
    }

    format_ssrc(&acct->rasta->last_ssrc, pvt->a.ssrc, sizeof(pvt->a.ssrc));
    format_ssrc(&acct->rasto->last_ssrc, pvt->o.ssrc, sizeof(pvt->o.ssrc));
    format_netaddr(acct->rtp.a.rem_addr, acct->rtcp.a.rem_addr, &pvt->a);
    format_netaddr(acct->rtp.o.rem_addr, acct->rtcp.o.rem_addr, &pvt->o);
    len = mod_asprintf(&buf, RVER_FMT SEP NID_FMT SEP PID_FMT SEP SID_FMT SEP
      "%s,%s,%f,%f,%f,%f,%f,%f,%lu,%lu,"
      "%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu" SEP LSSRC_FMT SEP SNCHG_FMT SEP
      PT_FMT SEP "%lu,%lu,%lu,%lu,%lu" SEP LSSRC_FMT SEP SNCHG_FMT SEP PT_FMT SEP
      "%f,%f,%f,%f,%f,%f" SEP RM_FMT SEP RM_FMT SEP RM_FMT SEP RM_FMT SEP
      HLD_STS_FMT SEP HLD_STS_FMT SEP HLD_CNT_FMT SEP HLD_CNT_FMT "\n",
      RTPP_METRICS_VERSION, rtpp_acct_get_nid(pvt, acct),
      pvt->pid, acct->seuid, ES_IF_NULL(acct->call_id), ES_IF_NULL(acct->from_tag),
      MT2RT_NZ(acct->init_ts), MT2RT_NZ(acct->destroy_ts), MT2RT_NZ(acct->rtp.o.ps->first_pkt_rcv),
      MT2RT_NZ(acct->rtp.o.ps->last_pkt_rcv), MT2RT_NZ(acct->rtp.a.ps->first_pkt_rcv),
      MT2RT_NZ(acct->rtp.a.ps->last_pkt_rcv), acct->rtp.a.ps->npkts_in, acct->rtp.o.ps->npkts_in,
      acct->rtp.pcnts->nrelayed, acct->rtp.pcnts->ndropped, acct->rtcp.a.ps->npkts_in,
      acct->rtcp.o.ps->npkts_in, acct->rtcp.pcnts->nrelayed, acct->rtcp.pcnts->ndropped,
      acct->rasto->psent, acct->rasto->precvd, acct->rasto->pdups, acct->rasto->plost,
      acct->rasto->pecount, pvt->o.ssrc, acct->rasto->ssrc_changes, acct->rasto->last_pt,
      acct->rasta->psent, acct->rasta->precvd, acct->rasta->pdups, acct->rasta->plost,
      acct->rasta->pecount, pvt->a.ssrc, acct->rasta->ssrc_changes, acct->rasta->last_pt,
      acct->jrasto->jlast, acct->jrasto->jmax, acct->jrasto->javg,
      acct->jrasta->jlast, acct->jrasta->jmax, acct->jrasta->javg,
      pvt->o.rtp_adr, pvt->a.rtp_adr, pvt->o.rtcp_adr, pvt->a.rtcp_adr,
      FMT_BOOL(acct->rtp.o.hld_stat.status), FMT_BOOL(acct->rtp.a.hld_stat.status),
      acct->rtp.o.hld_stat.cnt, acct->rtp.a.hld_stat.cnt);
    if (len <= 0) {
        if (len == 0 && buf != NULL) {
            mod_free(buf);
        }
        return;
    }
    write(pvt->fd, buf, len);
    rtpp_acct_csv_unlockf(pvt->fd, pos);
    mod_free(buf);
}

static off_t
rtpp_acct_csv_lockf(int fd)
{
    struct flock l;
    int rval;

    memset(&l, '\0', sizeof(l));
    l.l_whence = SEEK_CUR;
    l.l_type = F_WRLCK;
    do {
        rval = fcntl(fd, F_SETLKW, &l);
    } while (rval == -1 && errno == EINTR);
    if (rval == -1) {
        return (-1);
    }
    return lseek(fd, 0, SEEK_CUR);
}

static void
rtpp_acct_csv_unlockf(int fd, off_t offset)
{
    struct flock l;
    int rval;

    memset(&l, '\0', sizeof(l));
    l.l_whence = SEEK_SET;
    l.l_start = offset;
    l.l_type = F_UNLCK;
    do {
        rval = fcntl(fd, F_SETLKW, &l);
    } while (rval == -1 && errno == EINTR);
}
