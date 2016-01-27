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

#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <inttypes.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rtpp_monotime.h"
#include "rtpp_types.h"
#include "rtpp_analyzer.h"
#include "rtpp_pcount.h"
#include "rtpp_pcnt_strm.h"
#include "rtpp_acct.h"
#include "rtpp_module.h"

struct rtpp_module_priv {
   int fd;
   pid_t pid;
   struct stat stt;
   const char *fname;
};

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
        goto e0;
    }
    pos = rtpp_acct_csv_lockf(pvt->fd);
    if (pos < 0) {
        goto e1;
    }
    if (fstat(pvt->fd, &pvt->stt) < 0) {
        goto e2;
    }
    if (pvt->stt.st_size == 0) {
        buf = NULL;
        len = mod_asprintf(&buf, "rtpp_pid,sess_uid,call_id,from_tag,setup_ts,"
          "teardown_ts,first_rtp_ts_ino,last_rtp_ts_ino,first_rtp_ts_ina,"
          "last_rtp_ts_ina,rtp_npkts_ina,rtp_npkts_ino,rtp_nrelayed,rtp_ndropped,"
          "rtcp_npkts_ina,rtcp_npkts_ino,rtcp_nrelayed,rtcp_ndropped,"
          "rtpa_nsent_ino,rtpa_nrcvd_ino,rtpa_ndups_ino,rtpa_nlost_ino,"
          "rtpa_perrs_ino,rtpa_ssrc_last_ino,rtpa_ssrc_cnt_ino,rtpa_nsent_ina,"
          "rtpa_nrcvd_ina,rtpa_ndups_ina,rtpa_nlost_ina,rtpa_perrs_ina,"
          "rtpa_ssrc_last_ina,rtpa_ssrc_cnt_ina\n");
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
    pvt->fname = "rtpproxy_acct.csv";
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

    len = mod_asprintf(&buf, "%d,%" PRId64 ",%s,%s,%f,%f,%f,%f,%f,%f,%lu,%lu,"
      "%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu," SSRC_FMT ",%lu,%lu,%lu,%lu,"
      "%lu,%lu," SSRC_FMT ",%lu\n",
      pvt->pid, acct->seuid, ES_IF_NULL(acct->call_id), ES_IF_NULL(acct->from_tag),
      MT2RT_NZ(acct->init_ts), MT2RT_NZ(acct->destroy_ts), MT2RT_NZ(acct->pso_rtp->first_pkt_rcv),
      MT2RT_NZ(acct->pso_rtp->last_pkt_rcv), MT2RT_NZ(acct->psa_rtp->first_pkt_rcv),
      MT2RT_NZ(acct->psa_rtp->last_pkt_rcv), acct->psa_rtp->npkts_in, acct->pso_rtp->npkts_in,
      acct->pcnts_rtp->nrelayed, acct->pcnts_rtp->ndropped, acct->psa_rtcp->npkts_in,
      acct->pso_rtcp->npkts_in, acct->pcnts_rtcp->nrelayed, acct->pcnts_rtcp->ndropped,
      acct->rasto->psent, acct->rasto->precvd, acct->rasto->pdups, acct->rasto->plost,
      acct->rasto->pecount, acct->rasto->last_ssrc, acct->rasto->ssrc_changes,
      acct->rasta->psent, acct->rasta->precvd, acct->rasta->pdups, acct->rasta->plost,
      acct->rasta->pecount, acct->rasta->last_ssrc, acct->rasta->ssrc_changes);
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
