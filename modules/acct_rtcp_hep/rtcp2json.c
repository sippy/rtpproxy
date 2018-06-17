/*
 * (c) 1998-2018 by Columbia University; all rights reserved
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "rtcp.h"
#include "rtpp_sbuf.h"
#include "rtcp2json.h"

#if 0
typedef uint32_t member_t;

/*
* Show SDES information for one member.
*/
void member_sdes(FILE *out, member_t m, rtcp_sdes_type_t t, char *b, int len)
{
  static struct {
    rtcp_sdes_type_t t;
    const char *name;
  } map[] = {
    {RTCP_SDES_END,    "end"},
    {RTCP_SDES_CNAME,  "CNAME"},
    {RTCP_SDES_NAME,   "NAME"},
    {RTCP_SDES_EMAIL,  "EMAIL"},
    {RTCP_SDES_PHONE,  "PHONE"},
    {RTCP_SDES_LOC,    "LOC"},
    {RTCP_SDES_TOOL,   "TOOL"},
    {RTCP_SDES_NOTE,   "NOTE"},
    {RTCP_SDES_PRIV,   "PRIV"},
    {11,               "SOURCE"},
    {0,0}
  };
  int i;
  char num[10];

  sprintf(num, "%d", t);
  for (i = 0; map[i].name; i++) {
    if (map[i].t == t) break;
  }
  fprintf(out, "%s=\"%*.*s\" ",
    map[i].name ? map[i].name : num, len, len, b);
} /* member_sdes */

/*
* Parse one SDES chunk (one SRC description). Total length is 'len'.
* Return new buffer position or zero if error.
*/
static char *rtp_read_sdes(FILE *out, char *b, int len)
{
  rtcp_sdes_item_t *rsp;
  uint32_t src = *(uint32_t *)b;
  int total_len = 0;

  len -= 4;  /* subtract SSRC from available bytes */
  if (len <= 0) {
    return 0;
  }
  rsp = (rtcp_sdes_item_t *)(b + 4);
  for (; rsp->type; rsp = (rtcp_sdes_item_t *)((char *)rsp + rsp->length + 2)) {
    member_sdes(out, src, rsp->type, rsp->data, rsp->length);
    total_len += rsp->length + 2;
  }
  if (total_len >= len) {
    fprintf(stderr,
      "Remaining length of %d bytes for SSRC item too short (has %u bytes)\n",
      len, total_len);
    return 0;
  }
  b = (char *)rsp + 1;
  /* skip padding */
  return b + ((4 - ((int)b & 0x3)) & 0x3);
} /* rtp_read_sdes */
#endif

#define RSW_REST(exitcode, sbc, format, args...)         \
  {                                                      \
    int rval;                                            \
    for (;;) {                                           \
      rval = rtpp_sbuf_write((sbc), (format), ## args);  \
      if (rval == SBW_OK)                                \
          break;                                         \
      if (rval == SBW_ERR)                               \
          return (exitcode);                             \
      assert(rval == SBW_SHRT);                          \
      if (rtpp_sbuf_extend((sbc), (sbc)->alen * 2) != 0) \
          return (exitcode);                             \
    }                                                    \
  }
      

/*
* Return length parsed, -1 on error.
*/
int rtcp2json(struct rtpp_sbuf *out, void *buf, int len)
{
  rtcp_t *r;         /* RTCP header */
  int i;
#if 0
  char *cp;
#endif

  r = (rtcp_t *)buf;
  /* Backwards compatibility: VAT header. */
  if (r->common.version != RTP_VERSION) {
#if 0
    fprintf(out, "invalid version %d\n", r->common.version);
#endif
    return -1;
  }

#if 0
  fprintf(out, "\n");
#endif
  while (len > 0) {
    len -= (ntohs(r->common.length) + 1) << 2;
    if (len < 0) {
      /* something wrong with packet format */
#if 0
      fprintf(out, "Illegal RTCP packet length %d words.\n",
         ntohs(r->common.length));
#endif
      return -1;
    }

    switch (r->common.pt) {
    case RTCP_SR:
      RSW_REST(-1, out, "{\n \"ssrc\": %lu,\n",
        (unsigned long)ntohl(r->r.rr.ssrc));
      RSW_REST(-1, out, " \"sender_information\": {\n  \"ntp_timestamp_sec\": %lu,\n  \"ntp_timestamp_usec\": %lu,\n  \"rtp_timestamp\": %lu,\n  \"packets\": %lu,\n  \"octets\": %lu\n },\n",
        (unsigned long)ntohl(r->r.sr.ntp_sec),
        (unsigned long)ntohl(r->r.sr.ntp_frac),
        (unsigned long)ntohl(r->r.sr.rtp_ts),
        (unsigned long)ntohl(r->r.sr.psent),
        (unsigned long)ntohl(r->r.sr.osent));
      RSW_REST(-1, out, " \"type\": %lu,\n", (unsigned long)r->common.pt);
      if (r->common.count > 0)
        RSW_REST(-1, out, " \"report_blocks\": [\n");
      for (i = 0; i < r->common.count; i++) {
        if (i > 0)
          RSW_REST(-1, out, "  ,\n");
        RSW_REST(-1, out, "  {\n   \"source_ssrc\": %lu,\n   \"fraction_lost\": %lu,\n   \"packets_lost\": %ld,\n   \"highest_seq_no\": %lu,\n   \"ia_jitter\": %lu,\n   \"lsr\": %lu,\n   \"dlsr\": %lu\n  }\n",
         (unsigned long)ntohl(r->r.sr.rr[i].ssrc),
         (unsigned long)r->r.sr.rr[i].fraction,
         (long)RTCP_GET_LOST(&r->r.sr.rr[i]),
         (unsigned long)ntohl(r->r.sr.rr[i].last_seq),
         (unsigned long)ntohl(r->r.sr.rr[i].jitter),
         (unsigned long)ntohl(r->r.sr.rr[i].lsr),
         (unsigned long)ntohl(r->r.sr.rr[i].dlsr));
      }
      if (r->common.count > 0)
        RSW_REST(-1, out, " ],\n");
      RSW_REST(-1, out, " \"report_count\": %lu\n", (unsigned long)r->common.count);
      RSW_REST(-1, out, "}");
      break;

    case RTCP_RR:
      RSW_REST(-1, out, "{\n \"ssrc\": %lu,\n",
        (unsigned long)ntohl(r->r.rr.ssrc));
      RSW_REST(-1, out, " \"type\": %lu,\n", (unsigned long)r->common.pt);
      if (r->common.count > 0)
        RSW_REST(-1, out, " \"report_blocks\": [\n");
      for (i = 0; i < r->common.count; i++) {
        if (i > 0)
          RSW_REST(-1, out, "  ,\n");
        RSW_REST(-1, out, "  {\n   \"source_ssrc\": %lu,\n   \"fraction_lost\": %lu,\n   \"packets_lost\": %ld,\n   \"highest_seq_no\": %lu,\n   \"ia_jitter\": %lu,\n   \"lsr\": %lu,\n   \"dlsr\": %lu\n  }\n",
          (unsigned long)ntohl(r->r.rr.rr[i].ssrc),
          (unsigned long)r->r.sr.rr[i].fraction,
          (long)RTCP_GET_LOST(&r->r.rr.rr[i]),
          (unsigned long)ntohl(r->r.rr.rr[i].last_seq),
          (unsigned long)ntohl(r->r.rr.rr[i].jitter),
          (unsigned long)ntohl(r->r.rr.rr[i].lsr),
          (unsigned long)ntohl(r->r.rr.rr[i].dlsr));
      }
      if (r->common.count > 0)
        RSW_REST(-1, out, " ],\n");
      RSW_REST(-1, out, " \"report_count\": %lu,\n", (unsigned long)r->common.count);
      RSW_REST(-1, out, "}");
      break;

    case RTCP_SDES:
#if 0
      fprintf(out, " (SDES p=%d count=%d len=%d\n",
        r->common.p, r->common.count, ntohs(r->common.length));
      cp = (char *)&r->r.sdes;
      for (i = 0; i < r->common.count; i++) {
        int remaining = (ntohs(r->common.length) << 2) -
                        (cp - (char *)&r->r.sdes);
        fprintf(out, "  (src=0x%lx ",
          (unsigned long)ntohl(((struct rtcp_sdes *)cp)->src));
        if (remaining > 0) {
          cp = rtp_read_sdes(out, cp,
            (ntohs(r->common.length) << 2) - (cp - (char *)&r->r.sdes));
          if (!cp) return -1;
        }
        else {
          fprintf(stderr, "Missing at least %d bytes.\n", -remaining);
          return -1;
        }
        fprintf(out, ")\n");
      }
      fprintf(out, " )\n");
#endif
      break;

    case RTCP_BYE:
#if 0
      fprintf(out, " (BYE p=%d count=%d len=%d\n",
        r->common.p, r->common.count, ntohs(r->common.length));
      for (i = 0; i < r->common.count; i++) {
        fprintf(out, "  (ssrc[%d]=0x%0lx ", i,
          (unsigned long)ntohl(r->r.bye.src[i]));
      }
      fprintf(out, ")\n");
      if (ntohs(r->common.length) > r->common.count) {
        cp = (char *)&r->r.bye.src[r->common.count];
        fprintf(out, "reason=\"%*.*s\"", *cp, *cp, cp+1);
      }
      fprintf(out, " )\n");
#endif
      break;

    /* invalid type */
    default:
#if 0
      fprintf(out, "(? pt=%d src=0x%lx)\n", r->common.pt,
        (unsigned long)ntohl(r->r.sdes.src));
#endif
    break;
    }
    r = (rtcp_t *)((uint32_t *)r + ntohs(r->common.length) + 1);
  }

  return len;
} /* parse_control */
