/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2014 Sippy Software, Inc., http://www.sippysoft.com
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
 * $Id$
 *
 */

#include <assert.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>


#include "rtp.h"
#include "rtp_resizer.h"
#include "rtp_server.h"
#include "rtpp_log.h"
#include "rtpp_network.h"
#include "rtpp_notify.h"
#include "rtpp_bulk_netio.h"
#include "rtpp_proc.h"
#include "rtpp_record.h"
#include "rtpp_session.h"
#include "rtpp_util.h"

struct rtpp_proc_out_lst {
    struct rtpp_session *sp;
    int ridx;
    struct rtp_packet *packet;
};

struct rtpp_proc_ready_lst {
    struct rtpp_session *sp;
    int ridx;
};

static void send_packets(struct cfg *, struct rtpp_proc_out_lst *, int, \
  struct rtpp_bnet_opipe *);

void
process_rtp_servers(struct cfg *cf, double dtime, struct rtpp_bnet_opipe *op)
{
    int j, sidx, len, skipfd;
    struct rtpp_session *sp;
    struct rtp_packet *pkt;

    skipfd = 0;
    for (j = 0; j < cf->rtp_nsessions; j++) {
	sp = cf->rtp_servers[j];
	if (sp == NULL) {
	    skipfd++;
	    continue;
	}
	if (skipfd > 0) {
	    cf->rtp_servers[j - skipfd] = cf->rtp_servers[j];
	    sp->sridx = j - skipfd;
	}
	for (sidx = 0; sidx < 2; sidx++) {
	    if (sp->rtps[sidx] == NULL || sp->addr[sidx] == NULL)
		continue;
            for (;;) {
                pkt = rtp_server_get(sp->rtps[sidx], dtime, &len);
                if (pkt == NULL) {
                    if (len == RTPS_EOF) {
                        rtpp_bulk_netio_opipe_flush(op);
                        rtp_server_free(sp->rtps[sidx]);
                        sp->rtps[sidx] = NULL;
                        if (sp->rtps[0] == NULL && sp->rtps[1] == NULL) {
                            assert(cf->rtp_servers[sp->sridx] == sp);
                            cf->rtp_servers[sp->sridx] = NULL;
                            sp->sridx = -1;
                        }
                    } else if (len != RTPS_LATER) {
                        /* XXX some error, brag to logs */
                    }
                    break;
		}
		cf->packets_out++;
                rtpp_bulk_netio_opipe_send_pkt(op, sp->fds[sidx], sp->addr[sidx], \
                  SA_LEN(sp->addr[sidx]), pkt);
	    }
	}
    }
    rtpp_bulk_netio_opipe_flush(op);
    cf->rtp_nsessions -= skipfd;
}

static void
rxmit_packets(struct cfg *cf, struct rtpp_proc_ready_lst *rready, int rlen,
  double dtime, int drain_repeat, struct rtpp_bnet_opipe *op)
{
    int ndrain, i, port, rn, ridx, rout_len;
    struct rtp_packet *packet = NULL;
    struct rtpp_session *sp;
    struct rtpp_proc_out_lst rout[10];

    /* Repeat since we may have several packets queued on the same socket */
    ndrain = -1;
    rout_len = 0;
    for (rn = 0; rn < rlen; rn += (ndrain > 0) ? 0 : 1) {
        if (ndrain < 0) {
            ndrain = drain_repeat - 1;
        } else {
            ndrain -= 1;
        }
	if (packet != NULL)
	    rtp_packet_free(packet);

        sp = rready[rn].sp;
        ridx = rready[rn].ridx;

	packet = rtp_recv(sp->fds[ridx]);
	if (packet == NULL) {
            /* Move on to the next session */
            ndrain = -1;
	    continue;
        }
	packet->laddr = sp->laddr[ridx];
	packet->rport = sp->ports[ridx];
	packet->rtime = dtime;
	cf->packets_in++;

	i = 0;

	port = ntohs(satosin(&packet->raddr)->sin_port);

	if (sp->addr[ridx] != NULL) {
	    /* Check that the packet is authentic, drop if it isn't */
	    if (sp->asymmetric[ridx] == 0) {
		if (memcmp(sp->addr[ridx], &packet->raddr, packet->rlen) != 0) {
		    if (sp->canupdate[ridx] == 0) {
			/*
			 * Continue, since there could be good packets in
			 * queue.
			 */
                        ndrain += 1;
			continue;
		    }
		    /* Signal that an address has to be updated */
		    i = 1;
		} else if (sp->canupdate[ridx] != 0) {
		    if (sp->last_update[ridx] == 0 ||
		      dtime - sp->last_update[ridx] > UPDATE_WINDOW) {
			rtpp_log_write(RTPP_LOG_INFO, sp->log,
			  "%s's address latched in: %s:%d (%s)",
			  (ridx == 0) ? "callee" : "caller",
			  addr2char(sstosa(&packet->raddr)), port,
			  (sp->rtp == NULL) ? "RTP" : "RTCP");
			sp->canupdate[ridx] = 0;
		    }
		}
	    } else {
		/*
		 * For asymmetric clients don't check
		 * source port since it may be different.
		 */
		if (!ishostseq(sp->addr[ridx], sstosa(&packet->raddr))) {
		    /*
		     * Continue, since there could be good packets in
		     * queue.
		     */
                    ndrain += 1;
		    continue;
                }
	    }
	    sp->pcount[ridx]++;
	} else {
	    sp->pcount[ridx]++;
	    sp->addr[ridx] = malloc(packet->rlen);
	    if (sp->addr[ridx] == NULL) {
		sp->pcount[3]++;
		rtpp_log_write(RTPP_LOG_ERR, sp->log,
		  "can't allocate memory for remote address - "
		  "removing session");
                rtpp_bulk_netio_opipe_flush(op);
		remove_session(cf, GET_RTP(sp));
		/* Move on to the next session, sp is invalid now */
                ndrain = -1;
		continue;
	    }
	    /* Signal that an address have to be updated. */
	    i = 1;
	}

	/*
	 * Update recorded address if it's necessary. Set "untrusted address"
	 * flag in the session state, so that possible future address updates
	 * from that client won't get address changed immediately to some
	 * bogus one.
	 */
	if (i != 0) {
	    sp->untrusted_addr[ridx] = 1;
	    memcpy(sp->addr[ridx], &packet->raddr, packet->rlen);
	    if (sp->prev_addr[ridx] == NULL || memcmp(sp->prev_addr[ridx],
	      &packet->raddr, packet->rlen) != 0) {
	        sp->canupdate[ridx] = 0;
	    }

	    rtpp_log_write(RTPP_LOG_INFO, sp->log,
	      "%s's address filled in: %s:%d (%s)",
	      (ridx == 0) ? "callee" : "caller",
	      addr2char(sstosa(&packet->raddr)), port,
	      (sp->rtp == NULL) ? "RTP" : "RTCP");

	    /*
	     * Check if we have updated RTP while RTCP is still
	     * empty or contains address that differs from one we
	     * used when updating RTP. Try to guess RTCP if so,
	     * should be handy for non-NAT'ed clients, and some
	     * NATed as well.
	     */
	    if (sp->rtcp != NULL && (sp->rtcp->addr[ridx] == NULL ||
	      !ishostseq(sp->rtcp->addr[ridx], sstosa(&packet->raddr)))) {
		if (sp->rtcp->addr[ridx] == NULL) {
		    sp->rtcp->addr[ridx] = malloc(packet->rlen);
		    if (sp->rtcp->addr[ridx] == NULL) {
			sp->pcount[3]++;
			rtpp_log_write(RTPP_LOG_ERR, sp->log,
			  "can't allocate memory for remote address - "
			  "removing session");
                        rtpp_bulk_netio_opipe_flush(op);
			remove_session(cf, sp);
			/* Move on to the next session, sp is invalid now */
                        ndrain = -1;
			continue;
		    }
		}
		memcpy(sp->rtcp->addr[ridx], &packet->raddr, packet->rlen);
		satosin(sp->rtcp->addr[ridx])->sin_port = htons(port + 1);
		/* Use guessed value as the only true one for asymmetric clients */
		sp->rtcp->canupdate[ridx] = NOT(sp->rtcp->asymmetric[ridx]);
		rtpp_log_write(RTPP_LOG_INFO, sp->log, "guessing RTCP port "
		  "for %s to be %d",
		  (ridx == 0) ? "callee" : "caller", port + 1);
	    }
	}

	if (sp->resizers[ridx] != NULL)
	    rtp_resizer_enqueue(sp->resizers[ridx], &packet);
	if (packet != NULL) {
            rout[rout_len].sp = sp;
            rout[rout_len].ridx = ridx;
            rout[rout_len].packet = packet;
            packet = NULL;
            rout_len += 1;
            if (rout_len == 4) {
	        send_packets(cf, rout, rout_len, op);
                rout_len = 0;
            }
        }
    }
    if (packet != NULL)
        rtp_packet_free(packet);
    if (rout_len > 0) {
        send_packets(cf, rout, rout_len, op);
        rout_len = 0;
    }
}

static void
send_packets(struct cfg *cf, struct rtpp_proc_out_lst *rout, int rout_len, \
  struct rtpp_bnet_opipe *op)
{
    int sidx, ridx, rout_idx;
    struct rtpp_session *sp;
    struct rtp_packet *packet;

    for (rout_idx = 0; rout_idx < rout_len; rout_idx += 1) {
        sp = rout[rout_idx].sp;
        ridx = rout[rout_idx].ridx;
        packet = rout[rout_idx].packet;

        GET_RTP(sp)->ttl[ridx] = cf->stable.max_ttl;

        /* Select socket for sending packet out. */
        sidx = (ridx == 0) ? 1 : 0;

        if (sp->rrcs[ridx] != NULL && GET_RTP(sp)->rtps[ridx] == NULL)
            rwrite(sp, sp->rrcs[ridx], packet, sp->addr[sidx], sp->laddr[sidx],
              sp->ports[sidx], sidx);

        /*
         * Check that we have some address to which packet is to be
         * sent out, drop otherwise.
         */
        if (sp->addr[sidx] == NULL || GET_RTP(sp)->rtps[sidx] != NULL) {
            rtp_packet_free(packet);
	    sp->pcount[3]++;
        } else {
	    sp->pcount[2]++;
	    cf->packets_out++;
            rtpp_bulk_netio_opipe_send_pkt(op, sp->fds[sidx],  sp->addr[sidx], \
              SA_LEN(sp->addr[sidx]), packet);
        }
    }
}

static void
drain_socket(int rfd)
{
    struct rtp_packet *packet;

    for (;;) {
        packet = rtp_recv(rfd);
        if (packet == NULL)
            break;
        rtp_packet_free(packet);
    }
}

void
process_rtp(struct cfg *cf, double dtime, int alarm_tick, int drain_repeat, \
  struct rtpp_bnet_opipe *op)
{
    int readyfd, skipfd, ridx, rready_len, rout_len;
    struct rtpp_session *sp;
    struct rtp_packet *packet;
    struct rtpp_proc_ready_lst rready[10];
    struct rtpp_proc_out_lst rout[10];

    /* Relay RTP/RTCP */
    skipfd = 0;
    rready_len = 0;
    rout_len = 0;
    pthread_mutex_lock(&cf->sessinfo.lock);
    for (readyfd = 0; readyfd < cf->sessinfo.nsessions; readyfd++) {
	sp = cf->sessinfo.sessions[readyfd];

	if (alarm_tick != 0 && sp != NULL && sp->rtcp != NULL &&
	  sp->sidx[0] == readyfd) {
	    if (get_ttl(sp) == 0) {
		rtpp_log_write(RTPP_LOG_INFO, sp->log, "session timeout");
		rtpp_notify_schedule(cf, sp);
                rtpp_bulk_netio_opipe_flush(op);
		remove_session(cf, sp);
	    } else {
		if (sp->ttl[0] != 0)
		    sp->ttl[0]--;
		if (sp->ttl[1] != 0)
		    sp->ttl[1]--;
	    }
	}

	if (cf->sessinfo.pfds[readyfd].fd == -1) {
	    /* Deleted session, count and move one */
	    skipfd++;
	    continue;
	}

	/* Find index of the call leg within a session */
	for (ridx = 0; ridx < 2; ridx++)
	    if (cf->sessinfo.pfds[readyfd].fd == sp->fds[ridx])
		break;
	/*
	 * Can't happen.
	 */
	assert(ridx != 2);

	/* Compact pfds[] and sessions[] by eliminating removed sessions */
	if (skipfd > 0) {
	    cf->sessinfo.pfds[readyfd - skipfd] = cf->sessinfo.pfds[readyfd];
	    cf->sessinfo.sessions[readyfd - skipfd] = cf->sessinfo.sessions[readyfd];
	    sp->sidx[ridx] = readyfd - skipfd;
	}

	if (sp->complete != 0) {
	    if ((cf->sessinfo.pfds[readyfd].revents & POLLIN) != 0) {
                rready[rready_len].sp = sp;
                rready[rready_len].ridx = ridx;
                rready_len += 1;
            }
            if (rready_len == 4) {
		rxmit_packets(cf, rready, rready_len, dtime, drain_repeat, op);
                rready_len = 0;
            }
	    if (sp->resizers[ridx] != NULL) {
		while ((packet = rtp_resizer_get(sp->resizers[ridx], dtime)) != NULL) {
                    rout[rout_len].sp = sp;
                    rout[rout_len].ridx = ridx;
                    rout[rout_len].packet = packet;
                    rout_len += 1;
                    if (rout_len == 4) {
		        send_packets(cf, rout, rout_len, op);
                        rout_len = 0;
                    }
		}
	    }
	} else if ((cf->sessinfo.pfds[readyfd].revents & POLLIN) != 0) {
#if RTPP_DEBUG
            rtpp_log_write(RTPP_LOG_DBUG, cf->stable.glog, "Draining socket %d", cf->sessinfo.pfds[readyfd].fd);
#endif
            drain_socket(cf->sessinfo.pfds[readyfd].fd);
        }
    }
    if (rready_len > 0) {
        rxmit_packets(cf, rready, rready_len, dtime, drain_repeat, op);
        rready_len = 0;
    }
    if (rout_len > 0) {
        send_packets(cf, rout, rout_len, op);
        rout_len = 0;
    }
    /* Trim any deleted sessions at the end */
    cf->sessinfo.nsessions -= skipfd;
    rtpp_bulk_netio_opipe_flush(op);
    pthread_mutex_unlock(&cf->sessinfo.lock);
}
