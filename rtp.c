#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "rtp.h"
#include "rtpp_util.h"

static struct rtp_packet *rtp_packet_pool = NULL; // linked list of free packets

struct rtp_packet *
rtp_packet_alloc()
{
    struct rtp_packet *pkt;

    pkt = rtp_packet_pool;
    if (pkt != NULL)
        rtp_packet_pool = pkt->next;
    else
        pkt = malloc(sizeof(*pkt));
    memset(pkt, 0, sizeof(*pkt));
    pkt->rlen = sizeof(pkt->raddr);
    return pkt;
}

void
rtp_packet_free(struct rtp_packet *pkt)
{
    pkt->next = rtp_packet_pool;
    rtp_packet_pool = pkt;
}

struct rtp_packet *
rtp_recv(int fd)
{
    struct rtp_packet *pkt;

    pkt = rtp_packet_alloc();

    if (pkt == NULL)
        return NULL;

    pkt->size = recvfrom(fd, pkt->buf, sizeof(pkt->buf), 0, 
      sstosa(&pkt->raddr), &pkt->rlen);

    if (pkt->size == -1) {
	rtp_packet_free(pkt);
	return NULL;
    }
    
    return pkt;
}
