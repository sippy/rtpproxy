#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/module.h>
#include <sys/syscall.h>

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "bulk_net/module/syscall.h"

#include "rtpp_bulk_netio.h"

static int sendto_bulk_sycallno = -1;
static int recvfrom_bulk_sycallno;

struct rtpp_bnet_opipe {
    int plen;
    int clen;
    int compat;
    struct sendto_s *ss_send;
};

struct rtpp_bnet_opipe *
rtpp_bulk_netio_opipe_new(int plen)
{
    struct rtpp_bnet_opipe *op;

    op = malloc(sizeof(struct rtpp_bnet_opipe) + (sizeof(struct sendto_s) * plen));
    if (op == NULL) {
        return (NULL);
    }
    op->ss_send = (struct sendto_s *)(op + 1);
    op->plen = plen;
    op->clen = 0;
    op->compat = (sendto_bulk_sycallno == -1) ? 1 : 0;

    return (op);
}

int
rtpp_bulk_netio_opipe_destroy(struct rtpp_bnet_opipe *op)
{
    int rval;

    rval = rtpp_bulk_netio_opipe_flush(op);
    free(op);
    return (rval);
}

int
rtpp_bulk_netio_opipe_flush(struct rtpp_bnet_opipe *op)
{
    int rval;

    if (op->clen <= 0)
        return (op->clen);
    if (op->compat == 0) {
        rval = syscall(sendto_bulk_sycallno, op->ss_send, op->clen);
    } else {
        int i;
        struct sendto_s *ss_send;

        for (i = 0; i < op->clen; i++) {
            ss_send = &op->ss_send[i];
            sendto(ss_send->args.s, ss_send->args.buf, ss_send->args.len,
              ss_send->args.flags, (const struct sockaddr *)ss_send->args.to,
              ss_send->args.tolen);
        }
    }
    op->clen = 0;
    return (rval);
}

int
rtpp_bulk_netio_opipe_sendto(struct rtpp_bnet_opipe *op, int s, const void *msg, \
  size_t len, int flags, const struct sockaddr *to, socklen_t tolen)
{
    struct sendto_s *ss_send;

    ss_send = &op->ss_send[op->clen];
    ss_send->args.s = s;
    ss_send->args.buf = (void *)msg;
    ss_send->args.len = len;
    ss_send->args.flags = flags;
    ss_send->args.to = (void *)to;
    ss_send->args.tolen = tolen;
    ss_send->rval = EINVAL;
    op->clen += 1;
    if (op->clen < op->plen)
        return (0);
    
    return (rtpp_bulk_netio_opipe_flush(op));
}

int
rtpp_bulk_netio_init()
{
    int modid;
    struct module_stat stat;

    stat.version = sizeof(stat);
    modid = modfind("net_bulk");
    if (modid < 0) {
        warn("modfind(net_bulk)");
        return (-1);
    }
    if (modstat(modid, &stat) != 0) {
        warn("modstat(net_bulk)");
        return (-1);
    }
    sendto_bulk_sycallno = stat.data.intval;
    recvfrom_bulk_sycallno = stat.data.intval + 1;

    return (0);
}
