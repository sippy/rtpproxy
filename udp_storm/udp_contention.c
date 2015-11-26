#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int
genrandomdest(const char *dstaddr, int dstnetpref, struct sockaddr_in *sin)
{
    struct in_addr raddr;
    long rnum;
    uint16_t rport;

    assert(sin->sin_family == AF_INET);

    if (inet_aton(dstaddr, &raddr) == 0) {
        return (-1);
    }
    rnum = random() >> dstnetpref;
    raddr.s_addr |= htonl(rnum);
    do {
        rport = (uint16_t)(random());
    } while (rport < 1000);
    sin->sin_addr = raddr;
    sin->sin_port = htons(rport);
    return (0);
}

struct destination
{
    int s;
    int sconnected;
    struct sockaddr_in daddr;
    int buflen;
    unsigned char buf[256];
};

struct workset
{
    pthread_t tid;
    int nreps;
    int ndest;
    double stime;
    double etime;
    struct destination dests[0];
};

struct recvset
{
    pthread_t tid;
    int ndest;
    uint64_t **nrecvd;
    uint64_t nrecvd_total;
    uint64_t npolls;
    int done;
    struct pollfd pollset[0];
};

static void
genrandombuf(struct destination *dp, int minlen, int maxlen)
{
    unsigned int difflen;
    int i;

    assert(minlen <= maxlen && maxlen <= sizeof(dp->buf));
    difflen = maxlen - minlen;
    if (difflen > 0) {
        dp->buflen = minlen + (random() % (difflen + 1));
    } else {
        dp->buflen = minlen;
    }
    for (i = 0; i < dp->buflen; i++) {
        dp->buf[i] = (unsigned char)random();
    }
}

static struct workset *
generate_workset(int setsize, const char *dstaddr, int dstnetpref)
{
    struct workset *wp;
    struct destination *dp;
    size_t msize;
    int i, flags;

    msize = sizeof(struct workset) + (setsize * sizeof(struct destination));
    wp = malloc(msize);
    if (wp == NULL) {
        return (NULL);
    }
    memset(wp, '\0', msize);
    wp->ndest = setsize;
    for (i = 0; i < setsize; i++) {
        dp = &(wp->dests[i]);
        dp->daddr.sin_family = AF_INET;
        dp->s = socket(dp->daddr.sin_family, SOCK_DGRAM, 0);
        if (dp->s == -1) {
            goto e1;
        }
        genrandomdest(dstaddr, dstnetpref, &dp->daddr);
        genrandombuf(dp, 30, 170);
        flags = fcntl(dp->s, F_GETFL);
        fcntl(dp->s, F_SETFL, flags | O_NONBLOCK);
    }
    return (wp);
e1:
    for (i = i - 1; i >= 0; i--) {
        close(wp->dests[i].s);
    }
    free(wp);
    return (NULL);
}

#if !defined(sstosa)
#define sstosa(ss)      ((struct sockaddr *)(ss))
#endif

static int
connect_workset(struct workset *wp)
{
    int i;
    int rval;
    struct destination *dp;

    rval = 0;
    for (i = 0; i < wp->ndest; i++) {
        dp = &(wp->dests[i]);
        if (dp->sconnected == 0) {
            if (connect(dp->s, sstosa(&dp->daddr), sizeof(dp->daddr)) != 0) {
                rval -= 1;
                continue;
            }
            dp->sconnected = 1;
        }
    }
    return (rval);
}

#if defined(CLOCK_UPTIME_PRECISE)
#define RTPP_CLOCK CLOCK_UPTIME_PRECISE
#else
# if defined(CLOCK_MONOTONIC_RAW)
#define RTPP_CLOCK CLOCK_MONOTONIC_RAW
# else
#define RTPP_CLOCK CLOCK_MONOTONIC
#endif
#endif

static double timespec2dtime(time_t, long);

double
getdtime(void)
{
    struct timespec tp;

    if (clock_gettime(RTPP_CLOCK, &tp) == -1)
        return (-1);

    return timespec2dtime(tp.tv_sec, tp.tv_nsec);
}

static double
timespec2dtime(time_t tv_sec, long tv_nsec)
{

    return (double)tv_sec + (double)tv_nsec / 1000000000.0;
}

static void
process_workset(struct workset *wp)
{
    int i, j;
    struct destination *dp;

    wp->stime = getdtime();
    for (i = 0; i < wp->nreps; i++) {
        for (j = 0; j < wp->ndest; j++) {
            dp = &(wp->dests[j]);
            if (dp->sconnected == 0) {
                sendto(dp->s, dp->buf, dp->buflen, 0, sstosa(&dp->daddr),
                  sizeof(dp->daddr));
            } else {
                send(dp->s, dp->buf, dp->buflen, 0);
            }
        }
    }
    wp->etime = getdtime();
}

static void
process_recvset(struct recvset  *rp)
{
    int nready, i, rval;
    struct pollfd *pdp;
    unsigned char buf[256];
    struct sockaddr_storage raddr;
    socklen_t fromlen;

    for (;;) {
        nready = poll(rp->pollset, rp->ndest, 100);
        rp->npolls++;
        if (rp->done != 0 && nready == 0) {
            break;
        }
        if (nready <= 0) {
            continue;
        }
        for (i = 0; i < rp->ndest && nready > 0; i++) {
            pdp = &rp->pollset[i];
            if ((pdp->revents & POLLIN) == 0) {
                continue;
            }
            fromlen = sizeof(raddr);
            rval = recvfrom(pdp->fd, buf, sizeof(buf), 0, sstosa(&raddr),
              &fromlen);
            if (rval > 0) {
                rp->nrecvd[i]++;
                rp->nrecvd_total++;
            }
            nready -= 1;
        }
    }
}


static void
release_workset(struct workset *wp)
{
    int i;
    struct destination *dp;

    for (i = 0; i < wp->ndest; i++) {
        dp = &(wp->dests[i]);
        close(dp->s);
    }
    free(wp);
}

static void
release_recvset(struct recvset  *rp)
{

    free(rp->nrecvd);
    free(rp);
}

struct recvset *
generate_recvset(struct workset *wp)
{
    struct recvset *rp;
    int msize, i;
    struct pollfd *pdp;

    msize = sizeof(struct recvset) + (sizeof(struct pollfd) * wp->ndest);
    rp = malloc(msize);
    if (rp == NULL) {
        return (NULL);
    }
    memset(rp, '\0', msize);
    msize = sizeof(uint64_t) * wp->ndest;
    rp->nrecvd = malloc(msize);
    if (rp->nrecvd == NULL) {
        free(rp);
        return (NULL);
    }
    memset(rp->nrecvd, '\0', msize);
    for (i = 0; i < wp->ndest; i++) {
        pdp = &rp->pollset[i];
        pdp->fd = wp->dests[i].s;
        pdp->events = POLLIN;
    }
    rp->ndest = wp->ndest;
    return (rp);
}

struct tstats {
    double total_pps;
    double total_poll_rate;
    double ploss_rate;
};

void
run_test(int nthreads, int connect, const char *dstaddr, int dstnetpref,
  struct tstats *tsp)
{
    int nreps = 120 * 100;
    int npkts = 2000;
    struct workset *wsp[32];
    struct recvset *rsp[32];
    int i;
    double pps, tduration, poll_rate;
    uint64_t nrecvd_total, nsent_total;

    for (i = 0; i < nthreads; i++) {
        wsp[i] = generate_workset(npkts, dstaddr, dstnetpref);
        wsp[i]->nreps = nreps;
        if (connect) {
            connect_workset(wsp[i]);
        }
        rsp[i] = generate_recvset(wsp[i]);
    }
    for (i = 0; i < nthreads; i++) {
        pthread_create(&wsp[i]->tid, NULL, (void *(*)(void *))process_workset, wsp[i]);
        pthread_create(&rsp[i]->tid, NULL, (void *(*)(void *))process_recvset, rsp[i]);
    }
    tsp->total_pps = 0;
    tsp->total_poll_rate = 0;
    nrecvd_total = 0;
    nsent_total = 0;
    for (i = 0; i < nthreads; i++) {
        pthread_join(wsp[i]->tid, NULL);
        rsp[i]->done = 1;
        pthread_join(rsp[i]->tid, NULL);
        nsent_total += wsp[i]->nreps * wsp[i]->ndest;
        pps = wsp[i]->nreps * wsp[i]->ndest;
        tduration = wsp[i]->etime - wsp[i]->stime;
        pps /= tduration;
        tsp->total_pps += pps;
        nrecvd_total += rsp[i]->nrecvd_total;
        poll_rate = ((double)rsp[i]->npolls) / tduration;
        tsp->total_poll_rate += poll_rate / (double)nthreads;
        release_workset(wsp[i]);
        release_recvset(rsp[i]);
    }
    tsp->ploss_rate = (double)(nsent_total - nrecvd_total) /
      (double)(nsent_total);
    return;
}

int
main(void)
{
    int nthreads_max = 10;
    int nthreads_min = 1;
    int i, j;
    const char *dstaddr = "172.16.0.0";
    int dstnetpref = 12;
    struct tstats tstats;

    srandomdev();
    for (i = nthreads_min; i <= nthreads_max; i++) {
        for (j = 0; j <= 1; j++) {
            run_test(i, j, dstaddr, dstnetpref, &tstats);
            printf("nthreads = %d, connected = %d: total PPS = %f, "
              "loss %f%%, poll rate %f\n", i, j, tstats.total_pps,
              tstats.ploss_rate * 100, tstats.total_poll_rate);
        }
    }
    exit(0);
}
