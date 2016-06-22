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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <machine/cpufunc.h>

#define TEST_KIND_ALL         0
#define TEST_KIND_UNCONNECTED 1
#define TEST_KIND_CONNECTED   2
#define TEST_KIND_HALFCONN    3
#define TEST_KIND_MAX         TEST_KIND_CONNECTED

struct tconf {
    int nthreads_max;
    int nthreads_min;
    int paylen_min;
    int paylen_max;
    const char *dstaddr;
    int dstnetpref;
    int test_kind;
    uint64_t magic;
};

static int
genrandomdest(struct tconf *cfp, struct sockaddr_in *s_in)
{
    struct in_addr raddr;
    long rnum;
    uint16_t rport;

    assert(s_in->sin_family == AF_INET);

    if (inet_aton(cfp->dstaddr, &raddr) == 0) {
        return (-1);
    }
    rnum = random() >> cfp->dstnetpref;
    raddr.s_addr |= htonl(rnum);
    do {
        rport = (uint16_t)(random());
    } while (rport < 1000);
    s_in->sin_addr = raddr;
    s_in->sin_port = htons(rport);
    return (0);
}

struct pktdata {
    uint64_t magic;
    uint64_t send_ts;
    int idx;
};

union pkt {
    unsigned char d[256];
    struct pktdata pd;
};

struct destination
{
    int sin;
    int sout;
    int sconnected;
    struct sockaddr_in daddr;
    int buflen;
    union pkt buf;
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
    uint64_t rtt_total;
    int done;
    uint64_t magic;
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
        dp->buf.d[i] = (unsigned char)random();
    }
}

static int
socket_ctor(int domain)
{
    int s, flags;

    s = socket(domain, SOCK_DGRAM, 0);
    if (s == -1) {
        return (-1);
    }
    flags = fcntl(s, F_GETFL);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);
    return (s);
}

static struct workset *
generate_workset(int setsize, struct tconf *cfp)
{
    struct workset *wp;
    struct destination *dp;
    size_t msize;
    int i;

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
        dp->sout = dp->sin = socket_ctor(dp->daddr.sin_family);
        if (dp->sin == -1) {
            goto e1;
        }
        genrandomdest(cfp, &dp->daddr);
        genrandombuf(dp, cfp->paylen_min, cfp->paylen_max);
        dp->buf.pd.magic = cfp->magic;
        dp->buf.pd.idx = i;
    }
    return (wp);
e1:
    for (i = i - 1; i >= 0; i--) {
        close(wp->dests[i].sin);
    }
    free(wp);
    return (NULL);
}

#if !defined(sstosa)
#define sstosa(ss)      ((struct sockaddr *)(ss))
#endif
#if !defined(sstosin)
#define sstosin(ss)      ((struct sockaddr_in *)(ss))
#endif

#if !defined(SA_LEN)
#define SA_LEN(sa) \
  (((sa)->sa_family == AF_INET) ? \
  sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))
#endif
#if !defined(SS_LEN)
#define SS_LEN(ss) \
  (((ss)->ss_family == AF_INET) ? \
  sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))
#endif

int
local4remote(struct sockaddr *ra, struct sockaddr_storage *la)
{
    int s, r;
    socklen_t llen;

    s = socket(ra->sa_family, SOCK_DGRAM, 0);
    if (s == -1) {
        return (-1);
    }
    if (connect(s, ra, SA_LEN(ra)) == -1) {
        close(s);
        return (-1);
    }
    llen = sizeof(*la);
    r = getsockname(s, sstosa(la), &llen);
    close(s);
    return (r);
}

static int
connect_workset(struct workset *wp, int test_type)
{
    int i, r, reuse;
    int rval;
    socklen_t llen;
    struct destination *dp;
    struct sockaddr_storage la;
    struct sockaddr_in *lip;

    rval = 0;
    for (i = 0; i < wp->ndest; i++) {
        dp = &(wp->dests[i]);
        if (dp->sconnected == 0) {
            if (test_type == TEST_KIND_HALFCONN) {
                dp->sout = socket_ctor(dp->daddr.sin_family);
                if (dp->sout == -1) {
                    rval -= 1;
                    dp->sout = dp->sin;
                    continue;
                }

                reuse = 1;
                r = setsockopt(dp->sin, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
                if (r == -1) {
                    rval -= 1;
                    continue;
                }

                lip = sstosin(&la);
                lip->sin_addr.s_addr = INADDR_ANY;
                lip->sin_port = htons(0);
                llen = sizeof(struct sockaddr_in);
                r = bind(dp->sin, sstosa(&la), llen);
                if (r == -1) {
                    rval -= 1;
                    continue;
                }
                llen = sizeof(la);
                r = getsockname(dp->sin, sstosa(&la), &llen);
                if (r == -1) {
                    rval -= 1;
                    continue;
                }

                reuse = 1;
                r = setsockopt(dp->sout, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
                if (r == -1) {
                    rval -= 1;
                    continue;
                }
                lip = sstosin(&la);
#if 0
                r = local4remote(sstosa(&dp->daddr), &lat);
                if (r == -1) {
                    rval -= 1;
                    continue;
                }
                lip->sin_addr.s_addr = sstosin(&lat)->sin_addr.s_addr;
#endif
                llen = sizeof(struct sockaddr_in);
                r = bind(dp->sout, sstosa(&la), llen);
                if (r == -1) {
                    rval -= 1;
                    continue;
                }
            }
            if (connect(dp->sout, sstosa(&dp->daddr), sizeof(dp->daddr)) != 0) {
                rval -= 1;
                continue;
            }
            if (test_type == TEST_KIND_HALFCONN) {
#if 0
                llen = sizeof(la);
                r = getsockname(dp->sout, sstosa(&la), &llen);
                if (r == -1) {
                    rval -= 1;
                    continue;
                }
                reuse = 1;
                r = setsockopt(dp->sin, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
                if (r == -1) {
                    rval -= 1;
                    continue;
                }
                lip = sstosin(&la);
                lip->sin_addr.s_addr = INADDR_ANY;
                llen = sizeof(struct sockaddr_in);
                r = bind(dp->sin, sstosa(&la), llen);
                if (r == -1) {
                    rval -= 1;
                    continue;
                }
#endif
                r = shutdown(dp->sout, SHUT_RD);
                if (r == -1) {
                    rval -= 1;
                    continue;
                }
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
            dp->buf.pd.send_ts = rdtsc();
            if (dp->sconnected == 0) {
                sendto(dp->sout, dp->buf.d, dp->buflen, 0, sstosa(&dp->daddr),
                  sizeof(dp->daddr));
            } else {
                send(dp->sout, dp->buf.d, dp->buflen, 0);
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
    union pkt buf;
    struct sockaddr_storage raddr;
    socklen_t fromlen;
    uint64_t rtime, rtt;

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
            rval = recvfrom(pdp->fd, buf.d, sizeof(buf.d), 0, sstosa(&raddr),
              &fromlen);
            rtime = rdtsc();
            if (rval > 0) {
                if (buf.pd.magic != rp->magic) {
                    continue;
                }
                rtt = rtime - buf.pd.send_ts;
                rp->nrecvd[i]++;
                rp->nrecvd_total++;
                rp->rtt_total += rtt;
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
        close(dp->sin);
        if (dp->sout != dp->sin) {
            close(dp->sout);
        }
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
generate_recvset(struct workset *wp, struct tconf *cfp)
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
        pdp->fd = wp->dests[i].sin;
        pdp->events = POLLIN;
    }
    rp->ndest = wp->ndest;
    rp->magic = cfp->magic;
    return (rp);
}

struct tstats {
    double total_pps;
    double total_poll_rate;
    double ploss_rate;
};

static void
run_test(int nthreads, int test_type, struct tconf *cfp, struct tstats *tsp)
{
    int nreps = 10 * 100;
    int npkts = 4000;
    struct workset *wsp[32];
    struct recvset *rsp[32];
    int i;
    double pps, tduration, poll_rate;
    uint64_t nrecvd_total, nsent_total, rtt_total;

    for (i = 0; i < nthreads; i++) {
        wsp[i] = generate_workset(npkts, cfp);
        assert(wsp[i] != NULL);
        wsp[i]->nreps = nreps;
        if (test_type == TEST_KIND_CONNECTED || test_type == TEST_KIND_HALFCONN) {
            if (connect_workset(wsp[i], test_type) != 0) {
                fprintf(stderr, "connect_workset() failed\n");
                abort();
            }
        }
        rsp[i] = generate_recvset(wsp[i], cfp);
    }
    for (i = 0; i < nthreads; i++) {
        pthread_create(&wsp[i]->tid, NULL, (void *(*)(void *))process_workset, wsp[i]);
        pthread_create(&rsp[i]->tid, NULL, (void *(*)(void *))process_recvset, rsp[i]);
    }
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
        rtt_total += rsp[i]->rtt_total;
        poll_rate = ((double)rsp[i]->npolls) / tduration;
        tsp->total_poll_rate += poll_rate / (double)nthreads;
        release_workset(wsp[i]);
        release_recvset(rsp[i]);
    }
    fprintf(stderr, "nsent_total=%ju, nrecvd_total=%ju\n", (uintmax_t)nsent_total,
      (uintmax_t)nrecvd_total);
    tsp->ploss_rate = (double)(nsent_total - nrecvd_total) /
      (double)(nsent_total);
    return;
}

static void
usage(void)
{

    exit(1);
}

int
main(int argc, char **argv)
{
    struct tconf cfg;
    int i, j, ch;
    struct tstats tstats;
    char *cp;

    memset(&cfg, '\0', sizeof(struct tconf));
    cfg.nthreads_max = 10;
    cfg.nthreads_min = 1;
    cfg.dstaddr = "170.178.193.146";
    cfg.dstnetpref = 32;
    cfg.magic = ((uint64_t)random() << 32) | (uint64_t)random();
    cfg.paylen_min = 30;
    cfg.paylen_max = 170;

    while ((ch = getopt(argc, argv, "m:M:k:p:P:")) != -1) {
        switch (ch) {
        case 'm':
            cfg.nthreads_min = atoi(optarg);
            break;

        case 'M':
            cfg.nthreads_max = atoi(optarg);
            break;

        case 'k':
            cfg.test_kind = atoi(optarg);
            break;

        case 'p':
            cfg.paylen_min = atoi(optarg);
            if (cfg.paylen_min < sizeof(struct pktdata)) {
                usage();
            }
            break;

        case 'P':
            cfg.paylen_max = atoi(optarg);
            break;

        case '?':
        default:
            usage();
        }
    }
    if (cfg.paylen_max < cfg.paylen_min) {
        usage();
    }
    argc -= optind;
    argv += optind;

    if (argc != 1) {
        usage();
    }
    cfg.dstaddr = argv[0];
    cp = strrchr(cfg.dstaddr, '/');
    if (cp != NULL) {
        cp[0] = '\0';
        cfg.dstnetpref = atoi(cp + 1);
        if (cfg.dstnetpref < 1 || cfg.dstnetpref > 32) {
            usage();
        }
    }

    srandomdev();
    for (i = cfg.nthreads_min; i <= cfg.nthreads_max; i++) {
        if (cfg.test_kind != TEST_KIND_ALL) {
            memset(&tstats, '\0', sizeof(struct tstats));
            run_test(i, cfg.test_kind, &cfg, &tstats);
            printf("nthreads = %d, connected = %d: total PPS = %f, "
              "loss %f%%, poll rate %f\n", i, cfg.test_kind, tstats.total_pps,
              tstats.ploss_rate * 100, tstats.total_poll_rate);
            continue;
        }
        for (j = TEST_KIND_ALL + 1; j <= TEST_KIND_MAX; j++) {
            memset(&tstats, '\0', sizeof(struct tstats));
            run_test(i, j, &cfg, &tstats);
            printf("nthreads = %d, connected = %d: total PPS = %f, "
              "loss %f%%, poll rate %f\n", i, j, tstats.total_pps,
              tstats.ploss_rate * 100, tstats.total_poll_rate);
        }
    }
    exit(0);
}
