#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <elperiodic.h>

#if !defined(SA_LEN)
#define SA_LEN(sa) \
  (((sa)->sa_family == AF_INET) ? \
  sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))
#endif

struct sender_arg {
    int s;
    const _Atomic(double) *prp;
    char *sendbuf;
    int sendlen;
    _Atomic(uint64_t) *top;
};

struct receiver_arg {
    int s;
    const _Atomic(double) *prp;
    _Atomic(uint64_t) *tup;
};

int
resolve(struct sockaddr *ia, int pf, const char *host,
  const char *servname, int flags)
{
    int n;
    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = flags;          /* We create listening sockets */
    hints.ai_family = pf;              /* Protocol family */
    hints.ai_socktype = SOCK_DGRAM;     /* UDP */

    n = getaddrinfo(host, servname, &hints, &res);
    if (n == 0) {
        /* Use the first socket address returned */
        memcpy(ia, res->ai_addr, res->ai_addrlen);
        freeaddrinfo(res);
    }

    return n;
}

void sender(void *prt)
{
    int n;
    useconds_t sleeptime;
    struct sender_arg *sender_arg;
    double prate;

    {int b=0; while (b);}
    sender_arg = (struct sender_arg *)prt;

    prate = atomic_load(sender_arg->prp);
    sleeptime = (double)1e+6 / prate;

    for (;;) {
        n = send(sender_arg->s, sender_arg->sendbuf, sender_arg->sendlen, 0);
        if (n > 0)
		atomic_fetch_add(sender_arg->top, 1);
        /*printf("send: %d\n", n);*/
        usleep(sleeptime);
    }
}

#define RECV_UDP_MAXLEN (10*1024)
#define RECV_UDP_MAXPKTS 16

void receiver(void *prt)
{
    int n, alen;
    struct receiver_arg *receiver_arg;
    struct rdata {
        struct mmsghdr mhdr;
	struct iovec miov;
        char rbuf[1024];
    };
    struct mmsghdr *mstart;
    struct iovec *iovecs;
    char *rbstart;
   
    alen = sizeof(struct rdata) * RECV_UDP_MAXPKTS; 
    mstart = malloc(alen);
    memset(mstart, '\0', alen);
    iovecs = (void *)((char *)mstart +
      (offsetof(struct rdata, miov) * RECV_UDP_MAXPKTS));
    rbstart = (char *)mstart +
      (offsetof(struct rdata, rbuf) * RECV_UDP_MAXPKTS);

    for (int i = 0; i < RECV_UDP_MAXPKTS; i++) {
	iovecs[i].iov_base = rbstart;
	iovecs[i].iov_len = 1024;
        mstart[i].msg_hdr.msg_iov = &iovecs[i];
	mstart[i].msg_hdr.msg_iovlen = 1;
        rbstart += 1024;
    }

    receiver_arg = (struct receiver_arg *)prt;

    for (;;) {
        n = recvmmsg(receiver_arg->s, mstart, RECV_UDP_MAXPKTS,
	  MSG_WAITFORONE, NULL);
        if (n > 0) {
		//assert(n < 6);
                atomic_fetch_add(receiver_arg->tup, n);
	}
    }
}

int main(int argc, char **argv)
{
    int min_port, max_port, nthreads;
    const char *host;
    struct sender_arg sender_arg;
    void *thread_ret;
    char ch, *datafile;
    char sendbuf[88], databuf[1024 * 8];
    FILE *f;
    _Atomic(uint64_t) totalout;
    atomic_init(&totalout, 0);
    _Atomic(uint64_t) totalin;
    atomic_init(&totalin, 0);
    void *elp;
    _Atomic(double) prate;
    atomic_init(&prate, 100.0);
    double pr;

    min_port = 6000;
    max_port = 7000;
    host = "1.2.3.4";
    datafile = NULL;
    nthreads = -1;
    while ((ch = getopt(argc, argv, "p:P:h:f:t:r:")) != -1)
        switch (ch) {
        case 'p':
            min_port = atoi(optarg);
            break;

        case 'P':
            max_port = atoi(optarg);
            break;

        case 'h':
            host = optarg;
            break;

        case 'f':
            datafile = optarg;
            break;

        case 't':
            nthreads = atoi(optarg);
            break;

	case 'r':
	    pr = strtod(optarg, NULL);
	    assert(pr > 0.0);
            atomic_store(&prate, pr);
	    break;
    }

    if (nthreads <= 0) {
        nthreads = max_port - min_port + 1;
    } else if (nthreads < (max_port - min_port + 1)) {
        errx(1, "number of threads should be greater than or equial to port range");
        /* Not reached */
    }

    if (datafile == NULL) {
        sender_arg.sendbuf = sendbuf;
        sender_arg.sendlen = sizeof(sendbuf);
    } else {
        f = fopen(datafile, "r");
        if (f == NULL) {
            err(1, "%s", datafile);
            /* Not reached */
        }
        sender_arg.sendlen = fread(databuf, 1, sizeof(databuf), f);
        sender_arg.sendbuf = databuf;
        fclose(f);
    }
    elp = prdic_init(1.0, 0.0);
    if (elp == NULL) {
	errx(1, "prdic_init() failed");
    }

    int n;
    char *cport;
    struct sockaddr ia;

    asprintf(&cport, "%d", 5060);
    n = resolve(&ia, AF_INET, host, cport, AI_PASSIVE);
    if (n != 0) {
        errx(1, "resolve() failed");
    }

    pthread_t rthreads[nthreads], sthreads[nthreads]; 
    for (int port = min_port, i = 0; i < nthreads; i++) {
	struct {
	    struct sender_arg snd;
            struct receiver_arg rcv;
	} *sa;

        sa = malloc(sizeof(*sa));
        sa->snd.sendbuf = sender_arg.sendbuf;
        sa->snd.sendlen = sender_arg.sendlen;
	sa->snd.top = &totalout;
	sa->rcv.prp = sa->snd.prp = &prate;
	sa->rcv.tup = &totalin;

        sa->snd.s = socket(AF_INET, SOCK_DGRAM, 0);
        connect(sa->snd.s, &ia, SA_LEN(&ia));
	sa->rcv.s = sa->snd.s;

        pthread_create(&sthreads[i], NULL, (void *(*)(void *))&sender,
	  (void *)&(sa->snd));
	pthread_create(&rthreads[i], NULL, (void *(*)(void *))&receiver,
	  (void *)&(sa->rcv));
        port++;
        if (port > max_port)
            port = min_port;
    }
    for (uint64_t iout = 0, iin = 0;;) {
	uint64_t cout, cin;

	cout = atomic_load(&totalout);
	cin = atomic_load(&totalin);
	fprintf(stdout, "out=%d in=%d\n", (int)(cout - iout), (int)(cin - iin));
	prdic_procrastinate(elp);
	iout = cout;
	iin = cin;
    }
    for (int i = 0; i < nthreads; i++) {
        pthread_join(rthreads[i], &thread_ret);
	pthread_join(sthreads[i], &thread_ret);
    }
    return (0);
}
