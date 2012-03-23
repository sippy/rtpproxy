#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if !defined(SA_LEN)
#define SA_LEN(sa) \
  (((sa)->sa_family == AF_INET) ? \
  sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))
#endif

struct sender_arg {
    char *host;
    int port;
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
    int s, n;
    char sendbuf[88];
    struct sockaddr ia;
    struct sender_arg *sender_arg;
    char *port;

    {int b=0; while (b);}
    sender_arg = (struct sender_arg *)prt;

    asprintf(&port, "%d", sender_arg->port);
    n = resolve(&ia, AF_INET, sender_arg->host, port, AI_PASSIVE);

    s = socket(AF_INET, SOCK_DGRAM, 0);
    connect(s, &ia, SA_LEN(&ia));

    for (;;) {
        n = send(s, sendbuf, sizeof(sendbuf), 0);
        /*printf("send: %d\n", n);*/
        usleep(10000);
    }
}

int main(int argc, char **argv)
{
    int i, min_port, max_port;
    pthread_t thread;
    struct sender_arg sender_arg;
    void *thread_ret;
    char ch;

    min_port = 6000;
    max_port = 7000;
    sender_arg.host = "1.2.3.4";
    while ((ch = getopt(argc, argv, "p:P:h:")) != -1)
        switch (ch) {
        case 'p':
            min_port = atoi(optarg);
            break;

        case 'P':
            max_port = atoi(optarg);
            break;

        case 'h':
            sender_arg.host = optarg;
            break;
    }

    for (sender_arg.port = min_port; sender_arg.port <= max_port; sender_arg.port++) {
        pthread_create(&thread, NULL, (void *(*)(void *))&sender, (void *)&sender_arg);
    }
    pthread_join(thread, &thread_ret);
    for(;;);
    return (0);
}
