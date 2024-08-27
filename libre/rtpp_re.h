#pragma once

#define HAVE_INET_NTOP 1
#define HAVE_INET_PTON 1
#define HAVE_INET6 1

#define mem_alloc mem_zalloc

struct icem;
struct rtpp_command_argsp;
struct rtpp_log;

typedef void (mem_destroy_h)(void *data);

int rtpp_cand_decode(struct icem *, const struct rtpp_command_argsp *,
  struct rtpp_log *);
void *mem_deref(void *data);
void re_dbg_printf(int level, const char *buf, int len);

struct udp_helper;
struct udp_sock;
struct mbuf;
