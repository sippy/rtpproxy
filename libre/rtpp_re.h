#pragma once

#define HAVE_INET_NTOP 1
#define HAVE_INET_PTON 1

#define mem_alloc mem_zalloc

struct icem;
struct rtpp_command_argsp;

typedef void (mem_destroy_h)(void *data);

int rtpp_cand_decode(struct icem *icem, const struct rtpp_command_argsp *args);
void *mem_deref(void *data);
void re_dbg_printf(int level, const char *buf, int len);

struct udp_helper;
struct udp_sock;
struct mbuf;
