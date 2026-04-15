#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*rtp_packet_ext_dtor_t)(void *);

struct SPMCQueue;

struct rtpp_packetport {
    struct SPMCQueue *in;
    struct SPMCQueue *out;
};

struct rtp_packet_ext {
    const void *data;
    int dlen;
    unsigned int port;
};

struct rtpp_packetport *rtpp_packetport_ctor(unsigned int);
void rtpp_packetport_push(struct rtpp_packetport *, struct rtp_packet_ext *);
int rtpp_packetport_try_push(struct rtpp_packetport *, struct rtp_packet_ext *);
int rtpp_packetport_flush(struct rtpp_packetport *);
struct rtp_packet_ext *rtpp_packetport_try_pop(struct rtpp_packetport *);
size_t rtpp_packetport_try_pop_many(struct rtpp_packetport *,
  struct rtp_packet_ext **, size_t);
unsigned int rtpp_packetport_next_in_port(struct rtpp_packetport *);
void rtpp_packetport_dtor(struct rtpp_packetport *);
struct rtp_packet_ext *rtp_packet_ext_ctor(int, unsigned int, const void *,
  rtp_packet_ext_dtor_t, void *);
void rtp_packet_ext_dtor(struct rtp_packet_ext *);

#ifdef __cplusplus
}
#endif
