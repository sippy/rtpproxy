#pragma once

struct rtpp_refcnt;
struct rtpp_packetport;
struct rtpp_packetport_int;
struct rtp_packet;
struct rtpp_session;
struct rtpp_stream;

DEFINE_METHOD(rtpp_packetport_int, rtpp_packetport_send_pkt_na, int,
  unsigned int, struct rtp_packet *);
DEFINE_METHOD(rtpp_packetport_int, rtpp_packetport_next_in_port, unsigned int);
DEFINE_METHOD(rtpp_packetport_int, rtpp_packetport_next_out_port, unsigned int);
DEFINE_METHOD(rtpp_packetport_int, rtpp_packetport_reg_stream, int,
  unsigned int, struct rtpp_stream *);
DEFINE_METHOD(rtpp_packetport_int, rtpp_packetport_reg_streams, int,
  struct rtpp_session *, int, unsigned int);
DEFINE_METHOD(rtpp_packetport_int, rtpp_packetport_unreg_stream, void,
  unsigned int);

struct rtpp_packetport_int *rtpp_packetport_get_int(struct rtpp_packetport *);

DECLARE_SMETHODS(rtpp_packetport_int) {
    struct rtpp_refcnt *rcnt;
    METHOD_ENTRY(rtpp_packetport_send_pkt_na, send_pkt_na);
    METHOD_ENTRY(rtpp_packetport_next_in_port, next_in_port);
    METHOD_ENTRY(rtpp_packetport_next_out_port, next_out_port);
    METHOD_ENTRY(rtpp_packetport_reg_stream, reg_stream);
    METHOD_ENTRY(rtpp_packetport_reg_streams, reg_streams);
    METHOD_ENTRY(rtpp_packetport_unreg_stream, unreg_stream);
};

DECLARE_CLASS_PUBTYPE(rtpp_packetport_int, {
});
