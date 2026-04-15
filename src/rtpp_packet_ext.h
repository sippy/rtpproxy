#pragma once

struct rtp_packet;
struct rtp_packet_ext;

struct rtp_packet_ext *rtpp_packet_ext_link(struct rtp_packet *, unsigned int);
struct rtp_packet *rtpp_packet_ext_get_pkt(struct rtp_packet_ext *);
