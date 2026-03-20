#pragma once

struct rtp_packet;
struct rtp_packet_ext;

struct rtp_packet_ext *rtpp_packet_ext_link(struct rtp_packet *, unsigned int);
struct rtp_packet *rtpp_packet_ext_get_pkt(struct rtp_packet_ext *);
int rtpp_packet_ext_owns_data(struct rtp_packet_ext *);
double rtpp_packet_ext_get_rtime_wall(const struct rtp_packet_ext *);
double rtpp_packet_ext_get_rtime_mono(const struct rtp_packet_ext *);
void rtpp_packet_ext_set_rtime(struct rtp_packet_ext *, double, double);
