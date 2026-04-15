#pragma once

#include "packetport.h"

#ifdef __cplusplus
extern "C" {
#endif

int rtpp_packet_ext_owns_data(struct rtp_packet_ext *);
double rtpp_packet_ext_get_rtime_wall(const struct rtp_packet_ext *);
double rtpp_packet_ext_get_rtime_mono(const struct rtp_packet_ext *);
void rtpp_packet_ext_set_rtime(struct rtp_packet_ext *, double, double);

#ifdef __cplusplus
}
#endif
