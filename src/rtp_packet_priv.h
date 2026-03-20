#pragma once

#include "rtp.h"
#include "rtp_info.h"
#include "rtp_packet.h"
#include "rtpp_wi_private.h"

struct rtp_packet_priv {
    struct rtpp_wi *wi;
    struct rtp_info rinfo;
    struct rtpp_wi_pvt wip;
};

struct rtp_packet_full {
    struct rtp_packet pub;
    struct rtp_packet_priv pvt;
};
