#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "rtpp_endian.h"
#include "rtp_info.h"
#include "rtp.h"

int
LLVMFuzzerTestOneInput(const char *data, size_t size)
{
    struct rtp_info ri = {};

    rtp_packet_parse_raw((const unsigned char *)data, size, &ri);
    return (0);
}
