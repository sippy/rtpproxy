#ifndef _RTP_LOADER_H_
#define _RTP_LOADER_H_

#include <sys/types.h>
#include <sys/stat.h>

#include "session.h"
#include "../rtp_analyze.h"

struct rtpp_loader;

struct rtpp_loader {
    int ifd;
    struct stat sb;
    unsigned char *ibuf;    
    int (*load)(struct rtpp_loader *, struct channels *, struct rtpp_session_stat *, enum origin);
    void (*destroy)(struct rtpp_loader *);

    union {
        struct {
            pcap_hdr_t *pcap_hdr;
        } pcap_data;
        struct {} adhoc_data;
    } private;
};

struct rtpp_loader *rtpp_load(const char *);

#endif
