#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <pthread.h>

#include "rtpp_log.h"
#include "rtpp_cfg_stable.h"
#include "rtpp_sessinfo.h"

struct rtpp_sessinfo *
rtpp_sessinfo_ctor(struct rtpp_cfg_stable *cfsp)
{
    struct rtpp_sessinfo *sessinfo;

    sessinfo = malloc(sizeof(struct rtpp_sessinfo));
    if (sessinfo == NULL) {
        return (NULL);
    }
    memset(sessinfo, '\0', sizeof(struct rtpp_sessinfo));
    sessinfo->sessions = malloc((sizeof sessinfo->sessions[0]) *
      (((cfsp->port_max - cfsp->port_min + 1)) + 1));
    if (sessinfo->sessions == NULL) {
        goto e0;
    }
    sessinfo->rtp_servers =  malloc((sizeof sessinfo->rtp_servers[0]) *
      (((cfsp->port_max - cfsp->port_min + 1) * 2) + 1));
    if (sessinfo->rtp_servers == NULL) {
        goto e1;
    }
    sessinfo->pfds_rtp = malloc((sizeof sessinfo->pfds_rtp[0]) *
      (((cfsp->port_max - cfsp->port_min + 1)) + 1));
    if (sessinfo->pfds_rtp == NULL) {
        goto e2;
    }
    sessinfo->pfds_rtcp = malloc((sizeof sessinfo->pfds_rtcp[0]) *
      (((cfsp->port_max - cfsp->port_min + 1)) + 1));
    if (sessinfo->pfds_rtcp == NULL) {
        goto e3;
    }
    pthread_mutex_init(&sessinfo->lock, NULL);

    sessinfo->sessions[0] = NULL;
    sessinfo->nsessions = 0;
    sessinfo->rtp_nsessions = 0;

    return (sessinfo);

e3:
    free(sessinfo->pfds_rtp);
e2:
    free(sessinfo->rtp_servers);
e1:
    free(sessinfo->sessions);
e0:
    free(sessinfo);
    return (NULL);
}
