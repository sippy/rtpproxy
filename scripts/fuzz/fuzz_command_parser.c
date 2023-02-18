#include <sys/socket.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <unistd.h>

#include "rtpp_types.h"
#include "rtpp_cfg.h"
#include "rtpp_refcnt.h"
#include "rtpp_log_stand.h"
#include "rtpp_log_obj.h"
#include "rtpp_command_args.h"
#include "rtpp_command.h"
#include "rtpp_command_private.h"
#include "rtpp_genuid_singlet.h"
#include "rtpp_stats.h"
#include "rtpp_time.h"

struct rtpp_anetio_cf;
struct rtpp_socket;

int
rtpp_anetio_sendto(struct rtpp_anetio_cf *netio_cf, int sock, const void *msg,
  size_t msg_len, int flags, const struct sockaddr *sendto, socklen_t tolen)
{

    return (0);
}

long long
rtpp_rlim_max(const struct rtpp_cfg *cfsp)
{

    return (long long)(0);
}

struct rtpp_socket *
rtpp_socket_ctor(int domain, int type)
{

    return (NULL);
}

int
LLVMFuzzerTestOneInput(const char *data, size_t size)
{
    static thread_local struct rtpp_cfg cfg = {};
    struct rtpp_timestamp dtime = {};
    struct rtpp_command_stats cstat = {};
    struct rtpp_command *cmd;
    int rval = -1;

    if (size > RTPP_CMD_BUFLEN)
        return (0);
    if (cfg.glog == NULL) {
        assert(rtpp_gen_uid_init() == 0);
        cfg.glog = rtpp_log_ctor("rtpproxy", NULL, LF_REOPEN);
        assert(cfg.glog != NULL);
        cfg.rtpp_stats = rtpp_stats_ctor();
        assert(cfg.rtpp_stats != NULL);
    }
    cmd = rtpp_command_ctor(&cfg, STDIN_FILENO, &dtime, &cstat, 0);
    assert(cmd != NULL);
    memcpy(cmd->buf, data, size);
    rtpp_command_split(cmd, size, &rval, NULL);
    free_command(cmd);
    return (0);
}
