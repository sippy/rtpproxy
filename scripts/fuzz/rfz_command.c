#include <sys/socket.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define HAVE_CONFIG_H 1
#include "config_pp.h"

#include "rtpp_types.h"
#include "rtpp_cfg.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_command.h"
#include "rtpp_command_args.h"
#include "rtpp_command_sub.h"
#include "rtpp_command_private.h"
#include "rtpp_command_reply.h"
#include "rtpp_command_stats.h"
#include "rtpp_time.h"

#include "rfz_utils.h"
#include "rfz_command.h"

int
ExecuteRTPPCommand(struct rtpp_conf *gcp, const char *data, size_t size, int debug)
{
    struct rtpp_timestamp dtime = {};
    static struct rtpp_command_stats cstat = {};
    struct rtpp_command *cmd;
    int rval = -1;

    if (size >= RTPP_CMD_BUFLEN)
        return (-1);

    cmd = rtpp_command_ctor(gcp->cfsp, gcp->tfd, &dtime, &cstat, 0);
    if (cmd == NULL)
        return (-1);
    const void *tp = cmd->reply;
    const void *trp = cmd->reply->rcnt;
    if (debug)
        CALL_SMETHOD(cmd->reply->rcnt, traceen, HEREVAL);
    memcpy(cmd->buf, data, size);
    cmd->buf[size] = '\0';

    rval = rtpp_command_split(cmd, size, &rval, NULL);
    if (rval == 0) {
        rval = handle_command(gcp->cfsp, cmd);
    }
    assert(tp == cmd->reply);
    assert(trp == cmd->reply->rcnt);
    assert(CALL_SMETHOD(cmd->reply->rcnt, peek) == 1);
    RTPP_OBJ_DECREF(cmd);
    return (rval);
}
