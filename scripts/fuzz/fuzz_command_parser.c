#include <sys/socket.h>
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
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
#include "rtpp_command_async.h"
#include "rtpp_proc_async.h"
#include "rtpp_hash_table.h"
#include "rtpp_weakref.h"
#include "rtpp_sessinfo.h"
#include "rtpp_stats.h"
#include "rtpp_time.h"

#include "librtpproxy.h"

#include "fuzz_standalone.h"

#define howmany(x, y) (sizeof(x) / sizeof(y))

static const struct rtpp_cfg *cfsp;

void
cleanupHandler(void)
{
    printf("Cleaning up before exit...\n");
    rtpp_shutdown(cfsp);
}

int
LLVMFuzzerTestOneInput(const char *data, size_t size)
{
    struct rtpp_timestamp dtime = {};
    static struct rtpp_command_stats cstat = {};
    struct rtpp_command *cmd;
    int rval = -1;
    char *argv[] = {
       "rtpproxy",
       "-f",
       "-T", "1",
       "-W", "1",
       "-s", "stdio:",
       "-d", "crit",
       "-n", "tcp:127.0.0.1:9642",
       "-S", "/tmp",
       "-r", "."
    };
    int argc = howmany(argv, *argv);
    static int tfd;

    if (size > RTPP_CMD_BUFLEN)
        return (0);

    if (cfsp == NULL) {
        cfsp = rtpp_main(argc, argv);
        assert(cfsp != NULL);
        tfd = open("/dev/null", O_WRONLY, 0);
        assert(tfd >= 0);
        atexit(cleanupHandler);
    }
    cmd = rtpp_command_ctor(cfsp, tfd, &dtime, &cstat, 0);
    assert(cmd != NULL);
    memcpy(cmd->buf, data, size);
    cmd->buf[size == RTPP_CMD_BUFLEN ? size - 1 : size] = '\0';

    if (rtpp_command_split(cmd, size, &rval, NULL) == 0) {
        handle_command(cfsp, cmd);
    }
    free_command(cmd);
    return (0);
}
