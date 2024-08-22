#pragma once

#include <sys/socket.h>
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <unistd.h>

#include <openssl/rand.h>

#define HAVE_CONFIG_H 1
#include "config_pp.h"

#include "rtpp_types.h"
#include "rtpp_cfg.h"
#include "rtpp_refcnt.h"
#include "rtpp_log_stand.h"
#include "rtpp_log_obj.h"
#include "rtpp_command_args.h"
#include "rtpp_command.h"
#include "rtpp_command_sub.h"
#include "rtpp_command_private.h"
#include "rtpp_command_async.h"
#include "rtpp_proc_async.h"
#include "rtpp_hash_table.h"
#include "rtpp_weakref.h"
#include "rtpp_sessinfo.h"
#include "rtpp_stats.h"
#include "rtpp_time.h"
#include "rtpp_util.h"

#include "librtpproxy.h"

struct rtpp_conf {
    struct rtpp_cfg *cfsp;
    int tfd;
};

#define howmany(x, y) (sizeof(x) / sizeof(y))

static struct rtpp_conf gconf;

static void
cleanupHandler(void)
{
    printf("Cleaning up before exit...\n");
    rtpp_shutdown(gconf.cfsp);
    close(gconf.tfd);
}

static unsigned char deterministic_data[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};
static size_t offset = 0;

static int
dRAND_bytes(unsigned char *buf, int num) {
    for (int i = 0; i < num; i++) {
        buf[i] = deterministic_data[offset];
        offset = (offset + 1) % sizeof(deterministic_data);
    }
    return 1; // Return 1 to indicate success
}

static int
dRAND_status(void)
{

    return 1;
}

RAND_METHOD dummy = {
    .bytes = &dRAND_bytes,
    .pseudorand = &dRAND_bytes,
    .status = &dRAND_status,
};

static void
SeedRNGs(void)
{
    offset = 0;
    seedrandom();
}

static struct RTPPInitializeParams {
    const char *ttl;
    const char *setup_ttl;
    const char *socket;
    const char *debug_level;
    const char *notify_socket;
    const char *rec_spool_dir;
    const char *rec_final_dir;
    const char *modules[];
} RTPPInitializeParams = {
    .ttl = "1",
    .setup_ttl = "1",
    .socket = NULL,
    .debug_level = "crit",
    .notify_socket = "tcp:127.0.0.1:9642",
    .rec_spool_dir = "/tmp",
    .rec_final_dir = ".",
    .modules = {"acct_csv", "catch_dtmf", "dtls_gw", "ice_lite", NULL},
};

static int
RTPPInitialize(void)
{
    const struct RTPPInitializeParams *rp = &RTPPInitializeParams;
    const char *argv[] = {
       "rtpproxy",
       "-f",
       "-T", rp->ttl,
       "-W", rp->setup_ttl,
       "-s", (rp->socket != NULL) ? rp->socket : tmpnam(NULL),
       "-d", rp->debug_level,
       "-n", rp->notify_socket,
       "-S", rp->rec_spool_dir,
       "-r", rp->rec_final_dir,
       "--dso", rp->modules[0],
       "--dso", rp->modules[1],
       "--dso", rp->modules[2],
       "--dso", rp->modules[3],
    };
    int argc = howmany(argv, *argv);
    struct rtpp_cfg *cfsp;

    OPT_SAVE();
    assert(RAND_set_rand_method(&dummy) == 1);
    SeedRNGs();
    cfsp = rtpp_main(argc, argv);
    OPT_RESTORE();
    if (cfsp == NULL)
        goto e0;
    cfsp->no_resolve = 1;
    gconf.tfd = open("/dev/null", O_WRONLY, 0);
    if (gconf.tfd < 0)
        goto e1;
    gconf.cfsp = cfsp;
    atexit(cleanupHandler);
    return (0);
e1:
    cleanupHandler();
e0:
    return (-1);
}

static int
ExecuteRTPPCommand(struct rtpp_conf *gcp, const char *data, size_t size)
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
    memcpy(cmd->buf, data, size);
    cmd->buf[size] = '\0';

    rval = rtpp_command_split(cmd, size, &rval, NULL);
    if (rval == 0) {
        rval = handle_command(gcp->cfsp, cmd);
    }
    free_command(cmd);
    return (rval);
}
