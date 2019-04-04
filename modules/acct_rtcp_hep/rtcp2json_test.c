/*
 * Copyright (c) 2018 Sippy Software, Inc., http://www.sippysoft.com
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "rtpp_sbuf.h"
#include "rtcp2json.h"

int
main(int argc, char **argv)
{
    int fd;
    const char *path;
    struct rtpp_sbuf *sbp;
    char rtcp_data[1024];
    ssize_t rtcp_dlen;

    if (argc == 1) {
        path = "rtcp.raw";
    } else {
        path = argv[1];
    }

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open() failed\n");
        exit(1);
    }
    rtcp_dlen = read(fd, rtcp_data, sizeof(rtcp_data));
    if (rtcp_dlen <= 0) {
        fprintf(stderr, "read() failed\n");
        exit(1);
    }
    sbp = rtpp_sbuf_ctor(1024);
    if (sbp == NULL) {
        fprintf(stderr, "rtpp_sbuf_ctor() failed\n");
        exit(1);
    }
    if (rtcp2json(sbp, rtcp_data, rtcp_dlen) != 0) {
        fprintf(stderr, "rtcp2json() failed\n");
        exit(1);
    }
    printf("%s\n", sbp->bp);

    exit(0);
}
