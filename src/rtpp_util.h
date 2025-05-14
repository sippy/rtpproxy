/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2023 Sippy Software, Inc., http://www.sippysoft.com
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

#pragma once

#if !defined(PACKAGE_VERSION)
# error "config.h" needs to be included
#endif

#define	NOT(x)		(((x) == 0) ? 1 : 0)

struct rtpp_cfg;

struct rtpp_daemon_rope {
    int result;
    int pipe;
    const char *ok_msg;
    size_t msglen;
};

/* Function prototypes */
void seedrandom(void);
int set_rlimits(const struct rtpp_cfg *);
int drop_privileges(const struct rtpp_cfg *);
char *rtpp_strsep(char **, const char *);
int rtpp_daemon_rel_parent(const struct rtpp_daemon_rope *);
struct rtpp_daemon_rope rtpp_daemon(int, int, int);
int url_unquote(unsigned char *, int) RTPP_EXPORT;
int url_unquote2(const char *, char *, int) RTPP_EXPORT;
int url_quote(const char *, char *, int, int) RTPP_EXPORT;
int rtpp_get_sched_hz(void);
#ifndef HAVE_STRLCPY
size_t strlcpy(char *, const char *, size_t) RTPP_EXPORT;
#endif
enum atoi_rval {ATOI_OK = 0, ATOI_NOTINT = -1, ATOI_OUTRANGE = -2};
enum atoi_rval atoi_safe_sep(const char *, int *, char, const char **);
enum atoi_rval atoi_safe(const char *, int *);
enum atoi_rval atoi_saferange(const char *, int *, int, int) RTPP_EXPORT;
void rtpp_strsplit(char *, char *, size_t, size_t);
void generate_random_string(char *, int) RTPP_EXPORT;

/* Some handy/compat macros */
#if !defined(INFTIM)
#define	INFTIM		(-1)
#endif

#if !defined(ACCESSPERMS)
#define	ACCESSPERMS	(S_IRWXU|S_IRWXG|S_IRWXO)
#endif
#if !defined(DEFFILEMODE)
#define	DEFFILEMODE	(S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)
#endif

#if !defined(HAVE_ERR_H)
#define err(exitcode, format, args...) \
  errx(exitcode, format ": %s", ## args, strerror(errno))
#define errx(exitcode, format, args...) \
  { warnx(format, ## args); exit(exitcode); }
#define warn(format, args...) \
  warnx(format ": %s", ## args, strerror(errno))
#define warnx(format, args...) \
  fprintf(stderr, format "\n", ## args)
#endif
