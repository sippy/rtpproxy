/*
 * Copyright (c) 2015 Sippy Software, Inc., http://www.sippysoft.com
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

#ifndef RTPP_MEMDEB_STDOUT
#  define RTPP_MEMDEB_REPORT(handle, format, args...) \
    if (handle != NULL) { \
        RTPP_LOG(((struct rtpp_log *)handle), RTPP_LOG_DBUG, format, ## args); \
    }
#else
#  define RTPP_MEMDEB_REPORT2(handle, nostdout, format, args...) { \
    if (!nostdout) { \
        printf((format "\n"), ## args); \
        fflush(stdout); \
    }; \
    if (handle != NULL) { \
        RTPP_LOG(((struct rtpp_log *)handle), RTPP_LOG_DBUG, format, ## args); \
    } \
}
#  define RTPP_MEMDEB_REPORT(handle, format, args...) \
    RTPP_MEMDEB_REPORT2(handle, 0, format, ## args)
#endif

#define RTPP_MEMDEB_STATIC(appname) void *_##appname##_memdeb

#define RTPP_MEMDEB_APP_STATIC void * MEMDEB_SYM

#define RTPP_MEMDEB_INIT(appname) { \
	void *_trp = getreturnaddr(0); \
	assert(_trp != NULL); \
	assert(execinfo_set_topframe(_trp) == NULL); \
        _##appname##_memdeb = rtpp_memdeb_init(true); \
        assert(_##appname##_memdeb != NULL); \
    }

#define RTPP_MEMDEB_APP_INIT() { \
        void *_trp = getreturnaddr(0); \
        assert(_trp != NULL); \
        assert(execinfo_set_topframe(_trp) == NULL); \
        MEMDEB_SYM = rtpp_memdeb_init(true); \
        assert(MEMDEB_SYM != NULL); \
    }

#define RTPP_MEMDEB_INIT1(appname) { \
        _##appname##_memdeb = rtpp_memdeb_init(false); \
        assert(_##appname##_memdeb != NULL); \
    }

#define RTPP_MEMDEB_FIN(appname) { \
        assert(_##appname##_memdeb != NULL); \
        rtpp_memdeb_dtor(_##appname##_memdeb); \
        _##appname##_memdeb = NULL; \
    }

struct memdeb_loc {
    const char *fname;
    int linen;
    const char *funcn;
};

struct rtpp_log;

int rtpp_memdeb_dumpstats(void *, int);
void rtpp_memdeb_setbaseln(void *);
int rtpp_memdeb_selftest(void *);
void rtpp_memdeb_setlog(void *, struct rtpp_log *);
void rtpp_memdeb_setname(void *, const char *);
void rtpp_memdeb_approve(void *, const char *, int, const char *);

void *rtpp_memdeb_init(bool);
void rtpp_memdeb_dtor(void *);
