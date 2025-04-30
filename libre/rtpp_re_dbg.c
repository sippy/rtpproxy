#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#define DEBUG_MODULE "dbg"
#define DEBUG_LEVEL 0
#include "re_dbg.h"
#include "re_fmt.h"

#include "rtpp_log.h"

static int
rtpp_re_dbg_level(int re_level) {
    switch (re_level) {
    case DBG_EMERG:
    case DBG_ALERT:
    case DBG_CRIT:
        return (RTPP_LOG_CRIT);
    case DBG_ERR:
        return (RTPP_LOG_ERR);
    case DBG_WARNING:
        return (RTPP_LOG_WARN);
    case DBG_NOTICE:
    case DBG_INFO:
        return (RTPP_LOG_INFO);
    case DBG_DEBUG:
        return (RTPP_LOG_DBUG);
    }
    abort();
}

void
dbg_printf(int level, const char *fmt, ...)
{
    char buf[256];
    int len;
    va_list args;

    level = rtpp_re_dbg_level(level);

    va_start(args, fmt);
    len = re_vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (len <= 0)
        abort();
    if (buf[len - 1] == '\n')
        len -= 1;
    re_dbg_printf(level, buf, len);
}
