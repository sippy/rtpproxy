#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include "rtpp_defines.h"
#include "rtpp_proc.h"
#include "rtpp_proc_async.h"
#include "rtpp_util.h"

static void
rtpp_proc_async_run(void *arg)
{
    struct cfg *cf;
    double eptime, last_tick_time;
    int alarm_tick, i, last_ctick;
    struct rtpp_proc_async_cf *proc_cf;

    cf = (struct cfg *)arg;
    proc_cf = cf->rtpp_proc_cf;

    last_tick_time = 0;
    pthread_mutex_lock(&proc_cf->proc_mutex);
    last_ctick = proc_cf->clock_tick;
    pthread_mutex_unlock(&proc_cf->proc_mutex);

    for (;;) {
        pthread_mutex_lock(&proc_cf->proc_mutex);
        while (proc_cf->clock_tick == last_ctick) {
            pthread_cond_wait(&proc_cf->proc_cond, &proc_cf->proc_mutex);
        }
        last_ctick = proc_cf->clock_tick;
        pthread_mutex_unlock(&proc_cf->proc_mutex);

        pthread_mutex_lock(&cf->sessinfo.lock);
        if (cf->sessinfo.nsessions > 0) {
            i = poll(cf->sessinfo.pfds, cf->sessinfo.nsessions, 0);
            pthread_mutex_unlock(&cf->sessinfo.lock);
            if (i < 0 && errno == EINTR)
                continue;
        } else {
            pthread_mutex_unlock(&cf->sessinfo.lock);
        }
        eptime = getdtime();

#if RTPP_DEBUG
        if (last_ctick % POLL_RATE == 0 || last_ctick < 1000) {
            rtpp_log_write(RTPP_LOG_DBUG, cf->stable.glog, "run %lld eptime %f, CSV: %f,%f", \
              last_ctick, eptime, (double)last_ctick / (double)POLL_RATE, eptime);
        }
#endif

        if (last_tick_time == 0 || last_tick_time > eptime) {
            alarm_tick = 0;
            last_tick_time = eptime;
        } else if (last_tick_time + TIMETICK < eptime) {
            alarm_tick = 1;
            last_tick_time = eptime;
        } else {
            alarm_tick = 0;
        }

        pthread_mutex_lock(&cf->glock);
        process_rtp(cf, eptime, alarm_tick);
        if (cf->rtp_nsessions > 0) {
            process_rtp_servers(cf, eptime);
        }
        pthread_mutex_unlock(&cf->glock);
    }

}

int
rtpp_proc_async_wakeup(struct rtpp_proc_async_cf *proc_cf, int clock)
{
    int old_clock;

    pthread_mutex_lock(&proc_cf->proc_mutex);

    old_clock = proc_cf->clock_tick;
    proc_cf->clock_tick = clock;

    /* notify worker thread */
    pthread_cond_signal(&proc_cf->proc_cond);

    pthread_mutex_unlock(&proc_cf->proc_mutex);

    return (old_clock);
}

int
rtpp_proc_async_init(struct cfg *cf)
{
    struct rtpp_proc_async_cf *proc_cf;

    proc_cf = malloc(sizeof(*proc_cf));
    if (proc_cf == NULL)
        return (-1);

    memset(proc_cf, '\0', sizeof(*proc_cf));

    pthread_cond_init(&proc_cf->proc_cond, NULL);
    pthread_mutex_init(&proc_cf->proc_mutex, NULL);

    cf->rtpp_proc_cf = proc_cf;
    if (pthread_create(&proc_cf->thread_id, NULL, (void *(*)(void *))&rtpp_proc_async_run, cf) != 0) {
        pthread_cond_destroy(&proc_cf->proc_cond);
        pthread_mutex_destroy(&proc_cf->proc_mutex);
        free(proc_cf);
        cf->rtpp_proc_cf = NULL;
        return (-1);
    }

    return (0);
}
