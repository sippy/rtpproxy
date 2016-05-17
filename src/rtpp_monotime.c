/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2015 Sippy Software, Inc., http://www.sippysoft.com
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

#include <sys/time.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "rtpp_monotime.h"
#include "rtpp_time.h"

#define timespecsub2(r, v, u)                                      \
    do {                                                           \
        SEC(r) = SEC(v) - SEC(u);                                  \
        NSEC(r) = NSEC(v) - NSEC(u);                               \
        if (NSEC(r) < 0 && (SEC(r) > 0 || NSEC(r) <= -NSEC_MAX)) { \
            SEC(r)--;                                              \
            NSEC(r) += NSEC_MAX;                                   \
        }                                                          \
    } while (0);

#define timespecsub(v, u) timespecsub2((v), (v), (u))

#define timespecadd2(r, v, u)                                      \
    do {                                                           \
        SEC(r) = SEC(v) + SEC(u);                                  \
        NSEC(r) = NSEC(v) + NSEC(u);                               \
        if (NSEC(r) >= NSEC_MAX) {                                 \
            SEC(r)++;                                              \
            NSEC(r) -= NSEC_MAX;                                   \
        }                                                          \
    } while (0);

#define timespecmean2(r, v, u)                                     \
    do {                                                           \
        if ((SEC(v) % 2) ^ (SEC(u) % 2)) {                         \
            SEC(r) = 1;                                            \
            NSEC(r) = -(NSEC_MAX / 2);                             \
        } else {                                                   \
            SEC(r) = 0;                                            \
            NSEC(r) = 0;                                           \
        }                                                          \
        SEC(r) = (SEC(r) + SEC(v) + SEC(u)) / 2;                   \
        NSEC(r) += (NSEC(v) + NSEC(u)) / 2;                        \
    } while (0);

#define timespeccmp(t, c, u)                                       \
    ((SEC(t) == SEC(u)) ?                                          \
      (NSEC(t) c NSEC(u)) :                                        \
      (SEC(t) c SEC(u)))

#define timespecaddnsec(v, nsec)                                   \
    do {                                                           \
        NSEC(v) += (nsec);                                         \
        if (NSEC(v) >= NSEC_MAX) {                                 \
            SEC(v)++;                                              \
            NSEC(v) -= NSEC_MAX;                                   \
        }                                                          \
    } while (0);

#define timespecsubnsec(v, nsec)                                   \
    do {                                                           \
        NSEC(v) -= (nsec);                                         \
        if (NSEC(v) < 0 && (SEC(v) > 0 || NSEC(v) <= -NSEC_MAX)) { \
            SEC(v)--;                                              \
            NSEC(v) += NSEC_MAX;                                   \
        }                                                          \
    } while (0);

struct r2mdatapt {
    struct timespec r2m;
    struct timespec r2m_rel;
    struct timespec r2m_err;
    struct timespec mtime_dur;
    struct timespec rtime_dur;
    struct timespec mtime;
    struct timespec rtime;
    int rejected;
    double T;
    double T_r2m;
};

int rtime2mtime(struct r2mdatapt *dp)
{
    struct timespec tp[4];
    int i;

    for (i = 0; i < 4; i++) {
        switch (i) {
        case 0:
            if (clock_gettime(RTPP_CLOCK_MONO, &tp[i]) == -1)
                return (-1);
            break;

        case 1:
            if (clock_gettime(RTPP_CLOCK_REAL, &tp[i]) == -1)
                return (-1);
            break;

        case 2:
            if (clock_gettime(RTPP_CLOCK_REAL, &tp[i]) == -1)
                return (-1);
            if (timespeccmp(&tp[i], ==, &tp[1])) {
                /*
                 * If we are too fast or clock resolution is too
                 * shitty for the clock to increase between (1)
                 * and (2), call again until we get at least one
                 * notch of a difference between those.
                 */
                i -= 1;
            }
            break;

        case 3:
            if (clock_gettime(RTPP_CLOCK_MONO, &tp[i]) == -1)
                return (-1);
            if (timespeccmp(&tp[i], ==, &tp[0])) {
                /* 
                 * If we are too fast or clock resolution is too
                 * shitty for the clock to increase between (0)
                 * and (3), call again until we get at least one
                 * notch of a difference between those.
                 */
                i -= 1;
            }
            break;
        }
    }
    timespecsub2(&dp->rtime_dur, &tp[2], &tp[1]);
    timespecsub2(&dp->mtime_dur, &tp[3], &tp[0]);
    dp->rtime = tp[2];
    dp->mtime = tp[3];
    timespecsub(&tp[1], &tp[0]);
    timespecsub(&tp[2], &tp[3]);
    timespecmean2(&dp->r2m, &tp[1], &tp[2]);
    timespecsub2(&dp->r2m_err, &tp[1], &tp[2]);

    return (0);
}

/* 95% confidence at 50 data points */
#define Tcrit 2.956

#define R2M_DS_LEN   53
#define R2M_DS_WARM  3
#define R2M_DS_MIN   (R2M_DS_LEN / 2)
/* Don't bother to recalibrare is the diff is less than 1uS (1000nS) */
#define R2M_MIN_PREC 1000

struct r2m_conv {
    struct timespec cval;
    struct timespec min;
    struct timespec max;
    struct timespec lastcal_mtime;
    struct timespec lastcal_rtime;
};

static int
r2m_check(struct r2m_conv *r2m_old)
{
    struct r2mdatapt r2m_ds[R2M_DS_WARM + 1];
    int i;

    memset(r2m_ds, '\0', sizeof(r2m_ds));
    for (i = 0; i < R2M_DS_WARM + 1; i++) {
        rtime2mtime(&r2m_ds[i]);
    }
    if (timespeccmp(&r2m_old->min, <, &r2m_ds[R2M_DS_WARM].r2m) &&
      timespeccmp(&r2m_old->max, >, &r2m_ds[R2M_DS_WARM].r2m)) {
        r2m_old->lastcal_mtime = r2m_ds[R2M_DS_WARM].mtime;
        r2m_old->lastcal_rtime = r2m_ds[R2M_DS_WARM].rtime;
        return (0);
    }
    return (1);
}
    

static int
r2m_calibrate(struct r2m_conv *r2m)
{
    struct r2mdatapt r2m_ds[R2M_DS_LEN];
    int i, last_i, nsam;
    long long mean_err, mean_r2m, variance, variance_r2m, diff;
    double stddev, stddev_r2m;
    struct r2m_conv r2m_rval;

    /* Do a quick check to see if the update is really necessary */
    if (!timespeciszero(&r2m->cval) && r2m_check(r2m) == 0) {
        return (0);
    }

restart:
    memset(r2m_ds, '\0', sizeof(r2m_ds));
    for (i = 0; i < R2M_DS_LEN; i++) {
        rtime2mtime(&r2m_ds[i]);
        if (r2m_ds[i].r2m_err.tv_sec != 0 || r2m_ds[i].r2m_err.tv_nsec < 0) {
            /* Something weird, re-do */
            i -= 1;
            continue;
        }
        if (timespeccmp(&r2m_ds[i].rtime_dur, >, &r2m_ds[i].mtime_dur)) {
            /* Real-time jumped, restart the measurement */
            i = 0;
            continue;
        }
    }
    /*
     * Reject first few samples, they are usually skewed due to the cache
     * warm-up process.
     */
    for (i = 0; i < R2M_DS_WARM; i++) {
        r2m_ds[i].rejected = 1;
    }
again:
    mean_err = 0;
    nsam = 0;
    for (i = 0; i < R2M_DS_LEN; i++) {
        if (r2m_ds[i].rejected != 0) {
            continue;
        }
        nsam += 1;
        mean_err += r2m_ds[i].r2m_err.tv_nsec;
    }
    if (nsam < R2M_DS_MIN) {
        /* Make sure we have enough good data to work with */
        goto restart;
    }
    mean_err /= nsam;
    variance = 0;
    for (i = 0; i < R2M_DS_LEN; i++) {
        if (r2m_ds[i].rejected != 0) {
            continue;
        }
        diff = r2m_ds[i].r2m_err.tv_nsec - mean_err;
        variance += (diff * diff);
    }
    variance /= (nsam - 1);
    stddev = sqrt(variance);
    for (i = 0; i < R2M_DS_LEN; i++) {
        if (r2m_ds[i].rejected != 0) {
            continue;
        }
        r2m_ds[i].T = (r2m_ds[i].r2m_err.tv_nsec - mean_err) / stddev;
        if (r2m_ds[i].T < 0) {
            r2m_ds[i].T = -r2m_ds[i].T;
        }
        if (r2m_ds[i].T > Tcrit) {
            r2m_ds[i].rejected = 1;
            goto again;
        }
    }
    memset(&r2m_rval, '\0', sizeof(r2m_rval));
    for (i = 0; i < R2M_DS_LEN; i++) {
        if (r2m_ds[i].rejected != 0) { 
            continue;
        }
        if (timespeciszero(&r2m_rval.min) || timespeccmp(&r2m_rval.min, >, &r2m_ds[i].r2m)) {
            r2m_rval.min = r2m_ds[i].r2m;
        }
        if (timespeciszero(&r2m_rval.max) || timespeccmp(&r2m_rval.max, <, &r2m_ds[i].r2m)) {
            r2m_rval.max = r2m_ds[i].r2m;
        }
#if 0
        printf("%d,%ld,%ld,%ld,%ld,%f\n", i, r2m_ds[i].r2m.tv_sec,
          r2m_ds[i].r2m.tv_nsec, r2m_ds[i].r2m_err.tv_sec,
          r2m_ds[i].r2m_err.tv_nsec, r2m_ds[i].T);
#endif
    }
#if 0
    printf("min r2m: tv_sec = %ld, tv_nsec = %ld\n", r2m_rval.min.tv_sec, r2m_rval.min.tv_nsec);
    printf("mean_err = %lld, variance = %lld, stddev = %f\n", mean_err, variance, stddev);
#endif
    mean_r2m = 0;
    for (i = 0; i < R2M_DS_LEN; i++) {
        if (r2m_ds[i].rejected != 0) {
            continue;
        }
        /* Normalize r2m values so we can only deal with the nsec part */
        timespecsub2(&r2m_ds[i].r2m_rel, &r2m_ds[i].r2m, &r2m_rval.min);

        if (r2m_ds[i].r2m_rel.tv_sec > 0 || r2m_ds[i].r2m_rel.tv_nsec > 0x7fff) {
            /*
             * The difference between min and max measured r2m values cannot be
             * greater than about half of the tv_nsec total bit length, both
             * practically and because the code below would overflow otherwise.
             */
            goto restart;
        }
        mean_r2m += r2m_ds[i].r2m_rel.tv_nsec;
    }
    mean_r2m /= nsam;
    variance_r2m = 0;
    for (i = 0; i < R2M_DS_LEN; i++) {
        if (r2m_ds[i].rejected != 0) {
            continue;
        }
        diff = r2m_ds[i].r2m_rel.tv_nsec - mean_r2m;
        variance_r2m += (diff * diff);
    }
    variance_r2m /= (nsam - 1);
    stddev_r2m = sqrt(variance_r2m);
    last_i = 0;
    for (i = 0; i < R2M_DS_LEN; i++) {
        if (r2m_ds[i].rejected != 0) {
            continue;
        }
        r2m_ds[i].T_r2m = (r2m_ds[i].r2m_rel.tv_nsec - mean_r2m) / stddev_r2m;
        if (r2m_ds[i].T_r2m < 0) {
            r2m_ds[i].T_r2m = -r2m_ds[i].T_r2m;
        }
        if (r2m_ds[i].T_r2m > Tcrit) {
            r2m_ds[i].rejected = 1;
            goto again;
        }
        last_i = i;
    }
#if 0
    for (i = 0; i < R2M_DS_LEN; i++) {
        if (r2m_ds[i].rejected != 0) {
            continue;
        }
        printf("%d,%ld,%ld,%ld,%ld,%f,%f\n", i, r2m_ds[i].r2m_rel.tv_sec,
          r2m_ds[i].r2m_rel.tv_nsec, r2m_ds[i].r2m_err.tv_sec,
          r2m_ds[i].r2m_err.tv_nsec, r2m_ds[i].T, r2m_ds[i].T_r2m);
    }
#endif

    r2m_rval.cval = r2m_rval.min;
    timespecaddnsec(&r2m_rval.cval, mean_r2m);

    if (!timespeciszero(&r2m->cval) && timespeccmp(&r2m->min, <, &r2m_rval.cval) &&
      timespeccmp(&r2m->max, >, &r2m_rval.cval)) {
        /* The new value is essentially the same */
        r2m->lastcal_mtime = r2m_ds[last_i].mtime;
        r2m->lastcal_rtime = r2m_ds[last_i].rtime;
        return (0);
    }

    r2m_rval.lastcal_mtime = r2m_ds[last_i].mtime;
    r2m_rval.lastcal_rtime = r2m_ds[last_i].rtime;

    if (mean_r2m < (R2M_MIN_PREC / 2)) {
        r2m_rval.max = r2m_rval.min = r2m_rval.cval;
        timespecaddnsec(&r2m_rval.max, (R2M_MIN_PREC / 2));
        timespecsubnsec(&r2m_rval.min, (R2M_MIN_PREC / 2));
    }

#if 0
    printf("mean_r2m = %ld.%.9ld, variance = %lld, stddev = %f\n", r2m_rval.cval.tv_sec,
      r2m_rval.cval.tv_nsec, variance_r2m, stddev_r2m);
    printf("min_r2m = %ld.%.9ld, max_r2m = %ld.%.9ld\n", r2m_rval.min.tv_sec,
      r2m_rval.min.tv_nsec, r2m_rval.max.tv_sec, r2m_rval.max.tv_nsec);
#endif

    *r2m = r2m_rval; 

    return (1);
}

static __thread struct r2m_conv r2m_conv1;
static const struct timespec recal_ival = {.tv_sec = 1, .tv_nsec = 0};

#define timeval2timespec(s, v)         \
    do {                               \
        SEC(s) = SEC(v);               \
        NSEC(s) = USEC(v) * 1000;      \
    } while (0);
#define timespec2timeval(v, s)         \
    do {                               \
        SEC(v) = SEC(s);               \
        USEC(v) = NSEC(s) / 1000;      \
    } while (0);

double
rtimeval2dtime(struct timeval *rtime)
{
    struct timespec rtimespec, timediff;
    struct timespec mtime;

    timeval2timespec(&rtimespec, rtime);
    if (timespeciszero(&r2m_conv1.cval)) {
        r2m_calibrate(&r2m_conv1);
    } else {
        timespecsub2(&timediff, &rtimespec, &r2m_conv1.lastcal_rtime);
        if (timespeccmp(&rtimespec, <, &r2m_conv1.lastcal_rtime) ||
          timespeccmp(&timediff, >, &recal_ival)) {
            r2m_calibrate(&r2m_conv1);
        }
    }
    timespecsub2(&mtime, &rtimespec, &r2m_conv1.cval);

    return (timespec2dtime(&mtime));
}

void
dtime2rtimeval(double dtime, struct timeval *rtimeval)
{
    struct timespec rtimespec, mtime, timediff;

    dtime2mtimespec(dtime, &mtime);
    if (timespeciszero(&r2m_conv1.cval)) {
        r2m_calibrate(&r2m_conv1);
    } else {
        timespecsub2(&timediff, &mtime, &r2m_conv1.lastcal_mtime);
        if (timespeccmp(&timediff, >, &recal_ival)) {
            r2m_calibrate(&r2m_conv1);
        }
    }
    timespecadd2(&rtimespec, &mtime, &r2m_conv1.cval);
    timespec2timeval(rtimeval, &rtimespec);
}

double
dtime2rtime(double dtime)
{
    struct timespec rtimespec, mtime, timediff;

    dtime2mtimespec(dtime, &mtime);
    if (timespeciszero(&r2m_conv1.cval)) {
        r2m_calibrate(&r2m_conv1);
    } else {
        timespecsub2(&timediff, &mtime, &r2m_conv1.lastcal_mtime);
        if (timespeccmp(&timediff, >, &recal_ival)) {
            r2m_calibrate(&r2m_conv1);
        }
    }
    timespecadd2(&rtimespec, &mtime, &r2m_conv1.cval);
    return (timespec2dtime(&rtimespec));
}
