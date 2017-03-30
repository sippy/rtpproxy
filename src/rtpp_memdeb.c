/*
 * Copyright (c) 2014 Sippy Software, Inc., http://www.sippysoft.com
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

/*
 * Simple memory debug layer to track any unallocated memory as well as to
 * catch any other common mistakes, such as double free or freeing of
 * unallocated memory. Our attitude here is "fail with core dump early" if
 * some error of inconsistency is found to aid debugging. Some extra smarts
 * can be added, such as guard area to detect any buffer overflows.
 */

#include <sys/types.h>
#include <pthread.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#include "rtpp_log.h"
#include "rtpp_types.h"
#include "rtpp_refcnt.h"
#include "rtpp_log_obj.h"
#include "rtpp_memdeb.h"
#include "rtpp_memdeb_internal.h"
#include "rtpp_memdeb_stats.h"

#undef malloc
#undef free
#undef realloc
#undef strdup
#undef asprintf
#undef vasprintf

#define UNUSED(x) (void)(x)

#define MEMDEB_SIGNATURE 0x8b26e00041dfdec6UL

#define MEMDEB_SIGNATURE_ALLOC(x) (MEMDEB_SIGNATURE ^ (uint64_t)(x))
#define MEMDEB_SIGNATURE_FREE(x) (~MEMDEB_SIGNATURE_ALLOC(x))

#define MEMDEB_SIG_PRIV_SALT 0x7d442e4532bb9ef0UL
#define MEMDEB_SIGNATURE_PRIV(x) \
  (MEMDEB_SIG_PRIV_SALT ^ (uint64_t)(x))

#define MEMDEB_GUARD_SIZE 8

struct memdeb_node
{
    uint64_t magic;
    const char *fname;
    int linen;
    const char *funcn;
    struct memdeb_stats mstats;
    struct memdeb_node *next;
};

struct memdeb_pfx
{
    struct memdeb_node *mnp;
    size_t asize;
    uint64_t magic;
    /* Use longest datatype to ensure proper alignment */
    long long real_data[0];
};

struct rtpp_memdeb_au {
    const char *funcn;
    int max_nunalloc;
    const char *why;
};

#define MAX_APPROVED 10

struct rtpp_memdeb_priv {
    uint64_t magic;
    struct memdeb_node *nodes;
    pthread_mutex_t mutex;
    struct rtpp_memdeb_au au[MAX_APPROVED];
    struct rtpp_log *_md_glog;
};

void *
rtpp_memdeb_init()
{
    struct rtpp_memdeb_priv *pvt;

    pvt = malloc(sizeof(struct rtpp_memdeb_priv));
    if (pvt == NULL) {
        return (NULL);
    }
    memset(pvt, '\0', sizeof(struct rtpp_memdeb_priv));
    pthread_mutex_init(&pvt->mutex, NULL);
    pvt->magic = MEMDEB_SIGNATURE_PRIV(pvt);
    return (pvt);
}

#define CHK_PRIV(pvt, p) { \
        (pvt) = (struct rtpp_memdeb_priv *)(p); \
        if (pvt->magic != MEMDEB_SIGNATURE_PRIV(pvt)) { \
            RTPP_MEMDEB_REPORT(NULL, "%s(): bogus private pointer: %p", \
              __func__, pvt); \
            abort(); \
        } \
    }

void
rtpp_memdeb_dtor(void *p)
{
    struct rtpp_memdeb_priv *pvt;

    CHK_PRIV(pvt, p);
    if (pvt->_md_glog != NULL) {
        CALL_SMETHOD(pvt->_md_glog->rcnt, decref);
    }
    pvt->magic = MEMDEB_SIGNATURE_FREE(pvt);
    pthread_mutex_destroy(&pvt->mutex);
    free(pvt);
    return;
}

void
rtpp_memdeb_setlog(void *p, struct rtpp_log *log)
{
    struct rtpp_memdeb_priv *pvt;

    CHK_PRIV(pvt, p);
    CALL_SMETHOD(log->rcnt, incref);
    pvt->_md_glog = log;
}

void
rtpp_memdeb_approve(void *p, const char *funcn, int max_nunalloc,
  const char *why)
{
    int i;
    struct rtpp_memdeb_priv *pvt;

    CHK_PRIV(pvt, p);
    for (i = 0; i < MAX_APPROVED; i++) {
        if (pvt->au[i].funcn != NULL)
            continue;
        pvt->au[i].funcn = funcn;
        pvt->au[i].max_nunalloc = max_nunalloc;
        pvt->au[i].why = why;
        return;
    }
}

static struct memdeb_node *
rtpp_memdeb_nget(struct rtpp_memdeb_priv *pvt, const char *fname, int linen,
  const char *funcn, int doalloc)
{
    struct memdeb_node *rval, *mnp, *lastnode;

    pthread_mutex_lock(&pvt->mutex);
    lastnode = NULL;
    for (mnp = pvt->nodes; mnp != NULL; mnp = mnp->next) {
        if (mnp->magic != MEMDEB_SIGNATURE) {
            /* nodelist is corrupt */
            RTPP_MEMDEB_REPORT(pvt->_md_glog, "Nodelist %p is corrupt", mnp);
            abort();
        }
        if (mnp->fname == fname && mnp->linen == linen && mnp->funcn == funcn)
            return (mnp);
        lastnode = mnp;
    }
    if (doalloc == 0) {
        pthread_mutex_unlock(&pvt->mutex);
        return (NULL);
    }
    rval = malloc(sizeof(struct memdeb_node));
    if (rval == NULL) {
        RTPP_MEMDEB_REPORT(pvt->_md_glog, "Allocation for the new nodelist failed");
        abort();
    }
    memset(rval, '\0', sizeof(struct memdeb_node));
    rval->magic = MEMDEB_SIGNATURE;
    rval->fname = fname;
    rval->linen = linen;
    rval->funcn = funcn;
    if (pvt->nodes == NULL) {
        pvt->nodes = rval;
    } else {
        lastnode->next = rval;
    }
    return (rval);
}

#define CHK_PRIV_VRB(pvt, p, fname, linen, funcn) { \
        (pvt) = (struct rtpp_memdeb_priv *)(p); \
        if (pvt->magic != MEMDEB_SIGNATURE_PRIV(pvt)) { \
            RTPP_MEMDEB_REPORT(NULL, "%s(): bogus private pointer: %p", \
              __func__, pvt); \
            RTPP_MEMDEB_REPORT(NULL, "    called from %s+%d, %s()", \
              fname, linen, funcn); \
            abort(); \
        } \
    }

void *
rtpp_memdeb_malloc(size_t size, void *p, const char *fname, int linen, const char *funcn)
{
    struct memdeb_node *mnp;
    struct memdeb_pfx *mpf;
    unsigned char *gp;
    uint64_t guard;
    struct rtpp_memdeb_priv *pvt;

    CHK_PRIV_VRB(pvt, p, fname, linen, funcn);
    mpf = malloc(offsetof(struct memdeb_pfx, real_data) + size + MEMDEB_GUARD_SIZE);
    mnp = rtpp_memdeb_nget(pvt, fname, linen, funcn, 1);
    if (mpf == NULL) {
        mnp->mstats.afails++;
        pthread_mutex_unlock(&pvt->mutex);
        return (NULL);
    }
    mnp->mstats.nalloc++;
    mnp->mstats.balloc += size;
    mpf->magic = MEMDEB_SIGNATURE_ALLOC(mpf);
    pthread_mutex_unlock(&pvt->mutex);
    mpf->asize = size;
    mpf->mnp = mnp;
    gp = (unsigned char *)mpf->real_data + size;
    guard = MEMDEB_SIGNATURE_ALLOC(gp);
    memcpy(gp, &guard, MEMDEB_GUARD_SIZE);
    return (mpf->real_data);
}

static struct memdeb_pfx *
ptr2mpf(struct rtpp_memdeb_priv *pvt, void *ptr)
{
    char *cp;
    struct memdeb_pfx *mpf;

    cp = ptr;
    cp -= offsetof(struct memdeb_pfx, real_data);
    mpf = (struct memdeb_pfx *)cp;

    if (mpf->magic != MEMDEB_SIGNATURE_ALLOC(mpf)) {
        /* Random of de-allocated pointer */
        RTPP_MEMDEB_REPORT(pvt->_md_glog, "Random of de-allocated pointer");
        abort();
    }
    if (mpf->mnp->magic != MEMDEB_SIGNATURE) {
        /* Free of unallocated pointer or nodelist is corrupt */
        RTPP_MEMDEB_REPORT(pvt->_md_glog, "Nodelist %p is corrupt", mpf->mnp);
        abort();
    }
    return (mpf);
}

void
rtpp_memdeb_free(void *ptr, void *p, const char *fname, int linen, const char *funcn)
{
    UNUSED(fname);
    UNUSED(linen);
    UNUSED(funcn);
    struct memdeb_pfx *mpf;
    unsigned char *gp;
    uint64_t guard;
    struct rtpp_memdeb_priv *pvt;

    CHK_PRIV_VRB(pvt, p, fname, linen, funcn);
    mpf = ptr2mpf(pvt, ptr);
    gp = (unsigned char *)mpf->real_data + mpf->asize;
    guard = MEMDEB_SIGNATURE_ALLOC(gp);
    if (memcmp(gp, &guard, MEMDEB_GUARD_SIZE) != 0) {
        /* Guard is b0rken, probably out-of-bound write */
        RTPP_MEMDEB_REPORT(pvt->_md_glog, "Guard is b0rken, probably out-of-bound write");
        abort();
    }
    pthread_mutex_lock(&pvt->mutex);
    mpf->mnp->mstats.nfree++;
    mpf->mnp->mstats.bfree += mpf->asize;
    mpf->magic = MEMDEB_SIGNATURE_FREE(mpf);
    pthread_mutex_unlock(&pvt->mutex);
    return free(mpf);
}

void *
rtpp_memdeb_realloc(void *ptr, size_t size, void *p, const char *fname, int linen,
  const char *funcn)
{
    UNUSED(fname);
    UNUSED(linen);
    UNUSED(funcn);
    struct memdeb_pfx *mpf, *new_mpf;
    char *cp;
    uint64_t sig_save;
    unsigned char *gp;
    uint64_t guard;
    struct rtpp_memdeb_priv *pvt;

    CHK_PRIV_VRB(pvt, p, fname, linen, funcn);
    if (ptr == NULL) {
        return (rtpp_memdeb_malloc(size, pvt, fname, linen, funcn));
    }
    mpf = ptr2mpf(pvt, ptr);
    sig_save = MEMDEB_SIGNATURE_ALLOC(mpf);
    pthread_mutex_lock(&pvt->mutex);
    mpf->magic = MEMDEB_SIGNATURE_FREE(mpf);
    pthread_mutex_unlock(&pvt->mutex);
    cp = realloc(mpf, size + offsetof(struct memdeb_pfx, real_data) + MEMDEB_GUARD_SIZE);
    if (cp == NULL) {
        pthread_mutex_lock(&pvt->mutex);
        mpf->magic = sig_save;
        mpf->mnp->mstats.afails++;
        pthread_mutex_unlock(&pvt->mutex);
        return (cp);
    }
    new_mpf = (struct memdeb_pfx *)cp;
    if (new_mpf != mpf) {
        sig_save = MEMDEB_SIGNATURE_ALLOC(new_mpf);
    }
    pthread_mutex_lock(&pvt->mutex);
    new_mpf->magic = sig_save;
    new_mpf->mnp->mstats.nrealloc++;
    new_mpf->mnp->mstats.brealloc += size;
    new_mpf->mnp->mstats.balloc += size - new_mpf->asize;
    pthread_mutex_unlock(&pvt->mutex);
    new_mpf->asize = size;
    gp = (unsigned char *)new_mpf->real_data + size;
    guard = MEMDEB_SIGNATURE_ALLOC(gp);
    memcpy(gp, &guard, MEMDEB_GUARD_SIZE);
    return (new_mpf->real_data);
}

char *
rtpp_memdeb_strdup(const char *ptr, void *p, const char *fname, int linen, \
  const char *funcn)
{
    struct memdeb_node *mnp;
    struct memdeb_pfx *mpf;
    size_t size;
    unsigned char *gp;
    uint64_t guard;
    struct rtpp_memdeb_priv *pvt;

    CHK_PRIV_VRB(pvt, p, fname, linen, funcn);
    size = strlen(ptr) + 1;
    mpf = malloc(size + offsetof(struct memdeb_pfx, real_data) + MEMDEB_GUARD_SIZE);
    mnp = rtpp_memdeb_nget(pvt, fname, linen, funcn, 1);
    if (mpf == NULL) {
        mnp->mstats.afails++;
        pthread_mutex_unlock(&pvt->mutex);
        return (NULL);
    }
    mnp->mstats.nalloc++;
    mnp->mstats.balloc += size;
    pthread_mutex_unlock(&pvt->mutex);
    mpf->mnp = mnp;
    mpf->asize = size;
    memcpy(mpf->real_data, ptr, size);
    mpf->magic = MEMDEB_SIGNATURE_ALLOC(mpf);
    gp = (unsigned char *)mpf->real_data + size;
    guard = MEMDEB_SIGNATURE_ALLOC(gp);
    memcpy(gp, &guard, MEMDEB_GUARD_SIZE);
    return ((char *)mpf->real_data);
}

int
rtpp_memdeb_asprintf(char **pp, const char *fmt, void *p, const char *fname,
  int linen, const char *funcn, ...)
{
    va_list ap;
    int rval;

    va_start(ap, funcn);
    rval = rtpp_memdeb_vasprintf(pp, fmt, p, fname, linen, funcn, ap);
    va_end(ap);
    return (rval);
}

int
rtpp_memdeb_vasprintf(char **pp, const char *fmt, void *p, const char *fname,
  int linen, const char *funcn, va_list ap)
{
    int rval;
    void *tp;

    rval = vasprintf(pp, fmt, ap);
    if (rval <= 0) {
        return (rval);
    }
    tp = rtpp_memdeb_malloc(rval + 1, p, fname, linen, funcn);
    if (tp == NULL) {
        free(*pp);
        *pp = NULL;
        return (-1);
    }
    memcpy(tp, *pp, rval + 1);
    free(*pp);
    *pp = tp;
    return (rval);
}

static int
is_approved(struct rtpp_memdeb_priv *pvt, const char *funcn)
{
    int i;

    for (i = 0; pvt->au[i].funcn != NULL && i < MAX_APPROVED; i++) {
        if (strcmp(pvt->au[i].funcn, funcn) != 0)
            continue;
        return (pvt->au[i].max_nunalloc);
    }
    return (0);
}

int
rtpp_memdeb_dumpstats(void *p, int nostdout)
{
    struct memdeb_node *mnp;
    int errors_found, max_nunalloc;
    int64_t nunalloc;
    struct rtpp_log *log;
    struct rtpp_memdeb_priv *pvt;

    CHK_PRIV(pvt, p);
    errors_found = 0;
    log = pvt->_md_glog;
    pthread_mutex_lock(&pvt->mutex);
    for (mnp = pvt->nodes; mnp != NULL; mnp = mnp->next) {
        nunalloc = mnp->mstats.nalloc - mnp->mstats.nfree;
        if (mnp->mstats.afails == 0) {
            if (mnp->mstats.nalloc == 0)
                continue;
            if (mnp->mstats.nalloc == mnp->mstats.nfree)
                continue;
            if (nunalloc <= mnp->mstats.nunalloc_baseln)
                continue;
        }
        if (nunalloc > 0) {
            max_nunalloc = is_approved(pvt, mnp->funcn);
            if (max_nunalloc > 0 && nunalloc <= max_nunalloc)
                continue;
        }
        if (errors_found == 0) {
            RTPP_MEMDEB_REPORT2(log, nostdout,
              "MEMDEB suspicious allocations:");
        }
        errors_found++;
        RTPP_MEMDEB_REPORT2(log, nostdout,
          "  %s+%d, %s(): nalloc = %" PRId64 ", balloc = %" PRId64 ", nfree = %"
          PRId64 ", bfree = %" PRId64 ", afails = %" PRId64 ", nunalloc_baseln"
          " = %" PRId64, mnp->fname, mnp->linen, mnp->funcn, mnp->mstats.nalloc,
          mnp->mstats.balloc, mnp->mstats.nfree, mnp->mstats.bfree,
          mnp->mstats.afails, mnp->mstats.nunalloc_baseln);
    }
    pthread_mutex_unlock(&pvt->mutex);
    if (errors_found == 0) {
        RTPP_MEMDEB_REPORT2(log, nostdout,
          "MEMDEB: all clear");
    } else {
        RTPP_MEMDEB_REPORT2(log, nostdout,
          "MEMDEB: errors found: %d", errors_found);
    }
    return (errors_found);
}

void
rtpp_memdeb_setbaseln(void *p)
{

    struct memdeb_node *mnp;
    struct rtpp_memdeb_priv *pvt;

    CHK_PRIV(pvt, p);
    pthread_mutex_lock(&pvt->mutex);
    for (mnp = pvt->nodes; mnp != NULL; mnp = mnp->next) {
        if (mnp->magic != MEMDEB_SIGNATURE) {
            /* Nodelist is corrupt */
            RTPP_MEMDEB_REPORT(pvt->_md_glog, "Nodelist %p is corrupt", mnp);
            abort();
        }
        if (mnp->mstats.nalloc == 0)
            continue;
        mnp->mstats.nunalloc_baseln = mnp->mstats.nalloc - mnp->mstats.nfree;
        mnp->mstats.bunalloc_baseln = mnp->mstats.balloc - mnp->mstats.bfree;
    }
    pthread_mutex_unlock(&pvt->mutex);
}

int
rtpp_memdeb_get_stats(void *p, const char *fname, const char *funcn,
  struct memdeb_stats *mstatp)
{
    struct memdeb_node *mnp;
    int nmatches;
    struct rtpp_memdeb_priv *pvt;

    CHK_PRIV(pvt, p);
    nmatches = 0;
    pthread_mutex_lock(&pvt->mutex);
    for (mnp = pvt->nodes; mnp != NULL; mnp = mnp->next) {
        if (mnp->magic != MEMDEB_SIGNATURE) {
            /* Nodelist is corrupt */
            RTPP_MEMDEB_REPORT(pvt->_md_glog, "Nodelist %p is corrupt", mnp);
            abort();
        }
        if (funcn != NULL && strcmp(funcn, mnp->funcn) != 0) {
            continue;
        }
        if (fname != NULL && strcmp(fname, mnp->fname) != 0) {
            continue;
        }
        RTPP_MD_STATS_ADD(mstatp, &mnp->mstats);
        nmatches += 1;
    }
    pthread_mutex_unlock(&pvt->mutex);
    return (nmatches);
}
