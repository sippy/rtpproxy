/*
 * Copyright (c) 2004-2006 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2006-2014 Sippy Software, Inc., http://www.sippysoft.com
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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "rtpp_debug.h"
#include "rtpp_types.h"
#include "rtpp_hash_table.h"
#include "rtpp_pearson.h"
#include "rtpp_refcnt.h"
#include "rtpp_mallocs.h"

enum rtpp_hte_types {rtpp_hte_naive_t = 0, rtpp_hte_refcnt_t};

#define	RTPP_HT_LEN	256

struct rtpp_hash_table_entry {
    struct rtpp_hash_table_entry *prev;
    struct rtpp_hash_table_entry *next;
    void *sptr;
    union {
        char *ch;
        uint64_t u64;
        uint32_t u32;
        uint16_t u16;
    } key;
    uint8_t hash;
    enum rtpp_hte_types hte_type;
    char chstor[0];
};

struct rtpp_hash_table_priv
{
    struct rtpp_pearson rp;
    struct rtpp_hash_table_entry *hash_table[RTPP_HT_LEN];
    pthread_mutex_t hash_table_lock;
    int hte_num;
    enum rtpp_ht_key_types key_type;
    int flags;
};

struct rtpp_hash_table_full
{
    struct rtpp_hash_table pub;
    struct rtpp_hash_table_priv pvt;
};

#if 0
static struct rtpp_hash_table_entry * hash_table_append(struct rtpp_hash_table *self, const void *key, void *sptr);
#endif
static struct rtpp_hash_table_entry * hash_table_append_refcnt(struct rtpp_hash_table *self, const void *key, struct rtpp_refcnt *);
static void hash_table_remove(struct rtpp_hash_table *self, const void *key, struct rtpp_hash_table_entry * sp);
static void hash_table_remove_nc(struct rtpp_hash_table *self, struct rtpp_hash_table_entry * sp);
static struct rtpp_refcnt * hash_table_remove_by_key(struct rtpp_hash_table *self, const void *key);
#if 0
static struct rtpp_hash_table_entry * hash_table_findfirst(struct rtpp_hash_table *self, const void *key, void **sptrp);
static struct rtpp_hash_table_entry * hash_table_findnext(struct rtpp_hash_table *self, struct rtpp_hash_table_entry *psp, void **sptrp);
#endif
static struct rtpp_refcnt * hash_table_find(struct rtpp_hash_table *self, const void *key);
static void hash_table_foreach(struct rtpp_hash_table *self, rtpp_hash_table_match_t, void *);
static void hash_table_foreach_key(struct rtpp_hash_table *, const void *,
  rtpp_hash_table_match_t, void *);
static void hash_table_dtor(struct rtpp_hash_table *self);
static int hash_table_get_length(struct rtpp_hash_table *self);
static int hash_table_purge(struct rtpp_hash_table *self);

struct rtpp_hash_table *
rtpp_hash_table_ctor(enum rtpp_ht_key_types key_type, int flags)
{
    struct rtpp_hash_table_full *rp;
    struct rtpp_hash_table *pub;
    struct rtpp_hash_table_priv *pvt;

    rp = rtpp_zmalloc(sizeof(struct rtpp_hash_table_full));
    if (rp == NULL) {
        return (NULL);
    }
    pvt = &(rp->pvt);
    pvt->key_type = key_type;
    pvt->flags = flags;
    pub = &(rp->pub);
#if 0
    pub->append = &hash_table_append;
#endif
    pub->append_refcnt = &hash_table_append_refcnt;
    pub->remove = &hash_table_remove;
    pub->remove_nc = &hash_table_remove_nc;
    pub->remove_by_key = &hash_table_remove_by_key;
#if 0
    pub->findfirst = &hash_table_findfirst;
    pub->findnext = &hash_table_findnext;
#endif
    pub->find = &hash_table_find;
    pub->foreach = &hash_table_foreach;
    pub->foreach_key = &hash_table_foreach_key;
    pub->dtor = &hash_table_dtor;
    pub->get_length = &hash_table_get_length;
    pub->purge = &hash_table_purge;
    pthread_mutex_init(&pvt->hash_table_lock, NULL);
    rtpp_pearson_shuffle(&pvt->rp);
    pub->pvt = pvt;
    return (pub);
}

static void
hash_table_dtor(struct rtpp_hash_table *self)
{
    struct rtpp_hash_table_entry *sp, *sp_next;
    struct rtpp_hash_table_priv *pvt;
    int i;

    pvt = self->pvt;
    for (i = 0; i < RTPP_HT_LEN; i++) {
        sp = pvt->hash_table[i];
        if (sp == NULL)
            continue;
        do {
            sp_next = sp->next;
            if (sp->hte_type == rtpp_hte_refcnt_t) {
                CALL_SMETHOD((struct rtpp_refcnt *)sp->sptr, decref);
            }
            free(sp);
            sp = sp_next;
            pvt->hte_num -= 1;
        } while (sp != NULL);
    }
    pthread_mutex_destroy(&pvt->hash_table_lock);
    RTPP_DBG_ASSERT(pvt->hte_num == 0);

    free(self);
}

static inline uint8_t
rtpp_ht_hashkey(struct rtpp_hash_table_priv *pvt, const void *key)
{

    switch (pvt->key_type) {
    case rtpp_ht_key_str_t:
        return rtpp_pearson_hash8(&pvt->rp, key, NULL);

    case rtpp_ht_key_u16_t:
        return rtpp_pearson_hash8b(&pvt->rp, key, sizeof(uint16_t));

    case rtpp_ht_key_u32_t:
        return rtpp_pearson_hash8b(&pvt->rp, key, sizeof(uint32_t));

    case rtpp_ht_key_u64_t:
        return rtpp_pearson_hash8b(&pvt->rp, key, sizeof(uint64_t));

    default:
	abort();
    }
}

static inline int
rtpp_ht_cmpkey(struct rtpp_hash_table_priv *pvt,
  struct rtpp_hash_table_entry *sp, const void *key)
{
    switch (pvt->key_type) {
    case rtpp_ht_key_str_t:
        return (strcmp(sp->key.ch, key) == 0);

    case rtpp_ht_key_u16_t:
        return (sp->key.u16 == *(const uint16_t *)key);

    case rtpp_ht_key_u32_t:
        return (sp->key.u32 == *(const uint32_t *)key);

    case rtpp_ht_key_u64_t:
        return (sp->key.u64 == *(const uint64_t *)key);

    default:
	abort();
    }
}

static inline int
rtpp_ht_cmpkey2(struct rtpp_hash_table_priv *pvt,
  struct rtpp_hash_table_entry *sp1, struct rtpp_hash_table_entry *sp2)
{
    switch (pvt->key_type) {
    case rtpp_ht_key_str_t:
        return (strcmp(sp1->key.ch, sp2->key.ch) == 0);

    case rtpp_ht_key_u16_t:
        return (sp1->key.u16 == sp2->key.u16);

    case rtpp_ht_key_u32_t:
        return (sp1->key.u32 == sp2->key.u32);

    case rtpp_ht_key_u64_t:
        return (sp1->key.u64 == sp2->key.u64);

    default:
        abort();
    }
}

static struct rtpp_hash_table_entry *
hash_table_append_raw(struct rtpp_hash_table *self, const void *key,
  void *sptr, enum rtpp_hte_types htype)
{
    int malen, klen;
    struct rtpp_hash_table_entry *sp, *tsp, *tsp1;
    struct rtpp_hash_table_priv *pvt;

    pvt = self->pvt;
    if (pvt->key_type == rtpp_ht_key_str_t) {
        klen = strlen(key);
        malen = sizeof(struct rtpp_hash_table_entry) + klen + 1;
    } else {
        malen = sizeof(struct rtpp_hash_table_entry);
    }
    sp = rtpp_zmalloc(malen);
    if (sp == NULL) {
        return (NULL);
    }
    sp->sptr = sptr;
    sp->hte_type = htype;

    sp->hash = rtpp_ht_hashkey(pvt, key);

    switch (pvt->key_type) {
    case rtpp_ht_key_str_t:
        sp->key.ch = &sp->chstor[0];
        memcpy(sp->key.ch, key, klen);
        break;

    case rtpp_ht_key_u16_t:
        sp->key.u16 = *(const uint16_t *)key;
        break;

    case rtpp_ht_key_u32_t:
        sp->key.u32 = *(const uint32_t *)key;
        break;

    case rtpp_ht_key_u64_t:
        sp->key.u64 = *(const uint64_t *)key;
        break;
    }

    pthread_mutex_lock(&pvt->hash_table_lock);
    tsp = pvt->hash_table[sp->hash];
    if (tsp == NULL) {
       	pvt->hash_table[sp->hash] = sp;
    } else {
        for (tsp1 = tsp; tsp1 != NULL; tsp1 = tsp1->next) {
            tsp = tsp1;
            if ((pvt->flags & RTPP_HT_NODUPS) == 0) {
                continue;
            }
            if (rtpp_ht_cmpkey2(pvt, sp, tsp) == 0) {
                continue;
            }
            /* Duplicate detected, reject / abort */
            if ((pvt->flags & RTPP_HT_DUP_ABRT) != 0) {
                abort();
            }
            pthread_mutex_unlock(&pvt->hash_table_lock);
            free(sp);
            return (NULL);
        }
        tsp->next = sp;
        sp->prev = tsp;
    }
    pvt->hte_num += 1;
    pthread_mutex_unlock(&pvt->hash_table_lock);
    return (sp);
}

#if 0
static struct rtpp_hash_table_entry *
hash_table_append(struct rtpp_hash_table *self, const void *key, void *sptr)
{

    return (hash_table_append_raw(self, key, sptr, rtpp_hte_naive_t));
}
#endif

static struct rtpp_hash_table_entry *
hash_table_append_refcnt(struct rtpp_hash_table *self, const void *key,
  struct rtpp_refcnt *rptr)
{
    static struct rtpp_hash_table_entry *rval;

    CALL_SMETHOD(rptr, incref);
    rval = hash_table_append_raw(self, key, rptr, rtpp_hte_refcnt_t);
    if (rval == NULL) {
        CALL_SMETHOD(rptr, decref);
        return (NULL);
    }
    return (rval);
}

static inline void
hash_table_remove_locked(struct rtpp_hash_table_priv *pvt,
  struct rtpp_hash_table_entry *sp, uint8_t hash)
{

    if (sp->prev != NULL) {
        sp->prev->next = sp->next;
        if (sp->next != NULL) {
            sp->next->prev = sp->prev;
        }
    } else {
        /* Make sure we are removing the right session */
        RTPP_DBG_ASSERT(pvt->hash_table[hash] == sp);
        pvt->hash_table[hash] = sp->next;
        if (sp->next != NULL) {
            sp->next->prev = NULL;
        }
    }
    pvt->hte_num -= 1;
}

static void
hash_table_remove(struct rtpp_hash_table *self, const void *key,
  struct rtpp_hash_table_entry * sp)
{
    uint8_t hash;
    struct rtpp_hash_table_priv *pvt;

    pvt = self->pvt;
    hash = rtpp_ht_hashkey(pvt, key);
    pthread_mutex_lock(&pvt->hash_table_lock);
    hash_table_remove_locked(pvt, sp, hash);
    pthread_mutex_unlock(&pvt->hash_table_lock);
    if (sp->hte_type == rtpp_hte_refcnt_t) {
        CALL_SMETHOD((struct rtpp_refcnt *)sp->sptr, decref);
    }
    free(sp);
}

static void
hash_table_remove_nc(struct rtpp_hash_table *self, struct rtpp_hash_table_entry * sp)
{
    struct rtpp_hash_table_priv *pvt;

    pvt = self->pvt;
    pthread_mutex_lock(&pvt->hash_table_lock);
    hash_table_remove_locked(pvt, sp, sp->hash);
    pthread_mutex_unlock(&pvt->hash_table_lock);
    if (sp->hte_type == rtpp_hte_refcnt_t) {
        CALL_SMETHOD((struct rtpp_refcnt *)sp->sptr, decref);
    }
    free(sp);
}

static struct rtpp_refcnt *
hash_table_remove_by_key(struct rtpp_hash_table *self, const void *key)
{
    uint8_t hash;
    struct rtpp_hash_table_entry *sp;
    struct rtpp_hash_table_priv *pvt;
    struct rtpp_refcnt *rptr;

    pvt = self->pvt;
    hash = rtpp_ht_hashkey(pvt, key);
    pthread_mutex_lock(&pvt->hash_table_lock);
    for (sp = pvt->hash_table[hash]; sp != NULL; sp = sp->next) {
        if (rtpp_ht_cmpkey(pvt, sp, key)) {
            break;
        }
    }
    if (sp == NULL) {
        pthread_mutex_unlock(&pvt->hash_table_lock);
        return (NULL);
    }
    hash_table_remove_locked(pvt, sp, hash);
    pthread_mutex_unlock(&pvt->hash_table_lock);
    if (sp->hte_type == rtpp_hte_refcnt_t) {
        CALL_SMETHOD((struct rtpp_refcnt *)sp->sptr, decref);
    }
    rptr = sp->sptr;
    free(sp);
    return (rptr);
}

#if 0
static struct rtpp_hash_table_entry *
hash_table_findfirst(struct rtpp_hash_table *self, const void *key, void **sptrp)
{
    uint8_t hash;
    struct rtpp_hash_table_entry *sp;
    struct rtpp_hash_table_priv *pvt;

    pvt = self->pvt;
    hash = rtpp_ht_hashkey(pvt, key);
    pthread_mutex_lock(&pvt->hash_table_lock);
    for (sp = pvt->hash_table[hash]; sp != NULL; sp = sp->next) {
	if (rtpp_ht_cmpkey(pvt, sp, key)) {
            *sptrp = sp->sptr;
	    break;
	}
    }
    pthread_mutex_unlock(&pvt->hash_table_lock);
    return (sp);
}

static struct rtpp_hash_table_entry *
hash_table_findnext(struct rtpp_hash_table *self, struct rtpp_hash_table_entry *psp, void **sptrp)
{
    struct rtpp_hash_table_entry *sp;
    struct rtpp_hash_table_priv *pvt;

    pvt = self->pvt;
    pthread_mutex_lock(&pvt->hash_table_lock);
    for (sp = psp->next; sp != NULL; sp = sp->next) {
	if (rtpp_ht_cmpkey2(pvt, sp, psp)) {
            *sptrp = sp->sptr;
	    break;
	}
    }
    pthread_mutex_unlock(&pvt->hash_table_lock);
    return (sp);
}
#endif

static struct rtpp_refcnt *
hash_table_find(struct rtpp_hash_table *self, const void *key)
{
    struct rtpp_refcnt *rptr;
    struct rtpp_hash_table_priv *pvt;
    struct rtpp_hash_table_entry *sp;
    uint8_t hash;

    pvt = self->pvt;
    hash = rtpp_ht_hashkey(pvt, key);
    pthread_mutex_lock(&pvt->hash_table_lock);
    for (sp = pvt->hash_table[hash]; sp != NULL; sp = sp->next) {
        if (rtpp_ht_cmpkey(pvt, sp, key)) {
            break;
        }
    }
    if (sp != NULL) {
        RTPP_DBG_ASSERT(sp->hte_type == rtpp_hte_refcnt_t);
        rptr = (struct rtpp_refcnt *)sp->sptr;
        CALL_SMETHOD(rptr, incref);
    } else {
        rptr = NULL;
    }
    pthread_mutex_unlock(&pvt->hash_table_lock);
    return (rptr);
}

#define VDTE_MVAL(m) (((m) & ~(RTPP_HT_MATCH_BRK | RTPP_HT_MATCH_DEL)) == 0)

static void
hash_table_foreach(struct rtpp_hash_table *self,
  rtpp_hash_table_match_t hte_ematch, void *marg)
{
    struct rtpp_hash_table_entry *sp, *sp_next;
    struct rtpp_hash_table_priv *pvt;
    struct rtpp_refcnt *rptr;
    int i, mval;

    pvt = self->pvt;
    pthread_mutex_lock(&pvt->hash_table_lock);
    if (pvt->hte_num == 0) {
        pthread_mutex_unlock(&pvt->hash_table_lock);
        return;
    }
    for (i = 0; i < RTPP_HT_LEN; i++) {
        for (sp = pvt->hash_table[i]; sp != NULL; sp = sp_next) {
            RTPP_DBG_ASSERT(sp->hte_type == rtpp_hte_refcnt_t);
            rptr = (struct rtpp_refcnt *)sp->sptr;
            sp_next = sp->next;
            mval = hte_ematch(CALL_SMETHOD(rptr, getdata), marg);
            RTPP_DBG_ASSERT(VDTE_MVAL(mval));
            if (mval & RTPP_HT_MATCH_DEL) {
                hash_table_remove_locked(pvt, sp, sp->hash);
                CALL_SMETHOD(rptr, decref);
                free(sp);
            }
            if (mval & RTPP_HT_MATCH_BRK) {
                break;
            }
        }
    }
    pthread_mutex_unlock(&pvt->hash_table_lock);
}

static void
hash_table_foreach_key(struct rtpp_hash_table *self, const void *key,
  rtpp_hash_table_match_t hte_ematch, void *marg)
{
    struct rtpp_hash_table_entry *sp, *sp_next;
    struct rtpp_hash_table_priv *pvt;
    struct rtpp_refcnt *rptr;
    int mval;
    uint8_t hash;

    pvt = self->pvt;
    hash = rtpp_ht_hashkey(pvt, key);
    pthread_mutex_lock(&pvt->hash_table_lock);
    if (pvt->hte_num == 0 || pvt->hash_table[hash] == NULL) {
        pthread_mutex_unlock(&pvt->hash_table_lock);
        return;
    }
    for (sp = pvt->hash_table[hash]; sp != NULL; sp = sp_next) {
        sp_next = sp->next;
        if (!rtpp_ht_cmpkey(pvt, sp, key)) {
            continue;
        }
        RTPP_DBG_ASSERT(sp->hte_type == rtpp_hte_refcnt_t);
        rptr = (struct rtpp_refcnt *)sp->sptr;
        mval = hte_ematch(CALL_SMETHOD(rptr, getdata), marg);
        RTPP_DBG_ASSERT(VDTE_MVAL(mval));
        if (mval & RTPP_HT_MATCH_DEL) {
            hash_table_remove_locked(pvt, sp, sp->hash);
            CALL_SMETHOD(rptr, decref);
            free(sp);
        }
        if (mval & RTPP_HT_MATCH_BRK) {
            break;
        }
    }
    pthread_mutex_unlock(&pvt->hash_table_lock);
}

static int
hash_table_get_length(struct rtpp_hash_table *self)
{
    struct rtpp_hash_table_priv *pvt;
    int rval;

    pvt = self->pvt;
    pthread_mutex_lock(&pvt->hash_table_lock);
    rval = pvt->hte_num;
    pthread_mutex_unlock(&pvt->hash_table_lock);

    return (rval);
}

static int
hash_table_purge_f(void *dp, void *ap)
{
    int *npurgedp;

    npurgedp = (int *)ap;
    *npurgedp += 1;
    return (RTPP_HT_MATCH_DEL);
}

static int
hash_table_purge(struct rtpp_hash_table *self)
{
    int npurged;

    npurged = 0;
    CALL_METHOD(self, foreach, hash_table_purge_f, &npurged);
    return (npurged);
}
