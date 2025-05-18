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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "rtpp_debug.h"
#include "rtpp_types.h"
#include "rtpp_hash_table.h"
#include "rtpp_hash_table_fin.h"
#include "rtpp_xxHash.h"
#include "rtpp_codeptr.h"
#include "rtpp_refcnt.h"
#include "rtpp_mallocs.h"

enum rtpp_hte_types {rtpp_hte_naive_t = 0, rtpp_hte_refcnt_t};

#define HT_GET(l1p, hash) ((l1p)->hash_table[(hash) & ((l1p)->ht_len - 1)])
#define HT_GETREF(l1p, hash) (&HT_GET(l1p, hash))

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
    uint64_t hash;
    size_t klen;
    enum rtpp_hte_types hte_type;
    char chstor[0];
};

struct rtpp_ht_cntrs {
    struct {
        /* Those are Collected */
        uint64_t dels;
        uint64_t ins;
        uint64_t cols;
    };
    struct {
        /* Those are Derived */
        float load_factor;
        float collision_rate;
        uint64_t nbckts_empty;
    };
};

struct rtpp_hash_table_l1
{
    int hte_num;
    size_t ht_len;
#if defined(RTPP_DEBUG)
    struct rtpp_ht_cntrs cntrs;
#endif
    struct rtpp_hash_table_entry *hash_table[0];
};

struct rtpp_hash_table_priv
{
    struct rtpp_hash_table pub;
    pthread_mutex_t hash_table_lock;
    enum rtpp_ht_key_types key_type;
    int flags;
    struct rtpp_hash_table_l1 *l1;
};

static struct rtpp_hash_table_entry * hash_table_append_refcnt(struct rtpp_hash_table *,
const void *, struct rtpp_refcnt *, struct rtpp_ht_opstats *);
static struct rtpp_hash_table_entry * hash_table_append_str_refcnt(struct rtpp_hash_table *,
  const rtpp_str_t *, struct rtpp_refcnt *, struct rtpp_ht_opstats *);
static void hash_table_remove(struct rtpp_hash_table *self, const void *key, struct rtpp_hash_table_entry * sp);
static void hash_table_remove_str(struct rtpp_hash_table *self,
  const rtpp_str_t *key, struct rtpp_hash_table_entry * sp);
static struct rtpp_refcnt * hash_table_remove_by_key(struct rtpp_hash_table *self,
  const void *key, struct rtpp_ht_opstats *);
static struct rtpp_refcnt * hash_table_transfer(struct rtpp_hash_table *self,
  const void *key, struct rtpp_hash_table *other, struct rtpp_ht_opstats *);
static struct rtpp_refcnt * hash_table_find(struct rtpp_hash_table *self, const void *key);
static struct rtpp_refcnt * hash_table_find_str(struct rtpp_hash_table *self, const rtpp_str_t *key);
static void hash_table_foreach(struct rtpp_hash_table *self, rtpp_hash_table_match_t,
  void *, struct rtpp_ht_opstats *);
static void hash_table_foreach_key(struct rtpp_hash_table *, const void *,
  rtpp_hash_table_match_t, void *);
static void hash_table_foreach_key_str(struct rtpp_hash_table *, const rtpp_str_t *,
  rtpp_hash_table_match_t, void *);
static void hash_table_dtor(struct rtpp_hash_table_priv *);
static int hash_table_get_length(struct rtpp_hash_table *self);
static int hash_table_purge(struct rtpp_hash_table *self);
static int hash_table_resize_locked(struct rtpp_hash_table_priv *, size_t);

DEFINE_SMETHODS(rtpp_hash_table,
    .append_refcnt = &hash_table_append_refcnt,
    .append_str_refcnt = &hash_table_append_str_refcnt,
    .remove = &hash_table_remove,
    .remove_str = &hash_table_remove_str,
    .remove_by_key = &hash_table_remove_by_key,
    .transfer = &hash_table_transfer,
    .find = &hash_table_find,
    .find_str = &hash_table_find_str,
    .foreach = &hash_table_foreach,
    .foreach_key = &hash_table_foreach_key,
    .foreach_key_str = &hash_table_foreach_key_str,
    .get_length = &hash_table_get_length,
    .purge = &hash_table_purge,
);

static size_t
rtpp_hash_table_l1_sizeof(size_t ht_len)
{

    return (sizeof(struct rtpp_hash_table_l1) +
      (sizeof(struct rtpp_hash_table_entry *) * ht_len));
}

struct rtpp_hash_table *
rtpp_hash_table_ctor(enum rtpp_ht_key_types key_type, int flags)
{
    struct rtpp_hash_table *pub;
    struct rtpp_hash_table_priv *pvt;
    int ht_len = 256;

    pvt = rtpp_rzmalloc(sizeof(struct rtpp_hash_table_priv), PVT_RCOFFS(pvt));
    if (pvt == NULL) {
        goto e0;
    }
    pvt->l1 = rtpp_zmalloc(rtpp_hash_table_l1_sizeof(ht_len));
    if (pvt->l1 == NULL) {
        goto e1;
    }
    if (pthread_mutex_init(&pvt->hash_table_lock, NULL) != 0)
        goto e2;
    pvt->key_type = key_type;
    pvt->flags = flags;
    pvt->l1->ht_len = ht_len;
    pub = &(pvt->pub);
    pvt->pub.seed = ((uint64_t)random()) << 32 | (uint64_t)random();
    PUBINST_FININIT(&pvt->pub, pvt, hash_table_dtor);
    return (pub);
e2:
    free(pvt->l1);
e1:
    RTPP_OBJ_DECREF(&(pvt->pub));
e0:
    return (NULL);
}

static void
hash_table_dtor(struct rtpp_hash_table_priv *pvt)
{
    struct rtpp_hash_table_entry *sp, *sp_next;
    int i;

    rtpp_hash_table_fin(&(pvt->pub));
    for (i = 0; i < pvt->l1->ht_len; i++) {
        sp = pvt->l1->hash_table[i];
        if (sp == NULL)
            continue;
        do {
            sp_next = sp->next;
            if (sp->hte_type == rtpp_hte_refcnt_t) {
                RC_DECREF((struct rtpp_refcnt *)sp->sptr);
            }
            free(sp);
            sp = sp_next;
            pvt->l1->hte_num -= 1;
        } while (sp != NULL);
    }
    pthread_mutex_destroy(&pvt->hash_table_lock);
    RTPP_DBG_ASSERT(pvt->l1->hte_num == 0);

    free(pvt->l1);
}

static inline uint64_t
rtpp_ht_hashkey(struct rtpp_hash_table_priv *pvt, const void *key, size_t ksize)
{

    return XXH64(key, ksize, pvt->pub.seed);
}

static inline size_t
rtpp_ht_get_keysize(struct rtpp_hash_table_priv *pvt, const void *key)
{
    switch (pvt->key_type) {
    case rtpp_ht_key_str_t:
        return (strlen(key));

    case rtpp_ht_key_u16_t:
        return (sizeof(uint16_t));

    case rtpp_ht_key_u32_t:
        return (sizeof(uint32_t));

    case rtpp_ht_key_u64_t:
        return (sizeof(uint64_t));

    default:
        abort();
    }
}


static inline int
rtpp_ht_cmpkey(struct rtpp_hash_table_priv *pvt,
  struct rtpp_hash_table_entry *sp, const void *key, size_t ksize)
{
    switch (pvt->key_type) {
    case rtpp_ht_key_str_t:
        return (sp->klen == ksize && memcmp(sp->key.ch, key, ksize) == 0);

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
        if (sp1->hash != sp2->hash)
            return (0);
        return (sp1->klen == sp2->klen &&
          memcmp(sp1->key.ch, sp2->key.ch, sp1->klen) == 0);

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

static void
hash_table_on_coll(struct rtpp_hash_table_l1 *l1p)
{
#if defined(RTPP_DEBUG)
    l1p->cntrs.cols += 1;
#endif
}

static void
hash_table_before_insert(struct rtpp_hash_table_l1 *l1p)
{
#if defined(RTPP_DEBUG)
    l1p->cntrs.ins += 1;
#endif
}

static void
hash_table_after_insert(struct rtpp_hash_table_l1 *l1p)
{
#if defined(RTPP_DEBUG)
    l1p->cntrs.load_factor = (float)l1p->hte_num / (float)l1p->ht_len;
    l1p->cntrs.collision_rate = (float)l1p->cntrs.cols / (float)l1p->cntrs.ins;
    l1p->cntrs.nbckts_empty = l1p->ht_len + l1p->cntrs.dels;
    l1p->cntrs.nbckts_empty -= l1p->cntrs.ins - l1p->cntrs.cols;
#endif
}

static int
hash_table_insert_locked(struct rtpp_hash_table_priv *pvt,
  struct rtpp_hash_table_l1 *l1p, struct rtpp_hash_table_entry *sp)
{
    struct rtpp_hash_table_entry **tspp, *tsp;

    hash_table_before_insert(l1p);
    tspp = HT_GETREF(l1p, sp->hash);
    tsp = *tspp;
    if (tsp == NULL) {
        *tspp = sp;
    } else {
        hash_table_on_coll(l1p);
        struct rtpp_hash_table_entry *tsp1;
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
            return (0);
        }
        tsp->next = sp;
        sp->prev = tsp;
    }
    l1p->hte_num += 1;
    hash_table_after_insert(l1p);
    return (1);
}

static struct rtpp_hash_table_entry *
hash_table_insert(struct rtpp_hash_table_priv *pvt, struct rtpp_hash_table_entry *sp,
  struct rtpp_ht_opstats *hosp)
{

    pthread_mutex_lock(&pvt->hash_table_lock);
    if (hash_table_insert_locked(pvt, pvt->l1, sp) == 0) {
        pthread_mutex_unlock(&pvt->hash_table_lock);
        free(sp);
        return (NULL);
    }
    if (((float)pvt->l1->hte_num / (float)pvt->l1->ht_len) > 0.7)
        hash_table_resize_locked(pvt, pvt->l1->ht_len * 2);
    if (hosp != NULL && pvt->l1->hte_num == 1)
        hosp->first = 1;
    pthread_mutex_unlock(&pvt->hash_table_lock);
    return (sp);
}

static struct rtpp_hash_table_entry *
hash_table_append_raw(struct rtpp_hash_table *self, const void *key,
  size_t klen, void *sptr, enum rtpp_hte_types htype,
  struct rtpp_ht_opstats *hosp)
{
    int malen;
    struct rtpp_hash_table_entry *sp;
    struct rtpp_hash_table_priv *pvt;

    PUB2PVT(self, pvt);
    if (pvt->key_type == rtpp_ht_key_str_t) {
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

    sp->hash = rtpp_ht_hashkey(pvt, key, klen);
    sp->klen = klen;

    switch (pvt->key_type) {
    case rtpp_ht_key_str_t:
        sp->key.ch = &sp->chstor[0];
        memcpy(sp->key.ch, key, klen);
        sp->key.ch[klen] = '\0';
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

    return (hash_table_insert(pvt, sp, hosp));
}

static struct rtpp_hash_table_entry *
hash_table_append_refcnt(struct rtpp_hash_table *self, const void *key,
  struct rtpp_refcnt *rptr, struct rtpp_ht_opstats *hosp)
{
    static struct rtpp_hash_table_entry *rval;
    struct rtpp_hash_table_priv *pvt;

    PUB2PVT(self, pvt);
    RC_INCREF(rptr);
    size_t klen = rtpp_ht_get_keysize(pvt, key);
    rval = hash_table_append_raw(self, key, klen, rptr, rtpp_hte_refcnt_t, hosp);
    if (rval == NULL) {
        RC_DECREF(rptr);
        return (NULL);
    }
    return (rval);
}

static struct rtpp_hash_table_entry *
hash_table_append_str_refcnt(struct rtpp_hash_table *self, const rtpp_str_t *key,
  struct rtpp_refcnt *rptr, struct rtpp_ht_opstats *hosp)
{
    static struct rtpp_hash_table_entry *rval;

    RC_INCREF(rptr);
    rval = hash_table_append_raw(self, key->s, key->len, rptr, rtpp_hte_refcnt_t, hosp);
    if (rval == NULL) {
        RC_DECREF(rptr);
        return (NULL);
    }
    return (rval);
}

static inline void
hash_table_remove_locked(struct rtpp_hash_table_priv *pvt,
  struct rtpp_hash_table_entry *sp, uint64_t hash, struct rtpp_ht_opstats *hosp)
{

    if (sp->prev != NULL) {
        sp->prev->next = sp->next;
        if (sp->next != NULL) {
            sp->next->prev = sp->prev;
        }
    } else {
        /* Make sure we are removing the right session */
        RTPP_DBG_ASSERT(HT_GET(pvt->l1, hash) == sp);
        *HT_GETREF(pvt->l1, hash) = sp->next;
        if (sp->next != NULL) {
            sp->next->prev = NULL;
        }
    }
    pvt->l1->hte_num -= 1;
    if (hosp != NULL && pvt->l1->hte_num == 0)
        hosp->last = 1;
}

static void
hash_table_remove_raw(struct rtpp_hash_table_priv *pvt, const void *key,
  size_t klen, struct rtpp_hash_table_entry *sp)
{
    uint64_t hash;

    hash = rtpp_ht_hashkey(pvt, key, klen);
    pthread_mutex_lock(&pvt->hash_table_lock);
    hash_table_remove_locked(pvt, sp, hash, NULL);
    pthread_mutex_unlock(&pvt->hash_table_lock);
    if (sp->hte_type == rtpp_hte_refcnt_t) {
        RC_DECREF((struct rtpp_refcnt *)sp->sptr);
    }
    free(sp);
}

static void
hash_table_remove(struct rtpp_hash_table *self, const void *key,
  struct rtpp_hash_table_entry *sp)
{
    struct rtpp_hash_table_priv *pvt;
    size_t klen;

    PUB2PVT(self, pvt);
    klen = rtpp_ht_get_keysize(pvt, key);
    hash_table_remove_raw(pvt, key, klen, sp);
}

static void
hash_table_remove_str(struct rtpp_hash_table *self, const rtpp_str_t *key,
  struct rtpp_hash_table_entry *sp)
{
    struct rtpp_hash_table_priv *pvt;

    PUB2PVT(self, pvt);
    hash_table_remove_raw(pvt, key->s, key->len, sp);
}

static struct rtpp_hash_table_entry *
hash_table_remove_by_key_raw(struct rtpp_hash_table_priv *pvt, const void *key,
  struct rtpp_ht_opstats *hosp)
{
    uint64_t hash;
    struct rtpp_hash_table_entry *sp;
    size_t klen;

    klen = rtpp_ht_get_keysize(pvt, key);
    hash = rtpp_ht_hashkey(pvt, key, klen);
    pthread_mutex_lock(&pvt->hash_table_lock);
    for (sp = HT_GET(pvt->l1, hash); sp != NULL; sp = sp->next) {
        if (pvt->key_type == rtpp_ht_key_str_t && hash != sp->hash)
            continue;
        if (rtpp_ht_cmpkey(pvt, sp, key, klen)) {
            break;
        }
    }
    if (sp == NULL) {
        pthread_mutex_unlock(&pvt->hash_table_lock);
        return (NULL);
    }
    hash_table_remove_locked(pvt, sp, hash, hosp);
    pthread_mutex_unlock(&pvt->hash_table_lock);
    return (sp);
}

static struct rtpp_refcnt *
hash_table_remove_by_key(struct rtpp_hash_table *self, const void *key,
  struct rtpp_ht_opstats *hosp)
{
    struct rtpp_hash_table_priv *pvt;
    struct rtpp_hash_table_entry *sp;
    struct rtpp_refcnt *rptr;

    PUB2PVT(self, pvt);
    sp = hash_table_remove_by_key_raw(pvt, key, hosp);
    if (sp == NULL)
        return (NULL);
    rptr = sp->sptr;
    if (sp->hte_type == rtpp_hte_refcnt_t) {
        RC_DECREF(rptr);
    }
    free(sp);
    return (rptr);
}

static struct rtpp_refcnt *
hash_table_transfer(struct rtpp_hash_table *self, const void *key,
  struct rtpp_hash_table *other, struct rtpp_ht_opstats *hosp)
{
    struct rtpp_hash_table_priv *pvt, *pvt_other;
    struct rtpp_hash_table_entry *sp;
    struct rtpp_refcnt *rptr;

    PUB2PVT(self, pvt);
    PUB2PVT(other, pvt_other);

    RTPP_DBG_ASSERT(pvt->key_type == pvt_other->key_type);
    RTPP_DBG_ASSERT(pvt->pub.seed == pvt_other->pub.seed);

    sp = hash_table_remove_by_key_raw(pvt, key, hosp);
    if (sp == NULL)
        return (NULL);

    sp->next = NULL;
    sp->prev = NULL;
    rptr = sp->sptr;
    RC_INCREF(rptr);
    hash_table_insert(pvt_other, sp, hosp);
    return (rptr);
}

static struct rtpp_refcnt *
hash_table_find_raw(struct rtpp_hash_table_priv *pvt, const void *key, size_t klen)
{
    struct rtpp_refcnt *rptr;
    struct rtpp_hash_table_entry *sp;
    uint64_t hash;

    hash = rtpp_ht_hashkey(pvt, key, klen);
    pthread_mutex_lock(&pvt->hash_table_lock);
    for (sp = HT_GET(pvt->l1, hash); sp != NULL; sp = sp->next) {
        if (pvt->key_type == rtpp_ht_key_str_t && hash != sp->hash)
            continue;
        if (rtpp_ht_cmpkey(pvt, sp, key, klen)) {
            break;
        }
    }
    if (sp != NULL) {
        RTPP_DBG_ASSERT(sp->hte_type == rtpp_hte_refcnt_t);
        rptr = (struct rtpp_refcnt *)sp->sptr;
        RC_INCREF(rptr);
    } else {
        rptr = NULL;
    }
    pthread_mutex_unlock(&pvt->hash_table_lock);
    return (rptr);
}

static struct rtpp_refcnt *
hash_table_find(struct rtpp_hash_table *self, const void *key)
{
    struct rtpp_hash_table_priv *pvt;
    size_t klen;

    PUB2PVT(self, pvt);
    klen = rtpp_ht_get_keysize(pvt, key);
    return (hash_table_find_raw(pvt, key, klen));
}

static struct rtpp_refcnt *
hash_table_find_str(struct rtpp_hash_table *self, const rtpp_str_t *key)
{
    struct rtpp_hash_table_priv *pvt;

    PUB2PVT(self, pvt);
    return (hash_table_find_raw(pvt, key->s, key->len));
}

#define VDTE_MVAL(m) (((m) & ~(RTPP_HT_MATCH_BRK | RTPP_HT_MATCH_DEL)) == 0)

static void
hash_table_foreach_rc(struct rtpp_hash_table *self,
  rtpp_hash_table_match_rc_t hte_ematch_rc, void *marg, struct rtpp_ht_opstats *hosp)
{
    struct rtpp_hash_table_entry *sp, *sp_next;
    struct rtpp_hash_table_priv *pvt;
    struct rtpp_refcnt *rptr;
    int i, mval;

    PUB2PVT(self, pvt);
    pthread_mutex_lock(&pvt->hash_table_lock);
    if (pvt->l1->hte_num == 0) {
        pthread_mutex_unlock(&pvt->hash_table_lock);
        return;
    }
    for (i = 0; i < pvt->l1->ht_len; i++) {
        for (sp = pvt->l1->hash_table[i]; sp != NULL; sp = sp_next) {
            RTPP_DBG_ASSERT(sp->hte_type == rtpp_hte_refcnt_t);
            rptr = (struct rtpp_refcnt *)sp->sptr;
            sp_next = sp->next;
            mval = hte_ematch_rc(rptr, marg);
            RTPP_DBG_ASSERT(VDTE_MVAL(mval));
            if (mval & RTPP_HT_MATCH_DEL) {
                hash_table_remove_locked(pvt, sp, sp->hash, hosp);
                RC_DECREF(rptr);
                free(sp);
            }
            if (mval & RTPP_HT_MATCH_BRK) {
                goto out;
            }
        }
    }
out:
    pthread_mutex_unlock(&pvt->hash_table_lock);
}

struct rc2norc_args {
    rtpp_hash_table_match_t hte_ematch;
    void *marg;
};

static int
ematch_rc2norc(struct rtpp_refcnt *rptr, void *marg)
{
    struct rc2norc_args *args = (struct rc2norc_args *)marg;
    void *data = CALL_SMETHOD(rptr, getdata);
    return args->hte_ematch(data, args->marg);
}

static void
hash_table_foreach(struct rtpp_hash_table *self,
  rtpp_hash_table_match_t hte_ematch, void *marg, struct rtpp_ht_opstats *hosp)
{
    struct rc2norc_args args = {.hte_ematch = hte_ematch, .marg = marg};
    return hash_table_foreach_rc(self, ematch_rc2norc, &args, hosp);
}

static void
hash_table_foreach_key_raw(struct rtpp_hash_table_priv *pvt, const void *key,
  size_t klen, rtpp_hash_table_match_t hte_ematch, void *marg)
{
    struct rtpp_hash_table_entry *sp, *sp_next;
    struct rtpp_refcnt *rptr;
    int mval;
    uint64_t hash;

    hash = rtpp_ht_hashkey(pvt, key, klen);
    pthread_mutex_lock(&pvt->hash_table_lock);
    if (pvt->l1->hte_num == 0) {
        pthread_mutex_unlock(&pvt->hash_table_lock);
        return;
    }
    for (sp = HT_GET(pvt->l1, hash); sp != NULL; sp = sp_next) {
        sp_next = sp->next;
        if (pvt->key_type == rtpp_ht_key_str_t && hash != sp->hash)
            continue;
        if (!rtpp_ht_cmpkey(pvt, sp, key, klen)) {
            continue;
        }
        RTPP_DBG_ASSERT(sp->hte_type == rtpp_hte_refcnt_t);
        rptr = (struct rtpp_refcnt *)sp->sptr;
        mval = hte_ematch(CALL_SMETHOD(rptr, getdata), marg);
        RTPP_DBG_ASSERT(VDTE_MVAL(mval));
        if (mval & RTPP_HT_MATCH_DEL) {
            hash_table_remove_locked(pvt, sp, sp->hash, NULL);
            RC_DECREF(rptr);
            free(sp);
        }
        if (mval & RTPP_HT_MATCH_BRK) {
            break;
        }
    }
    pthread_mutex_unlock(&pvt->hash_table_lock);
}

static void
hash_table_foreach_key(struct rtpp_hash_table *self, const void *key,
  rtpp_hash_table_match_t hte_ematch, void *marg)
{
    struct rtpp_hash_table_priv *pvt;
    size_t klen;

    PUB2PVT(self, pvt);
    klen = rtpp_ht_get_keysize(pvt, key);
    hash_table_foreach_key_raw(pvt, key, klen, hte_ematch, marg);
}

static void
hash_table_foreach_key_str(struct rtpp_hash_table *self, const rtpp_str_t *key,
  rtpp_hash_table_match_t hte_ematch, void *marg)
{
    struct rtpp_hash_table_priv *pvt;

    PUB2PVT(self, pvt);
    hash_table_foreach_key_raw(pvt, key->s, key->len, hte_ematch, marg);
}

static int
hash_table_get_length(struct rtpp_hash_table *self)
{
    struct rtpp_hash_table_priv *pvt;
    int rval;

    PUB2PVT(self, pvt);
    pthread_mutex_lock(&pvt->hash_table_lock);
    rval = pvt->l1->hte_num;
    pthread_mutex_unlock(&pvt->hash_table_lock);

    return (rval);
}

#define PURGE_BATCH 64
struct purge_batch {
    struct rtpp_refcnt *rptrs[PURGE_BATCH];
    int n;
};

static int
hash_table_purge_f(struct rtpp_refcnt *rptr, void *ap)
{
    struct purge_batch *pbp = (struct purge_batch *)ap;

    RTPP_DBG_ASSERT(pbp->n < PURGE_BATCH);
    RC_INCREF(rptr);
    pbp->rptrs[pbp->n++] = rptr;
    return (RTPP_HT_MATCH_DEL | (pbp->n == PURGE_BATCH ? RTPP_HT_MATCH_BRK : 0));
}

static int
hash_table_purge(struct rtpp_hash_table *self)
{
    int npurged;
    struct purge_batch pb;

    for (npurged = 0;; npurged++) {
        pb.n = 0;
        hash_table_foreach_rc(self, hash_table_purge_f, &pb, NULL);
        RTPP_DBG_ASSERT(pb.n <= PURGE_BATCH);
        if (pb.n == 0)
            break;
        for (int i = 0; i < pb.n; i++)
            RC_DECREF(pb.rptrs[i]);
    }
    return (npurged);
}

static int
hash_table_resize_locked(struct rtpp_hash_table_priv *pvt, size_t ht_len)
{
    struct rtpp_hash_table_entry *sp, *sp_next;
    struct rtpp_hash_table_l1 *l1_new;

    l1_new = rtpp_zmalloc(rtpp_hash_table_l1_sizeof(ht_len));
    if (l1_new == NULL)
        return (-1);
    l1_new->ht_len = ht_len;
    for (int i = 0; i < pvt->l1->ht_len; i++) {
        for (sp = pvt->l1->hash_table[i]; sp != NULL; sp = sp_next) {
            sp_next = sp->next;
            sp->next = NULL;
            sp->prev = NULL;
            hash_table_insert_locked(pvt, l1_new, sp);
        }
    }
    free(pvt->l1);
    pvt->l1 = l1_new;
    return (0);
}
