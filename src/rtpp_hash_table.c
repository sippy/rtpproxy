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

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "rtpp_types.h"
#include "rtpp_hash_table.h"
#include "rtpp_pearson.h"
#include "rtpp_refcnt.h"
#include "rtpp_util.h"

enum rtpp_hte_types {rtpp_hte_naive_t = 0, rtpp_hte_refcnt_t};

#define	RTPP_HT_LEN	256

struct rtpp_hash_table_entry {
    struct rtpp_hash_table_entry *prev;
    struct rtpp_hash_table_entry *next;
    void *sptr;
    char *key;
    uint8_t hash;
    enum rtpp_hte_types hte_type;
};

struct rtpp_hash_table_priv
{
    struct rtpp_pearson rp;
    struct rtpp_hash_table_entry *hash_table[RTPP_HT_LEN];
    pthread_mutex_t hash_table_lock;
    int hte_num;
};

struct rtpp_hash_table_full
{
    struct rtpp_hash_table_obj pub;
    struct rtpp_hash_table_priv pvt;
};

static struct rtpp_hash_table_entry * hash_table_append(struct rtpp_hash_table_obj *self, const char *key, void *sptr);
static struct rtpp_hash_table_entry * hash_table_append_refcnt(struct rtpp_hash_table_obj *self, const char *key, struct rtpp_refcnt_obj *);
static void hash_table_remove(struct rtpp_hash_table_obj *self, const char *key, struct rtpp_hash_table_entry * sp);
static void hash_table_remove_nc(struct rtpp_hash_table_obj *self, struct rtpp_hash_table_entry * sp);
static struct rtpp_hash_table_entry * hash_table_findfirst(struct rtpp_hash_table_obj *self, const char *key, void **sptrp);
static struct rtpp_hash_table_entry * hash_table_findnext(struct rtpp_hash_table_obj *self, struct rtpp_hash_table_entry *psp, void **sptrp);
static struct rtpp_refcnt_obj * hash_table_find(struct rtpp_hash_table_obj *self, const char *key);
static void hash_table_expire(struct rtpp_hash_table_obj *self, rtpp_hash_table_match_t, void *);
static void hash_table_dtor(struct rtpp_hash_table_obj *self);

struct rtpp_hash_table_obj *
rtpp_hash_table_ctor(void)
{
    struct rtpp_hash_table_full *rp;
    struct rtpp_hash_table_obj *pub;
    struct rtpp_hash_table_priv *pvt;

    rp = rtpp_zmalloc(sizeof(struct rtpp_hash_table_full));
    if (rp == NULL) {
        return (NULL);
    }
    pvt = &(rp->pvt);
    pub = &(rp->pub);
    pub->append = &hash_table_append;
    pub->append_refcnt = &hash_table_append_refcnt;
    pub->remove = &hash_table_remove;
    pub->remove_nc = &hash_table_remove_nc;
    pub->findfirst = &hash_table_findfirst;
    pub->findnext = &hash_table_findnext;
    pub->find = &hash_table_find;
    pub->expire = &hash_table_expire;
    pub->dtor = &hash_table_dtor;
    pthread_mutex_init(&pvt->hash_table_lock, NULL);
    rtpp_pearson_shuffle(&pvt->rp);
    pub->pvt = pvt;
    return (pub);
}

static void
hash_table_dtor(struct rtpp_hash_table_obj *self)
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
                CALL_METHOD((struct rtpp_refcnt_obj *)sp->sptr, decref);
            }
            free(sp);
            sp = sp_next;
            pvt->hte_num -= 1;
        } while (sp != NULL);
    }
    pthread_mutex_destroy(&pvt->hash_table_lock);
    assert(pvt->hte_num == 0);

    free(self);
}

static struct rtpp_hash_table_entry *
hash_table_append_raw(struct rtpp_hash_table_obj *self, const char *key,
  void *sptr, enum rtpp_hte_types htype)
{
    int malen, klen;
    struct rtpp_hash_table_entry *sp, *tsp;
    struct rtpp_hash_table_priv *pvt;

    klen = strlen(key);
    malen = sizeof(struct rtpp_hash_table_entry) + klen + 1;
    sp = rtpp_zmalloc(malen);
    if (sp == NULL) {
        return (NULL);
    }
    sp->sptr = sptr;
    sp->hte_type = htype;
    sp->key = ((char *)sp) + sizeof(struct rtpp_hash_table_entry);
    memcpy(sp->key, key, klen);
    pvt = self->pvt;
    sp->hash = rtpp_pearson_hash8(&pvt->rp, key, NULL);

    pthread_mutex_lock(&pvt->hash_table_lock);
    tsp = pvt->hash_table[sp->hash];
    if (tsp == NULL) {
       	pvt->hash_table[sp->hash] = sp;
    } else {
        while (tsp->next != NULL) {
	    tsp = tsp->next;
        }
        tsp->next = sp;
        sp->prev = tsp;
    }
    pvt->hte_num += 1;
    pthread_mutex_unlock(&pvt->hash_table_lock);
    return (sp);
}

static struct rtpp_hash_table_entry *
hash_table_append(struct rtpp_hash_table_obj *self, const char *key, void *sptr)
{

    return (hash_table_append_raw(self, key, sptr, rtpp_hte_naive_t));
}

static struct rtpp_hash_table_entry *
hash_table_append_refcnt(struct rtpp_hash_table_obj *self, const char *key,
  struct rtpp_refcnt_obj *rptr)
{
    static struct rtpp_hash_table_entry *rval;

    CALL_METHOD(rptr, incref);
    rval = hash_table_append_raw(self, key, rptr, rtpp_hte_refcnt_t);
    if (rval == NULL) {
        CALL_METHOD(rptr, decref);
        return (NULL);
    }
    return (rval);
}

static void
hash_table_remove(struct rtpp_hash_table_obj *self, const char *key,
  struct rtpp_hash_table_entry * sp)
{
    uint8_t hash;
    struct rtpp_hash_table_priv *pvt;

    pvt = self->pvt;
    pthread_mutex_lock(&pvt->hash_table_lock);
    if (sp->prev != NULL) {
	sp->prev->next = sp->next;
	if (sp->next != NULL) {
	    sp->next->prev = sp->prev;
	}
    } else {
        hash = rtpp_pearson_hash8(&pvt->rp, key, NULL);
        /* Make sure we are removing the right session */
        assert(pvt->hash_table[hash] == sp);
        pvt->hash_table[hash] = sp->next;
        if (sp->next != NULL) {
	    sp->next->prev = NULL;
        }
    }
    pvt->hte_num -= 1;
    pthread_mutex_unlock(&pvt->hash_table_lock);
    if (sp->hte_type == rtpp_hte_refcnt_t) {
        CALL_METHOD((struct rtpp_refcnt_obj *)sp->sptr, decref);
    }
    free(sp);
}

static void
hash_table_remove_nc(struct rtpp_hash_table_obj *self, struct rtpp_hash_table_entry * sp)
{
    struct rtpp_hash_table_priv *pvt;

    pvt = self->pvt;
    pthread_mutex_lock(&pvt->hash_table_lock);
    if (sp->prev != NULL) {
        sp->prev->next = sp->next;
        if (sp->next != NULL) {
            sp->next->prev = sp->prev;
        }
    } else {
        /* Make sure we are removing the right entry */
        assert(pvt->hash_table[sp->hash] == sp);
        pvt->hash_table[sp->hash] = sp->next;
        if (sp->next != NULL) {
            sp->next->prev = NULL;
        }
    }
    pvt->hte_num -= 1;
    pthread_mutex_unlock(&pvt->hash_table_lock);
    if (sp->hte_type == rtpp_hte_refcnt_t) {
        CALL_METHOD((struct rtpp_refcnt_obj *)sp->sptr, decref);
    }
    free(sp);
}

static struct rtpp_hash_table_entry *
hash_table_findfirst(struct rtpp_hash_table_obj *self, const char *key, void **sptrp)
{
    uint8_t hash;
    struct rtpp_hash_table_entry *sp;
    struct rtpp_hash_table_priv *pvt;

    pvt = self->pvt;
    hash = rtpp_pearson_hash8(&pvt->rp, key, NULL);
    pthread_mutex_lock(&pvt->hash_table_lock);
    for (sp = pvt->hash_table[hash]; sp != NULL; sp = sp->next) {
	if (strcmp(sp->key, key) == 0) {
            *sptrp = sp->sptr;
	    break;
	}
    }
    pthread_mutex_unlock(&pvt->hash_table_lock);
    return (sp);
}

static struct rtpp_hash_table_entry *
hash_table_findnext(struct rtpp_hash_table_obj *self, struct rtpp_hash_table_entry *psp, void **sptrp)
{
    struct rtpp_hash_table_entry *sp;
    struct rtpp_hash_table_priv *pvt;

    pvt = self->pvt;
    pthread_mutex_lock(&pvt->hash_table_lock);
    for (sp = psp->next; sp != NULL; sp = sp->next) {
	if (strcmp(sp->key, psp->key) == 0) {
            *sptrp = sp->sptr;
	    break;
	}
    }
    pthread_mutex_unlock(&pvt->hash_table_lock);
    return (sp);
}

static struct rtpp_refcnt_obj *
hash_table_find(struct rtpp_hash_table_obj *self, const char *key)
{
    struct rtpp_refcnt_obj *rptr;
    struct rtpp_hash_table_priv *pvt;
    struct rtpp_hash_table_entry *sp;
    uint8_t hash;

    pvt = self->pvt;
    hash = rtpp_pearson_hash8(&pvt->rp, key, NULL);
    pthread_mutex_lock(&pvt->hash_table_lock);
    for (sp = pvt->hash_table[hash]; sp != NULL; sp = sp->next) {
        if (strcmp(sp->key, key) == 0) {
            break;
        }
    }
    if (sp != NULL) {
        assert(sp->hte_type == rtpp_hte_refcnt_t);
        rptr = (struct rtpp_refcnt_obj *)sp->sptr;
        CALL_METHOD(rptr, incref);
    } else {
        rptr = NULL;
    }
    pthread_mutex_unlock(&pvt->hash_table_lock);
    return (rptr);
}

static void
hash_table_expire(struct rtpp_hash_table_obj *self,
  rtpp_hash_table_match_t hte_ematch, void *marg)
{
    struct rtpp_hash_table_entry *sp, *sp_next;
    struct rtpp_hash_table_priv *pvt;
    struct rtpp_refcnt_obj *rptr;
    int i;

    pvt = self->pvt;
    pthread_mutex_lock(&pvt->hash_table_lock);
    if (pvt->hte_num == 0) {
        pthread_mutex_unlock(&pvt->hash_table_lock);
        return;
    }
    for (i = 0; i < RTPP_HT_LEN; i++) {
        for (sp = pvt->hash_table[i]; sp != NULL; sp = sp_next) {
            assert(sp->hte_type == rtpp_hte_refcnt_t);
            rptr = (struct rtpp_refcnt_obj *)sp->sptr;
            sp_next = sp->next;
            if (hte_ematch(rptr, marg) == 0) {
                continue;
            }
            if (sp->prev != NULL) {
                sp->prev->next = sp->next;
                if (sp->next != NULL) {
                    sp->next->prev = sp->prev;
                }
            } else {
                assert(pvt->hash_table[sp->hash] == sp);
                pvt->hash_table[sp->hash] = sp->next;
                if (sp->next != NULL) {
                    sp->next->prev = NULL;
                }
            }
            CALL_METHOD(rptr, decref);
            free(sp);
            pvt->hte_num -= 1;
        }
    }
    pthread_mutex_unlock(&pvt->hash_table_lock);
}
