/*
 * Copyright (c) 2019 Sippy Software, Inc., http://www.sippysoft.com
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "prdic_types.h"
#include "prdic_inst.h"
#include "prdic_sign.h"
#include "prdic_sign_ctx.h"
#include "prdic_sign_impl.h"

#define UINT_MAX      0xffffffff

static __thread struct prdic_sign_ctx psc = {
    .first = (NULL),
    .sigackd = (UINT_MAX - 20)
};

static void
sched_handler(int signum)
{

    atomic_fetch_add_explicit(&psc.sigackd, 1, memory_order_relaxed);
}

unsigned int
prdic_sign_getnrecv(void)
{

    return (atomic_load_explicit(&psc.sigackd, memory_order_acquire));
}

struct prdic_sign *
prdic_sign_setup(int signum)
{
    struct prdic_sign *sip;
    struct sigaction sa;

    sip = malloc(sizeof(struct prdic_sign));
    if (sip == NULL)
        goto e0;
    memset(sip, '\0', sizeof(struct prdic_sign));
    sip->sa_save = malloc(sizeof(struct sigaction));
    if (sip->sa_save == NULL)
        goto e1;
    memset(&sa, '\0', sizeof(sa));
    sip->pscp = &psc;
#if 0
    sip->pscp = malloc(sizeof(struct prdic_sign_ctx));
    if (sip->pscp == NULL)
        goto e2;
    memset(sip->pscp, '\0', sizeof(struct prdic_sign_ctx));
#endif
    sa.sa_handler = sched_handler;
    sigemptyset (&sa.sa_mask);
    if (sigaction(signum, &sa, sip->sa_save) < 0)
        goto e3;
    sip->signum = signum;
    sip->sigtgt = pthread_self();
    atomic_init(&sip->sigsent, atomic_load(&psc.sigackd));
    sigemptyset(&sip->bumask);
    sigaddset(&sip->bumask, signum);
#if 0
    atomic_init(&sip->pscp->first, NULL);
#endif
    prdic_sign_block(sip);
    return (sip);
e3:
#if 0
    free(sip->pscp);
#endif
e2:
    free(sip->sa_save);
e1:
    free(sip);
e0:
    return (NULL);
}

void
prdic_sign_dtor(struct prdic_sign *sip)
{
    struct prdic_sign_ctx *pscp = sip->pscp;
    struct cftnode *head, *next;

    sigaction(sip->signum, sip->sa_save, NULL);
    if (atomic_load(&sip->pscp->first) != NULL) {
        assert(sip->sigtgt == pthread_self());
        prdic_CFT_serve(sip);
    }
#if 0
    free(sip->pscp);
#endif
    free(sip->sa_save);
    free(sip);
}

void
prdic_sign_block(const struct prdic_sign *sip)
{

    sigprocmask(SIG_BLOCK, &sip->bumask, NULL);
}

void
prdic_sign_unblock(const struct prdic_sign *sip)
{

    sigprocmask(SIG_UNBLOCK, &sip->bumask, NULL);
}

void
prdic_CFT_serve(struct prdic_sign *sip)
{
    struct cftnode *first, *next, *last;
    struct prdic_sign_ctx *pscp = sip->pscp;

    do {
        first = pscp->first;
    } while (!atomic_compare_exchange_weak_explicit(&pscp->first, &first,
      NULL, memory_order_acquire, memory_order_relaxed));
    if (first == NULL)
        return;
    /* Now that we own the whole chain reverse its direction */
    for (last = NULL; first != NULL; first = next) {
        next = first->next;
        first->next = last;
        last = first;
    }
    for (; last != NULL; last = next) {
        next = last->next;
        last->handler(last->harg);
        free(last);
    }
}

int
prdic_call_from_thread(void *pinst, ctfhandler_m handler, void *harg)
{
    struct prdic_inst *pip = (struct prdic_inst *)pinst;
    struct prdic_sign_ctx *pscp = pip->sip->pscp;
    struct cftnode *newn, *head;

    newn = malloc(sizeof(struct cftnode));
    if (newn == NULL)
        return (-1);
    memset(newn, '\0', sizeof(struct cftnode));
    newn->handler = handler;
    newn->harg = harg;
    do {
        head = atomic_load_explicit(&pscp->first, memory_order_relaxed);
        newn->next = head;
    } while (!atomic_compare_exchange_weak_explicit(&pscp->first, &head,
      newn, memory_order_release, memory_order_relaxed));

    unsigned int sackd = atomic_load_explicit(&pscp->sigackd,
      memory_order_relaxed);
    unsigned int ssend = atomic_load_explicit(&pip->sip->sigsent,
      memory_order_relaxed);
    if (head != NULL && ssend > sackd) {
        return (0);
    }

    pthread_kill(pip->sip->sigtgt, pip->sip->signum);
    atomic_compare_exchange_strong_explicit(&pip->sip->sigsent, &ssend,
      sackd + 1, memory_order_release, memory_order_relaxed);
    return (0);
}
