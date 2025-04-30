/*
 * Copyright (c) 2019 Sippy Software, Inc., http://www.sippysoft.com
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

struct rtpp_codeptr;

struct _glav_trig {
    _Atomic(intmax_t) step;
    _Atomic(intmax_t) hits;
    uintptr_t stack;
    int wild;
    char act[16];
    union {
      const struct rtpp_codeptr *ptr;
      _Atomic(uintptr_t) aptr;
    } lasthit;
};

struct rtpp_glitch_opts {
    unsigned int mightclose:1;
};

extern struct _glav_trig _glav_trig;

enum glav_act {
  GLAV_NOP   = 0,
  GLAV_ABORT = 'a',
  GLAV_HANG  = 'h',
  GLAV_BAIL  = 'e',
  GLAV_RPRT  = 'r',
  GLAV_GLTCH = 'g'
};

void rtpp_glitch_init(struct rtpp_glitch_opts *);
void rtpp_glitch_callhome(intmax_t step, uintptr_t hash,
  const struct rtpp_codeptr *);

#define GLITCH_ACTION(mlp) { \
    const char *_cp; \
    static int _b = 1; \
    atomic_store(&_glav_trig.lasthit.aptr, (uintptr_t)mlp); \
    for (_cp = &_glav_trig.act[0]; *_cp != '\0'; _cp++) { \
        switch (*_cp) { \
        case GLAV_ABORT: \
            abort(); \
        case GLAV_HANG: \
            while (_b) \
                usleep(1000); \
            break; \
        case GLAV_BAIL: \
            exit(255); \
        case GLAV_RPRT: \
            rtpp_glitch_callhome(step, stack_cook, mlp); \
            break; \
        case GLAV_GLTCH: \
            _do_glitch = 1; \
            break; \
        } \
    } \
}

#define TRIG_CHCK1() (step == -1 || _glav_trig.wild != 0 || _glav_trig.stack != 0)
#define TRIG_CHCK2() (_glav_trig.stack == 0 || stack_cook == _glav_trig.stack)
#define TRIG_CHCK3() (_glav_trig.stack == 0 || (nhit == 0 || _glav_trig.wild != 0))

#define GLITCH_INJECT_IF(mlp, ghlabel, cond) { \
    intmax_t step = atomic_fetch_add(&_glav_trig.step, 1); \
    if (TRIG_CHCK1() && (cond)) { \
        uintptr_t stack_cook =  getstackcookie() ^ mlp->linen; \
        if (TRIG_CHCK2()) { \
            intmax_t nhit = atomic_fetch_add(&_glav_trig.hits, 1); \
            if (TRIG_CHCK3()) { \
                int _do_glitch = 0; \
                GLITCH_ACTION(mlp); \
                if (_do_glitch) { \
                    goto ghlabel; \
                } \
            } \
        } \
    } \
}

#define GLITCH_INJECT(mlp, ghlabel) GLITCH_INJECT_IF(mlp, ghlabel, 1)
