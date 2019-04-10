/*
 * Copyright (c) 2019 Sippy Software, Inc.
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
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

#include "execinfo.h"
#include "stacktraverse.h"
#include "execinfo_testfunc.h"
#include "execinfo_testfunc1.h"

static void *wrkthr(void *pa);

static int
testbody(void *cp)
{
  int r;
  bool inthread;
  uintptr_t sc;

  inthread = (cp == wrkthr);

  r = testfunc(testbody, 0);
  if (inthread)
    assert(r >= 2);
  else
    assert(r == 3);
  r = testfunc1(testbody, 0);
  if (inthread)
    assert(r >= 3);
  else
    assert(r == 4);
  r = testfunc1(testbody, STACKTRAVERSE_MAX_LEVELS - (inthread ? 2 : 3));
  assert(r == STACKTRAVERSE_MAX_LEVELS);
  assert(getreturnaddr(0) != NULL);
  sc = getstackcookie();
  assert(sc != 0);

  return (0);
}

static void *
wrkthr(void *pa)
{

  testbody(wrkthr);
  return ((void *)42);
}

int
main()
{
  void *topframe[1], *jp;
  pthread_t tp;

  memset(topframe, '\0', sizeof(topframe));
  assert(backtrace(topframe, 1) == 1);
  assert(topframe[0] != NULL);
  assert(execinfo_set_topframe(topframe[0]) == NULL);
  assert(testbody(main) == 0);
  assert(pthread_create(&tp, NULL, wrkthr, NULL) == 0);
  assert(pthread_join(tp, &jp) == 0);
  assert(jp == (void *)42);

  return (0);
}
