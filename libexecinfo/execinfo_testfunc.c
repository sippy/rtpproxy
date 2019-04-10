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
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "execinfo.h"
#include "stacktraverse.h"
#include "execinfo_testfunc.h"

int
testfunc(const void *caller, int rnum)
{
  void *array[STACKTRAVERSE_MAX_LEVELS + 1];
  size_t size;
  char **strings;

  memset(array, '\0', sizeof(array));
  size = backtrace(array, STACKTRAVERSE_MAX_LEVELS + 1);
  assert(size > 0);
  assert(array[0] > caller);
  if (size == STACKTRAVERSE_MAX_LEVELS)
    assert(getreturnaddr(size) != NULL);
  strings = backtrace_symbols(array, size + 1);
  assert(strings != NULL);
  backtrace_symbols_fd(array, size + 1, fileno(stdout));
  return ((rnum << 8) | size);
}
