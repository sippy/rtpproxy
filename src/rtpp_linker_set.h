/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 1999 John D. Polstra
 * Copyright (c) 1999,2001 Peter Wemm <peter@FreeBSD.org>
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
 * $FreeBSD: 7c12ae215018afa4eb26492e736b8fa748b79831 $
 */

#pragma once

#define __RTPP_CONCAT1(x,y)  x ## y
#define __RTPP_CONCAT(x,y)   __RTPP_CONCAT1(x,y)
#define __RTPP_STRING(x)     #x              /* stringify without expanding x */
#define __RTPP_XSTRING(x)    __RTPP_STRING(x)     /* expand x, then stringify */
#define __RTPP_WEAK(sym)     __asm__(".weak " __RTPP_XSTRING(sym))
#define __RTPP_GLOBL(sym)    __asm__(".globl " __RTPP_XSTRING(sym))
#define __rtpp_used          __attribute__((__used__))
#define __rtpp_section(x)    __attribute__((__section__(x)))
/*
 * The following macros are used to declare global sets of objects, which
 * are collected by the linker into a `linker_set' as defined below.
 * For ELF, this is done by constructing a separate segment for each set.
 */

#if defined(__powerpc64__) && (!defined(_CALL_ELF) || _CALL_ELF == 1)
/*
 * ELFv1 pointers to functions are actaully pointers to function
 * descriptors.
 *
 * Move the symbol pointer from ".text" to ".data" segment, to make
 * the GCC compiler happy:
 */
#define	__MAKE_SET_CONST
#else
#define	__MAKE_SET_CONST const
#endif

/*
 * Private macros, not to be used outside this header file.
 */
#if defined(__GNUC__)

/*
 * The userspace address sanitizer inserts redzones around global variables,
 * violating the assumption that linker set elements are packed.
 */
#if __has_attribute(no_sanitize) && defined(__clang__)
#define __NOASAN __attribute__((no_sanitize("address")))
#else
#define __NOASAN
#endif

#define __MAKE_SET_QV(set, sym, qv)				\
	__RTPP_WEAK(__RTPP_CONCAT(__start_set_,set));		\
	__RTPP_WEAK(__RTPP_CONCAT(__stop_set_,set));		\
	static void const * qv					\
	__NOASAN						\
	__set_##set##_sym_##sym __rtpp_section("set_" #set)	\
	__rtpp_used = &(sym)
#define __MAKE_SET(set, sym)	__MAKE_SET_QV(set, sym, __MAKE_SET_CONST)
#else /* !__GNUCLIKE___SECTION */
#error this file needs to be ported to your compiler
#endif /* __GNUCLIKE___SECTION */

/*
 * Public macros.
 */
#define TEXT_SET(set, sym)	__MAKE_SET(set, sym)
#define DATA_SET(set, sym)	__MAKE_SET(set, sym)
#define DATA_WSET(set, sym)	__MAKE_SET_QV(set, sym, )
#define BSS_SET(set, sym)	__MAKE_SET(set, sym)
#define ABS_SET(set, sym)	__MAKE_SET(set, sym)
#define SET_ENTRY(set, sym)	__MAKE_SET(set, sym)

/*
 * Initialize before referring to a given linker set.
 */
#define SET_DECLARE(set, ptype)					\
	extern ptype __attribute__((__weak__)) *__RTPP_CONCAT(__start_set_,set);	\
	extern ptype __attribute__((__weak__)) *__RTPP_CONCAT(__stop_set_,set)

#define SET_BEGIN(set)							\
	(&__RTPP_CONCAT(__start_set_,set))
#define SET_LIMIT(set)							\
	(&__RTPP_CONCAT(__stop_set_,set))

/*
 * Iterate over all the elements of a set.
 *
 * Sets always contain addresses of things, and "pvar" points to words
 * containing those addresses.  Thus is must be declared as "type **pvar",
 * and the address of each set item is obtained inside the loop by "*pvar".
 */
#define SET_FOREACH(pvar, set)						\
	for (pvar = SET_BEGIN(set); pvar < SET_LIMIT(set); pvar++)

#define SET_ITEM(set, i)						\
	((SET_BEGIN(set))[i])

/*
 * Provide a count of the items in a set.
 */
#define SET_COUNT(set)							\
	(SET_LIMIT(set) - SET_BEGIN(set))
