/*-
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
 * $FreeBSD: releng/11.2/sys/sys/linker_set.h 331722 2018-03-29 02:50:57Z eadler $
 */

#ifndef _SYS_LINKER_SET_H_
#define _SYS_LINKER_SET_H_

#if defined(__weak_symbol)
#undef __weak_symbol
#endif
#define __weak_symbol __attribute__((__weak__))

#if defined(__section)
#undef __section
#endif
#define __section(x)    __attribute__((__section__(x)))

#if defined(__used)
#undef __used
#endif
#define __used          __attribute__((__used__))

#define __CONCAT421(x,y)  x ## y
#define __CONCAT42(x,y)   __CONCAT421(x,y)

#define __GLOBL1(sym)   __asm__(".globl " #sym)
#define __GLOBL(sym)    __GLOBL1(sym)

/*
 * The following macros are used to declare global sets of objects, which
 * are collected by the linker into a `linker_set' as defined below.
 * For ELF, this is done by constructing a separate segment for each set.
 */

#if defined(__powerpc64__)
/*
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
#define __MAKE_SET(set, sym)				\
	__GLOBL(__CONCAT42(__start_set_,set));		\
	__GLOBL(__CONCAT42(__stop_set_,set));		\
	static void const * __MAKE_SET_CONST		\
	__set_##set##_sym_##sym __section("set_" #set)	\
	__used = &(sym)

/*
 * Public macros.
 */
#define TEXT_SET(set, sym)	__MAKE_SET(set, sym)
#define DATA_SET(set, sym)	__MAKE_SET(set, sym)
#define BSS_SET(set, sym)	__MAKE_SET(set, sym)
#define ABS_SET(set, sym)	__MAKE_SET(set, sym)
#define SET_ENTRY(set, sym)	__MAKE_SET(set, sym)

/*
 * Initialize before referring to a given linker set.
 */
#define SET_DECLARE(set, ptype)					\
	extern ptype __weak_symbol *__CONCAT42(__start_set_,set);	\
	extern ptype __weak_symbol *__CONCAT42(__stop_set_,set)

#define SET_BEGIN(set)							\
	(&__CONCAT42(__start_set_,set))
#define SET_LIMIT(set)							\
	(&__CONCAT42(__stop_set_,set))

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

#endif	/* _SYS_LINKER_SET_H_ */
