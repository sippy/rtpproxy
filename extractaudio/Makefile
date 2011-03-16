# Copyright (c) 2003-2006 Maksym Sobolyev
# Copyright (c) 2006-2008 Sippy Software, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $Id$

PROG=	extractaudio
SRCS=	main.c decoder.c _rtp.c _rtp_analyze.c _rtpp_util.c
CLEANFILES+= _rtp.c _rtp_analyze.c _rtpp_util.c
MAN1=

WARNS?=	2

LOCALBASE?=	/usr/local

CFLAGS=-DWITHOUT_SIPLOG

CFLAGS+= -I.. -I../../siplog -I${LOCALBASE}/include
LDFLAGS+= -L../../siplog -L${LOCALBASE}/lib
LDADD+=	-lg729 -lsndfile -lm

_rtp.c: ../rtp.c
	ln -sf ../rtp.c _rtp.c

_rtp_analyze.c: ../rtp_analyze.c
	ln -sf ../rtp_analyze.c _rtp_analyze.c

_rtpp_util.c: ../rtpp_util.c
	ln -sf ../rtpp_util.c _rtpp_util.c

.include <bsd.prog.mk>
