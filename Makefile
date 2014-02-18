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

PKGNAME=	rtpproxy
PKGFILES=	GNUmakefile Makefile README extractaudio makeann \
		  rtpproxy.init rtpproxy.sh udp_storm ${SRCS}

PROG=	rtpproxy
SRCS=	main.c rtp_server.c rtp_server.h rtpp_defines.h \
	rtpp_record.c rtpp_record.h rtpp_session.h rtpp_util.c \
	rtpp_util.h rtpp_log.h rtp_resizer.c rtp_resizer.h rtp.c \
	rtp.h rtpp_session.c rtpp_command.c rtpp_command.h \
	rtpp_network.c rtpp_network.h rtpp_log.c rtpp_notify.c \
	rtpp_notify.h rtpp_command_async.h rtpp_command_async.c \
	config.h
MAN1=

WARNS?=	2

LOCALBASE?=	/usr/local
BINDIR?=	${LOCALBASE}/bin

CFLAGS+=	-I../siplog -I${LOCALBASE}/include
#CFLAGS+=	-DRTPP_DEBUG
LDADD+=	-L../siplog -L${LOCALBASE}/lib -lsiplog -lpthread -lm

cleantabs:
	perl -pi -e 's|        |\t|g' ${SRCS}

TSTAMP!=	date "+%Y%m%d%H%M%S"

distribution: clean
	tar cvfy /tmp/${PKGNAME}-sippy-${TSTAMP}.tbz2 ${PKGFILES}
	git tag rel.${TSTAMP}
	git push origin rel.${TSTAMP}

.include <bsd.prog.mk>
