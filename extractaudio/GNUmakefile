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

CC?=	gcc
CFLAGS+=-Wall -DWITHOUT_SIPLOG -D_BSD_SOURCE -D_ISOC99_SOURCE -DENABLE_GSM -DENABLE_G729 \
  -I./ -I../ -I/usr/local/include
LIBS+=	-L. -L/usr/local/lib -lg729 -lgsm -lsndfile -lm
PREFIX?= /usr/local

ifeq ($(origin WITHOUT_G722), undefined)
LIBS+= -lg722
else
CFLAGS+= -DWITHOUT_G722
endif

# Uncomment this on Solaris
#LIBS+=	-lresolv -lsocket -lnsl

SRCS = decoder.c decoder.h format_au.h g711.h main.c session.h _rtp.c \
  _rtp_analyze.c _rtpp_util.c rtpp_loader.c rtpp_loader.h _rtpp_log_stand.c
PROG = extractaudio
sources = $(filter %.c, $(SRCS))
OBJS = $(sources:%.c=%.o)

.c.o: $(SRCS)
	$(CC) -c $(CFLAGS) $< -o $@

all: $(PROG)

_rtp.c: ../rtp.c
	ln -sf ../rtp.c _rtp.c

_rtp_analyze.c: ../rtp_analyze.c
	ln -sf ../rtp_analyze.c _rtp_analyze.c

_rtpp_util.c: ../rtpp_util.c
	ln -sf ../rtpp_util.c _rtpp_util.c

_rtpp_log_stand.c: ../rtpp_log_stand.c
	ln -sf ../rtpp_log_stand.c _rtpp_log_stand.c

$(PROG): $(OBJS)
	$(CC) -o $(PROG) $(OBJS) $(LIBS)

clean:
	rm -f $(PROG) $(OBJS) _rtp.c _rtp_analyze.c _rtpp_util.c

install: all
	install $(PROG) $(PREFIX)/bin/$(PROG)
