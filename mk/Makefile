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
		  rtpproxy.init rtpproxy.sh udp_storm ${SRCS:Nconfig[.]h}

.if !defined(RTPP_DEBUG)
PROG=	rtpproxy
CLEANFILES+=	rtpproxy_debug
LIBSIPLOG=	siplog
.else
PROG=	rtpproxy_debug
CLEANFILES+=	rtpproxy
DEBUG_FLAGS=	-g3 -O0 -DRTPP_DEBUG -include rtpp_memdeb.h
LDADD+=		-static ../libexecinfo/libexecinfo.a
CFLAGS+=	-I../
SRCS+=		${SRCS_DEBUG}
LIBSIPLOG=	siplog_debug
.endif

SRCS_BASE=	main.c rtpp_server.c rtpp_server.h rtpp_defines.h \
	rtpp_record.c rtpp_record.h rtpp_session.h rtpp_util.c \
	rtpp_util.h rtpp_log.h rtp_resizer.c rtp_resizer.h rtp.c \
	rtp.h rtpp_session.c rtpp_command.c rtpp_command.h \
	rtpp_network.c rtpp_network.h rtpp_log.c rtpp_notify.c \
	rtpp_notify.h rtpp_command_async.h rtpp_command_async.c \
	config.h rtpp_proc_async.c rtpp_proc_async.h rtpp_proc.h \
	rtpp_proc.c rtpp_version.h rtpp_math.c rtpp_math.h rtpp_wi.c \
	rtpp_wi.h rtpp_wi_private.h rtpp_queue.c rtpp_queue.h \
	rtpp_netio_async.c rtpp_netio_async.h rtpp_record_private.h \
	rtpp_command_parse.c rtpp_command_parse.h rtpp_command_copy.c \
	rtpp_command_copy.h rtpp_command_ul.c rtpp_command_ul.h \
	rtpp_hash_table.c rtpp_hash_table.h rtpp_types.h \
	rtpp_pcache.c rtpp_pcache.h config_pp.h rtpp_stats.c \
	rtpp_stats.h rtpp_cfg_stable.h rtpp_command_stats.h \
	rtpp_command_stats.c config_std.h rtp_info.h \
	rtpp_command_private.h rtpp_controlfd.h rtpp_controlfd.c \
	rtpp_list.h rtpp_command_stream.h rtpp_command_stream.c \
	rtpp_timed.c rtpp_timed.h rtpp_analyzer.c rtpp_analyzer.h \
	rtp_analyze.c rtp_analyze.h rtpp_command_query.c rtpp_command_query.h \
	rtpp_pearson.c rtpp_pearson.h rtpp_refcnt.c rtpp_refcnt.h \
	rtpp_command_rcache.c rtpp_command_rcache.h \
	rtpp_tnotify_set.c rtpp_tnotify_set.h rtpp_tnotify_tgt.h \
	rtp_packet.h rtpp_pthread.c rtpp_pthread.h rtpp_time.h rtpp_time.c \
	rtpp_sessinfo.c rtpp_sessinfo.h rtpp_weakref.c rtpp_weakref.h \
	rtpp_proc_servers.h rtpp_proc_servers.c rtpp_stream.h rtpp_stream.c \
	rtpp_genuid.h rtpp_genuid.c rtpp_genuid_singlet.h rtpp_genuid_singlet.c \
	rtpp_log_obj.h rtpp_log_obj.c rtpp_socket.c rtpp_socket.h \
	rtpp_ttl.c rtpp_ttl.h rtpp_proc_ttl.h rtpp_proc_ttl.c rtpp_pipe.h \
	rtpp_pipe.c rtpp_pcount.h rtpp_pcount.c rtpp_debug.h rtpp_monotime.h \
	rtpp_monotime.c

SRCS+=	${SRCS_BASE}

SRCS_DEBUG=	rtpp_memdeb.c rtpp_memdeb.h rtpp_memdeb_internal.h \
        rtpp_memdeb_stats.h rtpp_memdeb_test.c rtpp_stacktrace.c \
	rtpp_stacktrace.h

SRCS_AUTOGEN=rtpp_timed_fin.c rtpp_timed_fin.h rtpp_stream_fin.c \
  rtpp_stream_fin.h rtpp_server_fin.c rtpp_server_fin.h rtpp_refcnt_fin.c \
  rtpp_refcnt_fin.h rtpp_log_obj_fin.c rtpp_log_obj_fin.h \
  rtpp_command_rcache_fin.c rtpp_command_rcache_fin.h rtpp_socket_fin.c \
  rtpp_socket_fin.h rtpp_record_fin.c rtpp_record_fin.h rtpp_ttl_fin.c \
  rtpp_ttl_fin.h rtpp_pipe_fin.c rtpp_pipe_fin.h rtpp_pcount_fin.c \
  rtpp_pcount_fin.h

SRCS+=		${SRCS_AUTOGEN}
CLEANFILES+=	${SRCS_AUTOGEN}

MAN1=

WARNS?=	2

LOCALBASE?=	/usr/local
BINDIR?=	${LOCALBASE}/bin

CFLAGS+=	-I../siplog -I${LOCALBASE}/include
LDADD+=	-L../siplog -L${LOCALBASE}/lib -l${LIBSIPLOG} -lpthread -lm

cleantabs:
	perl -pi -e 's|        |\t|g' ${SRCS}

TSTAMP!=	date "+%Y%m%d%H%M%S"
GIT_BRANCH!=	sh -c "git branch | grep '^[*]' | awk '{print \$$2}'"
.if ${GIT_BRANCH} == "master"
RTPP_SW_VERSION=	${TSTAMP}
.else
RTPP_SW_VERSION=	${TSTAMP}_${GIT_BRANCH}
.endif

CLEANFILES+=	config.h

config.h: config_std.h
	cp ${.ALLSRC} ${.TARGET}

distribution: clean
	echo '#define RTPP_SW_VERSION "'rel.${RTPP_SW_VERSION}'"' > rtpp_version.h
	git commit -m "Update to rel.${RTPP_SW_VERSION}" rtpp_version.h
	git push origin ${GIT_BRANCH}
	tar cvfy /tmp/${PKGNAME}-sippy-${RTPP_SW_VERSION}.tbz2 ${PKGFILES}
	scp /tmp/${PKGNAME}-sippy-${RTPP_SW_VERSION}.tbz2 sobomax@download.sippysoft.com:/usr/local/www/data/rtpproxy/
	git tag rel.${RTPP_SW_VERSION}
	git push origin rel.${RTPP_SW_VERSION}

includepolice:
	for file in ${SRCS_BASE} ${SRCS_DEBUG}; do \
	  SMAKE="${MAKE}" SMAKEFLAGS="-f ../mk/Makefile" python ../misc/includepolice.py $${file} || sleep 5; \
	done

GENFINCODE= ../src/genfincode.sh

rtpp_timed_fin.c: genfincode.sh rtpp_timed.h
	$(GENFINCODE) rtpp_timed.h rtpp_timed_fin.h rtpp_timed_fin.c

rtpp_timed_fin.h: rtpp_timed_fin.c

rtpp_stream_fin.c: $(GENFINCODE) rtpp_stream.h
	$(GENFINCODE) rtpp_stream.h rtpp_stream_fin.h rtpp_stream_fin.c

rtpp_stream_fin.h: rtpp_stream_fin.c

rtpp_server_fin.c: $(GENFINCODE) rtpp_server.h
	$(GENFINCODE) rtpp_server.h rtpp_server_fin.h rtpp_server_fin.c

rtpp_server_fin.h: rtpp_server_fin.c

rtpp_refcnt_fin.c: $(GENFINCODE) rtpp_refcnt.h
	$(GENFINCODE) rtpp_refcnt.h rtpp_refcnt_fin.h rtpp_refcnt_fin.c

rtpp_refcnt_fin.h: rtpp_refcnt_fin.c

rtpp_log_obj_fin.c: $(GENFINCODE) rtpp_log_obj.h
	$(GENFINCODE) rtpp_log_obj.h rtpp_log_obj_fin.h rtpp_log_obj_fin.c

rtpp_log_obj_fin.h: rtpp_log_obj_fin.c

rtpp_command_rcache_fin.c: $(GENFINCODE) rtpp_command_rcache.h
	$(GENFINCODE) rtpp_command_rcache.h rtpp_command_rcache_fin.h rtpp_command_rcache_fin.c

rtpp_command_rcache_fin.h: rtpp_command_rcache_fin.c

rtpp_socket_fin.c: $(GENFINCODE) rtpp_socket.h
	$(GENFINCODE) rtpp_socket.h rtpp_socket_fin.h rtpp_socket_fin.c

rtpp_socket_fin.h: rtpp_socket_fin.c

rtpp_record_fin.c: $(GENFINCODE) rtpp_record.h
	$(GENFINCODE) rtpp_record.h rtpp_record_fin.h rtpp_record_fin.c

rtpp_record_fin.h: rtpp_record_fin.c

rtpp_ttl_fin.c: $(GENFINCODE) rtpp_ttl.h
	$(GENFINCODE) rtpp_ttl.h rtpp_ttl_fin.h rtpp_ttl_fin.c

rtpp_ttl_fin.h: rtpp_ttl_fin.c

rtpp_pipe_fin.c: $(GENFINCODE) rtpp_pipe.h
	$(GENFINCODE) rtpp_pipe.h rtpp_pipe_fin.h rtpp_pipe_fin.c

rtpp_pipe_fin.h: rtpp_pipe_fin.c

rtpp_pcount_fin.c: $(GENFINCODE) rtpp_pcount.h
	$(GENFINCODE) rtpp_pcount.h rtpp_pcount_fin.h rtpp_pcount_fin.c

rtpp_pcount_fin.h: rtpp_pcount_fin.c

.include <bsd.prog.mk>
