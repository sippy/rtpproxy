bin_PROGRAMS=rtpproxy rtpproxy_debug
BASE_SOURCES=main.c rtp.h rtpp_server.c rtpp_server.h \
  rtpp_defines.h rtpp_log.h rtpp_record.c rtpp_record.h rtpp_session.h \
  rtpp_util.c rtpp_util.h rtp.c rtp_resizer.c rtp_resizer.h rtpp_session.c \
  rtpp_command.c rtpp_command.h rtpp_network.h rtpp_network.c \
  rtpp_syslog_async.c rtpp_syslog_async.h rtpp_notify.c rtpp_notify.h \
  rtpp_command_async.h rtpp_command_async.c rtpp_proc_async.c \
  rtpp_proc_async.h rtpp_proc.h rtpp_proc.c rtpp_version.h rtpp_math.c \
  rtpp_math.h rtpp_wi.c rtpp_wi.h rtpp_wi_private.h rtpp_queue.c rtpp_queue.h \
  rtpp_netio_async.c rtpp_netio_async.h rtpp_record_private.h \
  rtpp_command_parse.c rtpp_command_parse.h rtpp_command_copy.c \
  rtpp_command_copy.h rtpp_command_ul.c rtpp_command_ul.h \
  rtpp_log_stand.c rtpp_log_stand.h rtpp_hash_table.c rtpp_hash_table.h \
  rtpp_types.h rtpp_pcache.c rtpp_pcache.h config_pp.h rtpp_stats.c \
  rtpp_stats.h rtpp_cfg_stable.h rtpp_command_stats.h rtpp_command_stats.c \
  rtp_info.h rtpp_command_private.h rtpp_controlfd.h rtpp_controlfd.c \
  rtpp_list.h rtpp_command_stream.h rtpp_command_stream.c rtpp_timed.c \
  rtpp_timed.h rtpp_analyzer.c rtpp_analyzer.h rtp_analyze.c rtp_analyze.h \
  rtpp_command_query.c rtpp_command_query.h rtpp_pearson.c rtpp_pearson.h \
  rtpp_refcnt.c rtpp_refcnt.h rtpp_command_rcache.c rtpp_command_rcache.h \
  rtpp_tnotify_set.c rtpp_tnotify_set.h rtpp_tnotify_tgt.h rtp_packet.h \
  rtpp_pthread.c rtpp_pthread.h rtpp_time.c rtpp_time.h \
  rtpp_sessinfo.c rtpp_sessinfo.h rtpp_weakref.c rtpp_weakref.h \
  rtpp_proc_servers.h rtpp_proc_servers.c rtpp_stream.h rtpp_stream.c \
  rtpp_genuid.h rtpp_genuid.c rtpp_genuid_singlet.h rtpp_genuid_singlet.c \
  rtpp_log_obj.h rtpp_log_obj.c rtpp_socket.c rtpp_socket.h \
  rtpp_ttl.c rtpp_ttl.h rtpp_proc_ttl.h rtpp_proc_ttl.c rtpp_pipe.h \
  rtpp_pipe.c rtpp_pcount.h rtpp_pcount.c rtpp_debug.h rtpp_monotime.h \
  rtpp_monotime.c rtpp_mallocs.c rtpp_mallocs.h

SRCS_DEBUG=	rtpp_memdeb.c rtpp_memdeb.h rtpp_memdeb_internal.h \
  rtpp_memdeb_stats.h rtpp_memdeb_test.c rtpp_stacktrace.c rtpp_stacktrace.h

SRCS_AUTOGEN=rtpp_timed_fin.c rtpp_timed_fin.h rtpp_stream_fin.c \
  rtpp_stream_fin.h rtpp_server_fin.c rtpp_server_fin.h rtpp_refcnt_fin.c \
  rtpp_refcnt_fin.h rtpp_log_obj_fin.c rtpp_log_obj_fin.h \
  rtpp_command_rcache_fin.c rtpp_command_rcache_fin.h rtpp_socket_fin.c \
  rtpp_socket_fin.h rtpp_record_fin.c rtpp_record_fin.h rtpp_ttl_fin.c \
  rtpp_ttl_fin.h rtpp_pipe_fin.c rtpp_pipe_fin.h rtpp_pcount_fin.c \
  rtpp_pcount_fin.h rtpp_sessinfo_fin.c rtpp_sessinfo_fin.h
rtpproxy_SOURCES=${BASE_SOURCES} ${SRCS_AUTOGEN}
rtpproxy_debug_SOURCES=${rtpproxy_SOURCES} ${SRCS_DEBUG}

rtpproxy_LDADD=-lm -lpthread
rtpproxy_debug_LDADD=${rtpproxy_LDADD} $(top_srcdir)/libexecinfo/libexecinfo.a \
  @LIBS_DL@
rtpproxy_debug_LDFLAGS=-static -Wl,--export-dynamic
rtpproxy_debug_CPPFLAGS=-DRTPP_DEBUG -DRTPP_MEMDEB_STDOUT -I$(top_srcdir) \
  -include rtpp_memdeb.h
rtpproxy_debug_CFLAGS=-g3 -O0 -fno-omit-frame-pointer

DEFS=	-DWITHOUT_SIPLOG -Wall -DRTPP_LOG_ADVANCED @DEFS@

CLEANFILES= ${SRCS_AUTOGEN}
BUILT_SOURCES= ${SRCS_AUTOGEN}

GENFINCODE= $(top_srcdir)/src/genfincode.sh

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

rtpp_sessinfo_fin.c: $(GENFINCODE) rtpp_sessinfo.h
	$(GENFINCODE) rtpp_sessinfo.h rtpp_sessinfo_fin.h rtpp_sessinfo_fin.c

rtpp_sessinfo_fin.h: rtpp_sessinfo_fin.c
