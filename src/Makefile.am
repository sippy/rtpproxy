UCL_DIR=$(top_srcdir)/external/libucl

bin_PROGRAMS=rtpproxy rtpproxy_debug
if BUILD_OBJCK
noinst_PROGRAMS=rtpp_objck rtpp_objck_perf
endif
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
  rtpp_hash_table.c rtpp_hash_table.h \
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
  rtpp_monotime.c rtpp_mallocs.c rtpp_mallocs.h rtpp_pcnt_strm.h \
  rtpp_pcnt_strm.c rtpp_endian.h rtpp_ringbuf.c rtpp_ringbuf.h \
  rtpp_command_delete.c rtpp_command_delete.h rtpp_command_record.c \
  rtpp_command_record.h rtpp_port_table.c rtpp_port_table.h rtpp_acct.c \
  rtpp_acct.h rtpp_stats.h rtpp_bindaddrs.c rtpp_bindaddrs.h rtpp_ssrc.h \
  rtpp_netaddr.c rtpp_netaddr.h rtpp_acct_pipe.h rtpp_command_play.c \
  rtpp_command_play.h rtpp_command_ver.h rtpp_command_ver.c \
  rtpp_pearson_perfect.c rtpp_pearson_perfect.h rtpp_acct_rtcp.h \
  rtpp_acct_rtcp.c rtpp_cfile.c rtpp_cfile.h rtpp_ucl.c rtpp_ucl.h

rtpproxy_LDADD=-lm -lpthread @LIBS_ELPERIODIC@ $(top_srcdir)/libucl/libucl.a
rtpproxy_debug_LDADD=-lm -lpthread @LIBS_ELPERIODIC@ $(top_srcdir)/libucl/libucl_debug.a \
  $(top_srcdir)/libexecinfo/libexecinfo.a @LIBS_DL@
rtpproxy_debug_LDFLAGS=-static -Wl,--export-dynamic

if ENABLE_MODULE_IF
BASE_SOURCES+=rtpp_module_if.c rtpp_module_if.h rtpp_module.h
rtpproxy_LDADD+=@LIBS_DL@
rtpproxy_LDFLAGS=-Wl,--export-dynamic
endif

if BUILD_LOG_STAND
BASE_SOURCES+=rtpp_log_stand.c rtpp_log_stand.h
else
BASE_SOURCES+=rtpp_log.c rtpp_log.h
rtpproxy_LDADD+=@LIBS_SIPLOG@
rtpproxy_debug_LDADD+=@LIBS_SIPLOG_DBG@
endif

SRGC_MEMDEB_CORE=rtpp_memdeb.c rtpp_memdeb.h rtpp_memdeb_internal.h \
  rtpp_memdeb_stats.h rtpp_memdeb_test.c rtpp_memdeb_glitch.c \
  rtpp_memdeb_glitch.h
SRCS_DEBUG=	$(SRGC_MEMDEB_CORE) rtpp_stacktrace.c rtpp_stacktrace.h

SRCS_AUTOGEN=rtpp_timed_fin.c rtpp_timed_fin.h rtpp_stream_fin.c \
  rtpp_stream_fin.h rtpp_server_fin.c rtpp_server_fin.h rtpp_refcnt_fin.c \
  rtpp_refcnt_fin.h rtpp_log_obj_fin.c rtpp_log_obj_fin.h \
  rtpp_command_rcache_fin.c rtpp_command_rcache_fin.h rtpp_socket_fin.c \
  rtpp_socket_fin.h rtpp_record_fin.c rtpp_record_fin.h rtpp_ttl_fin.c \
  rtpp_ttl_fin.h rtpp_pipe_fin.c rtpp_pipe_fin.h rtpp_pcount_fin.c \
  rtpp_pcount_fin.h rtpp_sessinfo_fin.c rtpp_sessinfo_fin.h \
  rtpp_pcnt_strm_fin.h rtpp_pcnt_strm_fin.c rtpp_ringbuf_fin.c \
  rtpp_ringbuf_fin.h rtpp_module_if_fin.h rtpp_module_if_fin.c \
  rtpp_port_table_fin.c rtpp_port_table_fin.h \
  rtpp_netaddr_fin.c rtpp_netaddr_fin.h \
  rtpp_stats_fin.c rtpp_stats_fin.h rtpp_pearson_perfect_fin.c \
  rtpp_pearson_perfect_fin.h rtpp_timed_task_fin.c rtpp_timed_task_fin.h
rtpproxy_SOURCES=$(BASE_SOURCES) $(SRCS_AUTOGEN)
rtpproxy_debug_SOURCES=$(rtpproxy_SOURCES) $(SRCS_DEBUG)
rtpp_objck_perf_LDADD=-lm -lpthread @LIBS_ELPERIODIC@
rtpp_objck_perf_SOURCES=rtpp_objck.c $(SRCS_AUTOGEN) \
  rtpp_stats.c rtpp_stats.h rtpp_mallocs.c rtpp_mallocs.h \
  rtpp_pearson_perfect.c rtpp_pearson_perfect.h rtpp_pearson.c rtpp_pearson.h \
  rtpp_refcnt.c rtpp_refcnt.h rtpp_time.c rtpp_time.h rtpp_timed.c rtpp_timed.h \
  rtpp_queue.c rtpp_queue.h rtpp_wi.c rtpp_wi.h
rtpp_objck_LDADD=$(rtpp_objck_perf_LDADD)
rtpp_objck_SOURCES=$(rtpp_objck_perf_SOURCES) $(SRGC_MEMDEB_CORE)

RTPP_MEMDEB_CPPFLAGS=-DRTPP_MEMDEB_STDOUT -include rtpp_memdeb.h
RTPP_COMMON_CPPFLAGS=-DCFILE_PATH='"$(sysconfdir)/@PACKAGE@.conf"' \
  -DMDDIR_PATH='"$(libdir)/@PACKAGE@"' -I$(UCL_DIR)/include
EXTRA_CFLAGS=-Werror=implicit-function-declaration -Wall

if BUILD_ELPERIODIC
EXTRA_CPPFLAGS=-I$(top_srcdir)/libelperiodic/src
endif

rtpproxy_debug_CFLAGS=$(EXTRA_CFLAGS) -g3 -O0 -fno-omit-frame-pointer
rtpproxy_debug_CPPFLAGS=$(RTPP_COMMON_CPPFLAGS) $(EXTRA_CPPFLAGS) -DRTPP_DEBUG $(RTPP_MEMDEB_CPPFLAGS) \
  -DMEMDEB_APP=@PACKAGE@ -I$(top_srcdir)

rtpproxy_CFLAGS=$(EXTRA_CFLAGS)
rtpproxy_CPPFLAGS=$(RTPP_COMMON_CPPFLAGS) $(EXTRA_CPPFLAGS)

rtpp_objck_perf_CPPFLAGS=$(EXTRA_CPPFLAGS)
rtpp_objck_CFLAGS=$(EXTRA_CFLAGS) -g3 -O0 -fno-omit-frame-pointer
rtpp_objck_CPPFLAGS=$(EXTRA_CPPFLAGS) $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP=rtpp_objck

DEFS=	-Wall @DEFS@

CLEANFILES= $(SRCS_AUTOGEN) *.gcda *.gcno
BUILT_SOURCES= $(SRCS_AUTOGEN)

GENFINCODE= $(top_srcdir)/src/genfincode.sh
GENFINCODE_S= $(top_srcdir)/src/genfincode_stat.sh

rtpp_timed_fin.c: $(GENFINCODE_S) rtpp_timed.h
	$(GENFINCODE_S) rtpp_timed.h rtpp_timed_fin.h rtpp_timed_fin.c

rtpp_timed_fin.h: rtpp_timed_fin.c

rtpp_timed_task_fin.c: $(GENFINCODE) rtpp_timed_task.h
	$(GENFINCODE) rtpp_timed_task.h rtpp_timed_task_fin.h rtpp_timed_task_fin.c

rtpp_timed_task_fin.h: rtpp_timed_task_fin.c

rtpp_stream_fin.c: $(GENFINCODE_S) rtpp_stream.h
	$(GENFINCODE_S) rtpp_stream.h rtpp_stream_fin.h rtpp_stream_fin.c

rtpp_stream_fin.h: rtpp_stream_fin.c

rtpp_server_fin.c: $(GENFINCODE) rtpp_server.h
	$(GENFINCODE_S) rtpp_server.h rtpp_server_fin.h rtpp_server_fin.c

rtpp_server_fin.h: rtpp_server_fin.c

rtpp_refcnt_fin.c: $(GENFINCODE_S) rtpp_refcnt.h
	$(GENFINCODE_S) rtpp_refcnt.h rtpp_refcnt_fin.h rtpp_refcnt_fin.c

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

rtpp_ringbuf_fin.c: $(GENFINCODE) rtpp_ringbuf.h
	$(GENFINCODE) rtpp_ringbuf.h rtpp_ringbuf_fin.h rtpp_ringbuf_fin.c

rtpp_ringbuf_fin.h: rtpp_ringbuf_fin.c

rtpp_sessinfo_fin.c: $(GENFINCODE) rtpp_sessinfo.h
	$(GENFINCODE) rtpp_sessinfo.h rtpp_sessinfo_fin.h rtpp_sessinfo_fin.c

rtpp_sessinfo_fin.h: rtpp_sessinfo_fin.c

rtpp_pcnt_strm_fin.c: $(GENFINCODE) rtpp_pcnt_strm.h
	$(GENFINCODE) rtpp_pcnt_strm.h rtpp_pcnt_strm_fin.h rtpp_pcnt_strm_fin.c

rtpp_pcnt_strm_fin.h: rtpp_pcnt_strm_fin.c

rtpp_module_if_fin.c: $(GENFINCODE) rtpp_module_if.h
	$(GENFINCODE) rtpp_module_if.h rtpp_module_if_fin.h rtpp_module_if_fin.c

rtpp_module_if_fin.h: rtpp_module_if_fin.c

rtpp_port_table_fin.c: $(GENFINCODE) rtpp_port_table.h
	$(GENFINCODE) rtpp_port_table.h rtpp_port_table_fin.h rtpp_port_table_fin.c

rtpp_port_table_fin.h: rtpp_port_table_fin.c

#rtpp_acct_fin.c: $(GENFINCODE) rtpp_acct.h
#	$(GENFINCODE) rtpp_acct.h rtpp_acct_fin.h rtpp_acct_fin.c

#rtpp_acct_fin.h: rtpp_acct_fin.c

#rtpp_acct_rtcp_fin.c: $(GENFINCODE) rtpp_acct_rtcp.h
#	$(GENFINCODE) rtpp_acct_rtcp.h rtpp_acct_rtcp_fin.h rtpp_acct_rtcp_fin.c

#rtpp_acct_rtcp_fin.h: rtpp_acct_rtcp_fin.c

rtpp_netaddr_fin.c: $(GENFINCODE_S) rtpp_netaddr.h
	$(GENFINCODE_S) rtpp_netaddr.h rtpp_netaddr_fin.h rtpp_netaddr_fin.c

rtpp_netaddr_fin.h: rtpp_netaddr_fin.c

rtpp_stats_fin.c: $(GENFINCODE_S) rtpp_stats.h
	$(GENFINCODE_S) rtpp_stats.h rtpp_stats_fin.h rtpp_stats_fin.c

rtpp_stats_fin.h: rtpp_stats_fin.c

rtpp_pearson_perfect_fin.c: $(GENFINCODE_S) rtpp_pearson_perfect.h
	$(GENFINCODE_S) rtpp_pearson_perfect.h rtpp_pearson_perfect_fin.h rtpp_pearson_perfect_fin.c

rtpp_pearson_perfect_fin.h: rtpp_pearson_perfect_fin.c

IPLDIR=$(top_srcdir)/src/ipol

includepolice:
	@rm -f $(IPLDIR)/*.txt $(IPLDIR)/*.iout
	@nfiles=`echo ${BASE_SOURCES} | wc -w`; nfiles=$$(($${nfiles})); \
	 i=1; nwarns=0; \
	 for file in ${BASE_SOURCES}; \
	 do \
	   echo -n "  policing file $${i} of $${nfiles} -> $${file}: "; \
	   set +e; set +x; \
	   SMAKE="${MAKE}" SMAKEFLAGS='CFLAGS="-DRTPP_DEBUG_MAX"' \
            SIPATH="$(UCL_DIR)/include:$(top_srcdir)/libelperiodic/src" \
	    python ../misc/includepolice.py $${file} > $(IPLDIR)/$${file}.txt; \
	   RC=$${?}; if [ $${RC} -eq 255 ]; then exit 1; fi; \
	   if [ $${RC} -eq 0 ]; then \
	     rm -f $(IPLDIR)/$${file}.txt $(IPLDIR)/$${file}.iout; \
	     echo "all clean"; \
	   else \
	     echo "$${RC} warning(s)"; \
	     nwarns=$$(($${nwarns} + $${RC})); \
	   fi; \
	   i=$$(($${i} + 1)); \
	 done; \
	 echo "=========="; \
	 echo "Total warnings: $${nwarns}"
