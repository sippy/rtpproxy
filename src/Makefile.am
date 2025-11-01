include $(top_srcdir)/m4/dirs.ami
include $(top_srcdir)/m4/memdeb.ami
include $(top_srcdir)/m4/ccflags.ami
include $(top_srcdir)/m4/coverage.ami
include $(top_srcdir)/autosrc/Makefile.ami

bin_PROGRAMS=rtpproxy
if ENABLE_noinst
noinst_PROGRAMS = rtpp_rzmalloc_perf rtpp_rzmalloc_perf_debug rtpp_fintest
endif
if ENABLE_debug
bin_PROGRAMS += rtpproxy_debug
endif
if ENABLE_LIBRTPPROXY
lib_LTLIBRARIES = librtpproxy.la
else
noinst_LTLIBRARIES = librtpproxy.la
endif

if ENABLE_noinst
if BUILD_OBJCK
noinst_PROGRAMS += rtpp_objck rtpp_objck_perf
endif
endif

RTPP_AUTOSRC_SOURCES = rtpp_command_rcache.h rtpp_log_obj.h \
  rtpp_port_table.h rtpp_timed_task.h rtpp_modman.h

RTPP_AUTOSRC_SOURCES_S = rtpp_netaddr.h rtpp_pearson_perfect.h rtpp_refcnt.h \
  rtpp_server.h rtpp_stats.h rtpp_stream.h rtpp_timed.h rtpp_pcount.h \
  rtpp_record.h rtpp_hash_table.h rtpp_weakref.h rtpp_analyzer.h \
  rtpp_pcnt_strm.h rtpp_ttl.h rtpp_pipe.h rtpp_ringbuf.h rtpp_sessinfo.h \
  rtpp_rw_lock.h rtpp_proc_servers.h rtpp_proc_wakeup.h rtpp_socket.h \
  rtpp_refproxy.h rtpp_command_reply.h rtpp_genuid.h

CMDSRCDIR=$(MAINSRCDIR)/commands
BASE_SOURCES=main.c rtp.h rtpp_server.c \
  rtpp_defines.h rtpp_log.h rtpp_record.c rtpp_session.h \
  rtpp_util.c rtpp_util.h rtp.c rtp_resizer.c rtp_resizer.h rtpp_session.c \
  rtpp_command.c rtpp_command.h rtpp_network.h rtpp_network.c \
  rtpp_syslog_async.c rtpp_syslog_async.h rtpp_notify.c rtpp_notify.h \
  rtpp_command_async.h rtpp_command_async.c rtpp_proc_async.c \
  rtpp_proc_async.h rtpp_proc.h rtpp_proc.c rtpp_version.h \
  rtpp_math.h rtpp_wi.h rtpp_wi_private.h rtpp_queue.c rtpp_queue.h \
  rtpp_netio_async.c rtpp_netio_async.h rtpp_record_private.h \
  rtpp_command_parse.c rtpp_command_parse.h $(CMDSRCDIR)/rpcpv1_copy.c \
  $(CMDSRCDIR)/rpcpv1_copy.h $(CMDSRCDIR)/rpcpv1_ul.c $(CMDSRCDIR)/rpcpv1_ul.h \
  rtpp_hash_table.c rtpp_types.h config_pp.h rtpp_stats.c \
  rtpp_cfg.h $(CMDSRCDIR)/rpcpv1_stats.h $(CMDSRCDIR)/rpcpv1_stats.c \
  rtp_info.h rtpp_command_private.h rtpp_controlfd.h rtpp_controlfd.c \
  rtpp_list.h rtpp_command_stream.h rtpp_command_stream.c rtpp_timed.c \
  rtpp_analyzer.c rtp_analyze.c rtp_analyze.h \
  $(CMDSRCDIR)/rpcpv1_query.c $(CMDSRCDIR)/rpcpv1_query.h rtpp_pearson.c rtpp_pearson.h \
  rtpp_command_rcache.c rtpp_command_ecodes.h \
  rtpp_tnotify_set.c rtpp_tnotify_set.h rtpp_tnotify_tgt.h rtp_packet.h \
  rtp_packet.c rtpp_time.c rtpp_time.h rtpp_pcnts_strm.h rtpp_runcreds.h \
  rtpp_sessinfo.c rtpp_weakref.c rtpp_rw_lock.c \
  rtpp_proc_servers.c rtpp_stream.c rtpp_proc_wakeup.c \
  rtpp_genuid.c \
  rtpp_log_obj.c rtpp_socket.c rtpp_wi_apis.c rtpp_wi_apis.h \
  rtpp_ttl.c rtpp_proc_ttl.h rtpp_proc_ttl.c \
  rtpp_pipe.c rtpp_pcount.c rtpp_debug.h rtpp_wi_sgnl.c rtpp_wi_sgnl.h \
  rtpp_wi_data.c rtpp_wi_data.h \
  rtpp_pcnt_strm.c rtpp_endian.h rtpp_ringbuf.c \
  $(CMDSRCDIR)/rpcpv1_delete.c $(CMDSRCDIR)/rpcpv1_delete.h $(CMDSRCDIR)/rpcpv1_record.c \
  $(CMDSRCDIR)/rpcpv1_record.h rtpp_port_table.c rtpp_acct.c \
  rtpp_acct.h rtpp_stats.h rtpp_bindaddrs.c rtpp_bindaddrs.h rtpp_ssrc.h \
  rtpp_netaddr.c rtpp_acct_pipe.h $(CMDSRCDIR)/rpcpv1_play.c \
  $(CMDSRCDIR)/rpcpv1_play.h $(CMDSRCDIR)/rpcpv1_ver.h $(CMDSRCDIR)/rpcpv1_ver.c \
  rtpp_pearson_perfect.c rtpp_acct_rtcp.h \
  rtpp_acct_rtcp.c rtpp_cfile.c rtpp_cfile.h rtpp_ucl.c rtpp_ucl.h \
  rtpp_network_io.c rtpp_network_io.h rtpp_wi_pkt.c rtpp_wi_pkt.h \
  rtpp_timeout_data.c rtpp_timeout_data.h rtpp_locking.h \
  rtpp_nofile.c rtpp_nofile.h rtpp_record_adhoc.h \
  $(CMDSRCDIR)/rpcpv1_norecord.c $(CMDSRCDIR)/rpcpv1_norecord.h \
  $(CMDSRCDIR)/rpcpv1_ul_subc.c $(CMDSRCDIR)/rpcpv1_ul_subc.h \
  $(RTPP_AUTOSRC_SOURCES) rtpp_epoll.c rtpp_str.c rtpp_str.h \
  rtpp_sbuf.c rtpp_sbuf.h rtpp_refproxy.c rtpp_command_reply.c
BASE_SOURCES+=$(ADV_DIR)/packet_observer.h $(ADV_DIR)/pproc_manager.c \
  $(ADV_DIR)/pproc_manager.h
BASE_SOURCES+=rtpp_modman.c rtpp_module_if_static.c rtpp_module_if_static.h

rtpproxy_LDADD=librtpproxy.la -lm -lpthread
rtpproxy_debug_LDADD=-lm -lpthread @LIBS_ELPERIODIC@ $(top_srcdir)/libucl/libucl_debug.la \
  $(XXH_DIR)/libxxHash_debug.la $(RTPP_MEMDEB_LDADD)
rtpproxy_debug_LDFLAGS=-Wl,--export-dynamic $(LTO_FLAG)
rtpproxy_LDFLAGS=$(LTO_FLAG)

if ENABLE_MODULE_IF
RTPP_AUTOSRC_SOURCES += rtpp_module_if.h
BASE_SOURCES += rtpp_module_if.c rtpp_module.h
rtpproxy_LDADD+=@LIBS_DL@
rtpproxy_LDFLAGS+=-Wl,--export-dynamic
endif

if BUILD_LOG_STAND
BASE_SOURCES+=rtpp_log_stand.c rtpp_log_stand.h
else
BASE_SOURCES+=rtpp_log.c rtpp_log.h
rtpproxy_LDADD+=@LIBS_SIPLOG@
rtpproxy_debug_LDADD+=@LIBS_SIPLOG_DBG@
endif

SRCS_MEMDEB_CORE = $(RTPP_MEMDEB_CORESRCS) rtpp_memdeb_stats.h rtpp_memdeb_test.c
SRCS_DEBUG=	$(SRCS_MEMDEB_CORE)

rtpproxy_SOURCES=main.c librtpproxy.la
if ENABLE_MODULE_IF
rtpproxy_SOURCES += rtpp_module_if.c rtpp_module.h
endif
rtpproxy_debug_SOURCES=$(BASE_SOURCES) $(SRCS_AUTOGEN) $(SRCS_DEBUG) $(SRCS_AUTOGEN_DEBUG)
rtpp_objck_perf_LDADD=-lm -lpthread @LIBS_ELPERIODIC@
rtpp_objck_BASESOURCES=rtpp_objck.c $(SRCS_AUTOGEN) rtpp_network.c \
  rtpp_network.h rtpp_stats.c rtpp_stats.h rtpp_netaddr.c rtpp_netaddr.h \
  rtpp_pearson_perfect.c rtpp_pearson_perfect.h rtpp_pearson.c rtpp_pearson.h \
  rtpp_time.c rtpp_time.h rtpp_timed.c rtpp_timed.h rtp_packet.c rtp_packet.h \
  rtpp_queue.c rtpp_queue.h rtpp_wi.h rtpp_wi_data.c rtpp_wi_data.h \
  rtpp_wi_sgnl.c rtpp_wi_sgnl.h rtpp_wi_pkt.c rtpp_wi_pkt.h rtp.c rtp.h \
  rtpp_util.c rtpp_util.h
rtpp_objck_perf_SOURCES=$(rtpp_objck_BASESOURCES) rtpp_refcnt.c rtpp_refcnt.h \
  rtpp_mallocs.c rtpp_mallocs.h
rtpp_objck_LDADD=$(rtpp_objck_perf_LDADD) $(RTPP_MEMDEB_LDADD)
rtpp_objck_SOURCES=$(rtpp_objck_BASESOURCES) $(SRCS_MEMDEB_CORE) $(SRCS_AUTOGEN_DEBUG)

rtpp_rzmalloc_perf_SOURCES = rtpp_rzmalloc_perf.c rtpp_mallocs.c rtpp_mallocs.h \
  rtpp_refcnt.c rtpp_time.c
rtpp_rzmalloc_perf_CFLAGS = $(OPT_CFLAGS) $(EXTRA_CFLAGS)
rtpp_rzmalloc_perf_CPPFLAGS = $(EXTRA_CPPFLAGS)
rtpp_rzmalloc_perf_LDFLAGS = $(LTO_FLAG)
rtpp_rzmalloc_perf_LDADD = -lm

rtpp_rzmalloc_perf_debug_SOURCES = rtpp_rzmalloc_perf.c rtpp_time.c \
  $(SRCS_MEMDEB_CORE) $(SRCS_AUTOGEN_DEBUG)
rtpp_rzmalloc_perf_debug_CFLAGS = $(NOPT_CFLAGS) $(EXTRA_CFLAGS) $(RTPP_MEMDEB_CFLAGS)
rtpp_rzmalloc_perf_debug_CPPFLAGS = $(rtpp_rzmalloc_perf_CPPFLAGS) $(RTPP_MEMDEB_CPPFLAGS) \
  -DMEMDEB_APP=rtpp_rzmalloc_perf -I$(top_srcdir)
rtpp_rzmalloc_perf_debug_LDFLAGS = $(rtpp_rzmalloc_perf_LDFLAGS)
rtpp_rzmalloc_perf_debug_LDADD = $(rtpp_rzmalloc_perf_LDADD) \
  $(top_srcdir)/libexecinfo/libexecinfo.la @LIBS_DL@ -lpthread

RTPP_COMMON_CPPFLAGS=-DCFILE_PATH='"$(sysconfdir)/@PACKAGE@.conf"' \
  -DMDDIR_PATH='"$(libdir)/@PACKAGE@"' -I$(UCL_DIR)/include \
  -I$(XXH_DIR) -D_BSD_SOURCE
EXTRA_CFLAGS = $(CC_WFLAGS) $(LTO_FLAG)

EXTRA_CPPFLAGS = -I$(RTPP_AUTOSRC_DIR)

if BUILD_ELPERIODIC
EXTRA_CPPFLAGS += -I$(top_srcdir)/external/libelperiodic/src
endif

rtpproxy_debug_CFLAGS=$(NOPT_CFLAGS) $(EXTRA_CFLAGS) $(RTPP_MEMDEB_CFLAGS)
rtpproxy_debug_CPPFLAGS=$(RTPP_COMMON_CPPFLAGS) $(EXTRA_CPPFLAGS) $(RTPP_MEMDEB_CPPFLAGS) \
  -DMEMDEB_APP=@PACKAGE@ -I$(top_srcdir)

rtpproxy_CFLAGS=$(OPT_CFLAGS) $(EXTRA_CFLAGS)
rtpproxy_CPPFLAGS=$(RTPP_COMMON_CPPFLAGS) $(EXTRA_CPPFLAGS)

rtpp_objck_perf_CFLAGS=$(OPT_CFLAGS) $(EXTRA_CFLAGS)
rtpp_objck_perf_CPPFLAGS=$(EXTRA_CPPFLAGS) -D_BSD_SOURCE
rtpp_objck_perf_LDFLAGS=$(LDO_LDFLAGS)
rtpp_objck_CFLAGS=$(NOPT_CFLAGS) $(EXTRA_CFLAGS) $(RTPP_MEMDEB_CFLAGS)
rtpp_objck_CPPFLAGS=$(rtpp_objck_perf_CPPFLAGS) $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP=rtpp_objck \
  -DRTPQ_CHECK_SEQ
rtpp_objck_LDFLAGS=$(rtpp_objck_perf_LDFLAGS)

DEFS=	-Wall @DEFS@

#BUILT_SOURCES= $(_SRCS_AUTOGEN)

GENFINCODE= $(top_srcdir)/src/genfincode.sh
GENFINCODE_S= $(top_srcdir)/src/genfincode_stat.sh

rtpp_fintest_SOURCES = rtpp_fintest.c $(SRCS_MEMDEB_CORE) \
  $(SRCS_AUTOGEN) $(SRCS_AUTOGEN_DEBUG)
rtpp_fintest_CPPFLAGS = -I$(RTPP_AUTOSRC_DIR) -Drtpp_fintest=main \
  "-DRTPP_AUTOTRAP()=(_naborts++)" -DRTPP_FINTEST $(RTPP_MEMDEB_CPPFLAGS) \
  -I$(top_srcdir) -DMEMDEB_APP=rtpp_fintest
rtpp_fintest_CFLAGS = $(OPT_CFLAGS) $(LTO_FLAG) $(RTPP_MEMDEB_CFLAGS)
rtpp_fintest_LDADD = $(RTPP_MEMDEB_LDADD)
rtpp_fintest_LDFLAGS = $(LTO_FLAG)

librtpproxy_la_SOURCES = $(BASE_SOURCES) $(SRCS_AUTOGEN) \
  rtpp_refcnt.c rtpp_refcnt.h rtpp_mallocs.c rtpp_mallocs.h \
  rtpp_coverage.c rtpp_coverage.h \
  $(top_srcdir)/libucl/libucl.la $(XXH_DIR)/libxxHash.la \
  librtpp_main.c
librtpproxy_la_CFLAGS = $(rtpproxy_CFLAGS) -fPIC
librtpproxy_la_CPPFLAGS = $(rtpproxy_CPPFLAGS) -DLIBRTPPROXY
librtpproxy_la_LIBADD = $(top_srcdir)/libucl/libucl.la \
  $(XXH_DIR)/libxxHash.la
if BUILD_MODULES
librtpproxy_la_LIBADD += $(MOD_DIR)/catch_dtmf/librtpp_catch_dtmf.la \
  $(MOD_DIR)/acct_csv/librtpp_acct_csv.la \
  $(MOD_DIR)/acct_rtcp_hep/librtpp_acct_rtcp_hep.la
if BUILD_CRYPTO
librtpproxy_la_LIBADD += $(MOD_DIR)/dtls_gw/librtpp_dtls_gw.la \
  $(MOD_DIR)/ice_lite/librtpp_ice_lite.la
endif
endif
librtpproxy_la_LDFLAGS = -static
librtpproxy_la_LIBADD += @LIBS_ELPERIODIC@

update_autosrc:
	@echo "# Auto-generated by $(srcdir)/Makefile - DO NOT EDIT!" > $(RTPP_AUTOSRC_DIR)/Makefile.ami
	@echo "include \$$(top_srcdir)/m4/autosrc.ami" >> $(RTPP_AUTOSRC_DIR)/Makefile.ami
	@echo "SRCS_AUTOGEN = # To be continued..." >> $(RTPP_AUTOSRC_DIR)/Makefile.ami
	@echo "SRCS_AUTOGEN_DEBUG = # To be continued..." >> $(RTPP_AUTOSRC_DIR)/Makefile.ami
	@set -ex; \
	for f in $(RTPP_AUTOSRC_SOURCES); \
	do \
	  ofile="$${f%.h}"; \
	  if [ $${ofile} = $${f} ]; \
	  then \
	    echo "Cannot determine output file name from $${f}" >&2; \
	    exit 1; \
	  fi; \
	  echo "Processing $${f}..."; \
	  $(GENFINCODE) $${f} $(RTPP_AUTOSRC_DIR)/$${ofile}_fin.h $(RTPP_AUTOSRC_DIR)/$${ofile}_fin.c; \
	  echo "$${ofile}_AUTOSRCS = \$$(RTPP_AUTOSRC_DIR)/$${ofile}_fin.h \$$(RTPP_AUTOSRC_DIR)/$${ofile}_fin.c" >> $(RTPP_AUTOSRC_DIR)/Makefile.ami; \
	  echo "SRCS_AUTOGEN += \$$($${ofile}_AUTOSRCS)" >> $(RTPP_AUTOSRC_DIR)/Makefile.ami; \
	done
	@set -ex; \
	for f in $(RTPP_AUTOSRC_SOURCES_S); \
	do \
	  ofile="$${f%.h}"; \
	  if [ $${ofile} = $${f} ]; \
	  then \
	    echo "Cannot determine output file name from $${f}" >&2; \
	    exit 1; \
	  fi; \
	  echo "Processing $${f}..."; \
	  $(GENFINCODE_S) $${f} $(RTPP_AUTOSRC_DIR)/$${ofile}_fin.h $(RTPP_AUTOSRC_DIR)/$${ofile}_fin.c; \
	  echo "$${ofile}_AUTOSRCS = \$$(RTPP_AUTOSRC_DIR)/$${ofile}_fin.h \$$(RTPP_AUTOSRC_DIR)/$${ofile}_fin.c" >> $(RTPP_AUTOSRC_DIR)/Makefile.ami; \
	  echo "SRCS_AUTOGEN_DEBUG += \$$($${ofile}_AUTOSRCS)" >> $(RTPP_AUTOSRC_DIR)/Makefile.ami; \
	done

include $(top_srcdir)/m4/ipolice.ami
