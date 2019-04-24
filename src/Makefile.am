include $(top_srcdir)/m4/memdeb.ami
include $(top_srcdir)/m4/autosrc.ami

include $(top_srcdir)/autosrc/Makefile.ami

UCL_DIR=$(top_srcdir)/external/libucl

bin_PROGRAMS=rtpproxy rtpproxy_debug
noinst_PROGRAMS = rtpp_rzmalloc_perf rtpp_fintest

if BUILD_OBJCK
noinst_PROGRAMS += rtpp_objck rtpp_objck_perf
endif

RTPP_AUTOSRC_SOURCES = rtpp_command_rcache.h rtpp_log_obj.h \
  rtpp_pcnt_strm.h rtpp_pcount.h rtpp_pipe.h rtpp_port_table.h rtpp_record.h \
  rtpp_ringbuf.h rtpp_sessinfo.h rtpp_socket.h rtpp_timed_task.h rtpp_ttl.h

RTPP_AUTOSRC_SOURCES_S = rtpp_netaddr.h rtpp_pearson_perfect.h rtpp_refcnt.h \
  rtpp_server.h rtpp_stats.h rtpp_stream.h rtpp_timed.h

BASE_SOURCES=main.c rtp.h rtpp_server.c \
  rtpp_defines.h rtpp_log.h rtpp_record.c rtpp_session.h \
  rtpp_util.c rtpp_util.h rtp.c rtp_resizer.c rtp_resizer.h rtpp_session.c \
  rtpp_command.c rtpp_command.h rtpp_network.h rtpp_network.c \
  rtpp_syslog_async.c rtpp_syslog_async.h rtpp_notify.c rtpp_notify.h \
  rtpp_command_async.h rtpp_command_async.c rtpp_proc_async.c \
  rtpp_proc_async.h rtpp_proc.h rtpp_proc.c rtpp_version.h \
  rtpp_math.h rtpp_wi.c rtpp_wi.h rtpp_wi_private.h rtpp_queue.c rtpp_queue.h \
  rtpp_netio_async.c rtpp_netio_async.h rtpp_record_private.h \
  rtpp_command_parse.c rtpp_command_parse.h rtpp_command_copy.c \
  rtpp_command_copy.h rtpp_command_ul.c rtpp_command_ul.h \
  rtpp_hash_table.c rtpp_hash_table.h rtpp_types.h config_pp.h rtpp_stats.c \
  rtpp_cfg_stable.h rtpp_command_stats.h rtpp_command_stats.c \
  rtp_info.h rtpp_command_private.h rtpp_controlfd.h rtpp_controlfd.c \
  rtpp_list.h rtpp_command_stream.h rtpp_command_stream.c rtpp_timed.c \
  rtpp_analyzer.c rtpp_analyzer.h rtp_analyze.c rtp_analyze.h \
  rtpp_command_query.c rtpp_command_query.h rtpp_pearson.c rtpp_pearson.h \
  rtpp_refcnt.c rtpp_command_rcache.c rtpp_command_ecodes.h \
  rtpp_tnotify_set.c rtpp_tnotify_set.h rtpp_tnotify_tgt.h rtp_packet.h \
  rtpp_time.c rtpp_time.h rtpp_pcnts_strm.h rtpp_runcreds.h \
  rtpp_sessinfo.c rtpp_weakref.c rtpp_weakref.h \
  rtpp_proc_servers.h rtpp_proc_servers.c rtpp_stream.c \
  rtpp_genuid.h rtpp_genuid.c rtpp_genuid_singlet.h rtpp_genuid_singlet.c \
  rtpp_log_obj.c rtpp_socket.c \
  rtpp_ttl.c rtpp_proc_ttl.h rtpp_proc_ttl.c \
  rtpp_pipe.c rtpp_pcount.c rtpp_debug.h \
  rtpp_mallocs.c rtpp_mallocs.h \
  rtpp_pcnt_strm.c rtpp_endian.h rtpp_ringbuf.c \
  rtpp_command_delete.c rtpp_command_delete.h rtpp_command_record.c \
  rtpp_command_record.h rtpp_port_table.c rtpp_acct.c \
  rtpp_acct.h rtpp_stats.h rtpp_bindaddrs.c rtpp_bindaddrs.h rtpp_ssrc.h \
  rtpp_netaddr.c rtpp_acct_pipe.h rtpp_command_play.c \
  rtpp_command_play.h rtpp_command_ver.h rtpp_command_ver.c \
  rtpp_pearson_perfect.c rtpp_acct_rtcp.h \
  rtpp_acct_rtcp.c rtpp_cfile.c rtpp_cfile.h rtpp_ucl.c rtpp_ucl.h \
  $(RTPP_AUTOSRC_SOURCES) $(RTPP_AUTOSRC_SOURCES_S)

rtpproxy_LDADD=-lm -lpthread @LIBS_ELPERIODIC@ $(top_srcdir)/libucl/libucl.a
rtpproxy_debug_LDADD=-lm -lpthread @LIBS_ELPERIODIC@ $(top_srcdir)/libucl/libucl_debug.a \
  $(RTPP_MEMDEB_LDADD)
rtpproxy_debug_LDFLAGS=-static -Wl,--export-dynamic

if ENABLE_MODULE_IF
RTPP_AUTOSRC_SOURCES += rtpp_module_if.h
BASE_SOURCES += rtpp_module_if.c rtpp_module.h
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

SRCS_MEMDEB_CORE = $(RTPP_MEMDEB_CORESRCS) rtpp_memdeb_stats.h rtpp_memdeb_test.c
SRCS_DEBUG=	$(SRCS_MEMDEB_CORE) rtpp_stacktrace.c rtpp_stacktrace.h

rtpproxy_SOURCES=$(BASE_SOURCES) $(SRCS_AUTOGEN)
rtpproxy_debug_SOURCES=$(rtpproxy_SOURCES) $(SRCS_DEBUG)
rtpp_objck_perf_LDADD=-lm -lpthread @LIBS_ELPERIODIC@
rtpp_objck_perf_SOURCES=rtpp_objck.c $(SRCS_AUTOGEN) \
  rtpp_stats.c rtpp_stats.h rtpp_mallocs.c rtpp_mallocs.h \
  rtpp_pearson_perfect.c rtpp_pearson_perfect.h rtpp_pearson.c rtpp_pearson.h \
  rtpp_refcnt.c rtpp_refcnt.h rtpp_time.c rtpp_time.h rtpp_timed.c rtpp_timed.h \
  rtpp_queue.c rtpp_queue.h rtpp_wi.c rtpp_wi.h
rtpp_objck_LDADD=$(rtpp_objck_perf_LDADD) $(RTPP_MEMDEB_LDADD)
rtpp_objck_SOURCES=$(rtpp_objck_perf_SOURCES) $(SRCS_MEMDEB_CORE)

rtpp_rzmalloc_perf_SOURCES = rtpp_rzmalloc_perf.c rtpp_mallocs.c rtpp_mallocs.h \
  rtpp_refcnt.c $(rtpp_refcnt_AUTOSRCS)
rtpp_rzmalloc_perf_CFLAGS = $(EXTRA_CFLAGS)
rtpp_rzmalloc_perf_CPPFLAGS = $(EXTRA_CPPFLAGS)

RTPP_COMMON_CPPFLAGS=-DCFILE_PATH='"$(sysconfdir)/@PACKAGE@.conf"' \
  -DMDDIR_PATH='"$(libdir)/@PACKAGE@"' -I$(UCL_DIR)/include
EXTRA_CFLAGS=-Werror=implicit-function-declaration -Wall

EXTRA_CPPFLAGS = -I$(RTPP_AUTOSRC_DIR)

if BUILD_ELPERIODIC
EXTRA_CPPFLAGS += -I$(top_srcdir)/libelperiodic/src
endif

rtpproxy_debug_CFLAGS=$(EXTRA_CFLAGS) $(RTPP_MEMDEB_CFLAGS)
rtpproxy_debug_CPPFLAGS=$(RTPP_COMMON_CPPFLAGS) $(EXTRA_CPPFLAGS) -DRTPP_DEBUG $(RTPP_MEMDEB_CPPFLAGS) \
  -DMEMDEB_APP=@PACKAGE@ -I$(top_srcdir)

rtpproxy_CFLAGS=$(EXTRA_CFLAGS)
rtpproxy_CPPFLAGS=$(RTPP_COMMON_CPPFLAGS) $(EXTRA_CPPFLAGS)

rtpp_objck_perf_CFLAGS=$(EXTRA_CFLAGS)
rtpp_objck_perf_CPPFLAGS=$(EXTRA_CPPFLAGS)
rtpp_objck_CFLAGS=$(rtpp_objck_perf_CFLAGS) $(RTPP_MEMDEB_CFLAGS)
rtpp_objck_CPPFLAGS=$(rtpp_objck_perf_CPPFLAGS) $(RTPP_MEMDEB_CPPFLAGS) -DMEMDEB_APP=rtpp_objck

DEFS=	-Wall @DEFS@

CLEANFILES= *.gcda *.gcno
#BUILT_SOURCES= $(_SRCS_AUTOGEN)

GENFINCODE= $(top_srcdir)/src/genfincode.sh
GENFINCODE_S= $(top_srcdir)/src/genfincode_stat.sh

rtpp_fintest_SOURCES = rtpp_fintest.c rtpp_mallocs.c rtpp_mallocs.h \
  rtpp_refcnt.c rtpp_refcnt.h rtpp_stacktrace.c rtpp_stacktrace.h \
  $(SRCS_AUTOGEN)
rtpp_fintest_CPPFLAGS = -I$(RTPP_AUTOSRC_DIR) -Drtpp_fintest=main \
  "-DRTPP_AUTOTRAP()=(_naborts++)" -DRTPP_FINTEST -DRTPP_DEBUG \
  -I$(top_srcdir)
rtpp_fintest_LDADD = $(RTPP_MEMDEB_LDADD)

update_autosrc:
	@echo "# Auto-generated by $(srcdir)/Makefile - DO NOT EDIT!" > $(RTPP_AUTOSRC_DIR)/Makefile.ami
	@echo "include \$$(top_srcdir)/m4/autosrc.ami" >> $(RTPP_AUTOSRC_DIR)/Makefile.ami
	@echo "SRCS_AUTOGEN = # To be continued..." >> $(RTPP_AUTOSRC_DIR)/Makefile.ami
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
	  echo "SRCS_AUTOGEN += \$$($${ofile}_AUTOSRCS)" >> $(RTPP_AUTOSRC_DIR)/Makefile.ami; \
	done

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
            SIPATH="$(UCL_DIR)/include:$(top_srcdir)/libelperiodic/src:$(RTPP_AUTOSRC_DIR):$(top_srcdir)" \
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
