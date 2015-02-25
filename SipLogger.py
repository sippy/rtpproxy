# Copyright (c) 2003-2005 Maxim Sobolev. All rights reserved.
# Copyright (c) 2006-2014 Sippy Software, Inc. All rights reserved.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation and/or
# other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from Signal import LogSignal
from time import time, localtime, strftime
from fcntl import flock, LOCK_EX, LOCK_UN
from signal import SIGUSR1
from threading import Thread, Condition
import sys, os, syslog

SIPLOG_DBUG = 0
SIPLOG_INFO = 1
SIPLOG_WARN = 2
SIPLOG_ERR = 3
SIPLOG_CRIT = 4

class AsyncLogger(Thread):
    log = None
    app = None
    master = None

    def __init__(self, app, master):
        Thread.__init__(self)
        self.master = master
        self.app = app
        self.setDaemon(True)
        self.start()

    def run(self):
        self.safe_open()
        while True:
            self.master.wi_available.acquire()
            while len(self.master.wi) == 0:
                self.master.wi_available.wait()
            op, args, kwargs = self.master.wi.pop(0)
            self.master.wi_available.release()
            if op == 'reopen':
                self.safe_open()
                continue
            if op == 'shutdown':
                self.closelog()
                return
            try:
                self.do_write(self.master.format(args, kwargs))
            except:
                # Reopen on any errror, drop message and continue
                self.safe_open()

    def do_write(self, obuf):
        my_flock = flock
        try:
            my_flock(self.log, LOCK_EX)
        except IOError, e:
            # Catch ENOTSUP
            if e.args[0] != 45:
                raise e
            my_flock = lambda x, y: None
        try:
            self.log.write(obuf)
            self.log.flush()
        except:
            pass
        my_flock(self.log, LOCK_UN)

    def safe_open(self):
        try:
            self.log = file(self.master.logfile, 'a')
        except Exception, e:
            print e

    def shutdown(self):
        self.master.wi_available.acquire()
        self.master.wi.append(('shutdown', None, None))
        self.master.wi_available.notify()
        self.master.wi_available.release()
        self.join()
        self.master = None

    def closelog(self):
        del self.log

class AsyncLoggerSyslog(AsyncLogger):
    def safe_open(self):
        try:
            syslog.openlog(self.app, syslog.LOG_PID)
        except Exception, e:
            print e

    def do_write(self, obuf):
        try:
            syslog.syslog(syslog.LOG_NOTICE, obuf)
        except Exception, e:
            print e
            pass

    def closelog(self):
        syslog.closelog()

class SipLogger(object):
    app = None
    call_id = None
    level = None
    write = None
    logfile = None
    discarded = 0
    pid = None
    logger = None
    signal_handler = None
    itime = None
    offstime = False

    def __init__(self, app, call_id = 'GLOBAL', logfile = '/var/log/sip.log'):
        self.itime = time()
        self.app = '/%s' % app
        self.call_id = call_id
        bend = os.environ.get('SIPLOG_BEND', 'stderr').lower()
        tform = os.environ.get('SIPLOG_TFORM', 'abs').lower()
        if tform == 'rel':
            self.offstime = True
            itime = os.environ.get('SIPLOG_TSTART', self.itime)
            self.itime = float(itime)
        if bend == 'stderr':
            self.write = self.write_stderr
        elif bend == 'none':
            self.write = self.donoting
        else:
            self.write = self.write_logfile
            self.wi_available = Condition()
            self.wi = []
            if bend != 'syslog':
                self.logger = AsyncLogger(app, self)
                self.logfile = os.environ.get('SIPLOG_LOGFILE_FILE', logfile)
                self.signal_handler = LogSignal(self, SIGUSR1, self.reopen)
            else:
                self.logger = AsyncLoggerSyslog(app, self)
                self.app = ''
        self.level = eval('SIPLOG_' + os.environ.get('SIPLOG_LVL', 'INFO'))

    def ftime(self, ltime):
        if self.offstime:
            ltime -= self.itime
        msec = (ltime % 1) * 1000
        if not self.offstime:
            return '%s.%.3d' % (strftime('%d %b %H:%M:%S', localtime(ltime)), msec)
        hrs = int(ltime / (60 * 60))
        ltime -= (hrs * 60 * 60)
        mins = int(ltime / 60)
        ltime -= (mins * 60)
        secs = int(ltime)
        return '%.2d:%.2d:%.2d.%.3d' % (hrs, mins, secs, msec)

    def donoting(self, *args, **kwargs):
        pass

    def write_stderr(self, *args, **kwargs):
        if kwargs.get('level', SIPLOG_INFO) < self.level:
            return
        sys.__stderr__.write(self.format(args, kwargs))

    def write_logfile(self, *args, **kwargs):
        if kwargs.get('level', SIPLOG_INFO) < self.level:
            return
        discarded = False
        self.wi_available.acquire()
        if len(self.wi) > 1000:
            # Discard some items, as the writer doesn't seems to be able
            # to keep up pace with incoming requests
            self.discarded += len(self.wi) - 1000
            self.wi = self.wi[-1000:]
            discarded = True
        self.wi.append(('write', args, kwargs))
        self.wi_available.notify()
        self.wi_available.release()
        if discarded and self.discarded % 1000 == 0:
            print 'SipLogger: discarded %d requests, I/O too slow' % self.discarded

    def format(self, args, kwargs):
        ltime = kwargs.get('ltime', None)
        if ltime == None:
            ltime = time()
        call_id = kwargs.get('call_id', self.call_id)
        if self.pid != None:
            pid = '[%d]' % self.pid
        else:
            pid = ''
        return '%s/%s%s%s: %s\n' % (self.ftime(ltime), \
          call_id, self.app, pid, \
          reduce(lambda x, y: x + y, [str(x) for x in args]))

    def reopen(self, signum = None):
        self.wi_available.acquire()
        self.wi.append(('reopen', None, None))
        self.wi_available.notify()
        self.wi_available.release()

    def shutdown(self):
        if self.logger == None:
            return
        if self.signal_handler != None:
            self.signal_handler.cancel()
            self.signal_handler = None
        self.logger.shutdown()
        self.logger = None
