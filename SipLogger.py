# Copyright (c) 2003-2005 Maxim Sobolev. All rights reserved.
# Copyright (c) 2006 Sippy Software, Inc. All rights reserved.
#
# Warning: This computer program is protected by copyright law and
# international treaties. Unauthorized reproduction or distribution of this
# program, or any portion of it, may result in severe civil and criminal
# penalties, and will be prosecuted under the maximum extent possible under
# law.

from Signal import Signal
from time import time, localtime, strftime
from fcntl import flock, LOCK_EX, LOCK_UN
from signal import SIGUSR1
from threading import Thread, Condition
import sys, os

SIPLOG_DBUG = 0
SIPLOG_INFO = 1
SIPLOG_WARN = 2
SIPLOG_ERR = 3
SIPLOG_CRIT = 4

class AsyncLogger(Thread):
    log = None
    master = None

    def __init__(self, master):
        Thread.__init__(self)
        self.master = master
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
        my_flock(self.master.log, LOCK_UN)

    def safe_open(self):
        try:
            self.log = file(self.master.logfile, 'a')
        except Exception, e:
            print e

class SipLogger(object):
    app = None
    call_id = None
    level = None
    write = None
    logfile = None
    discarded = 0
    pid = None

    def __init__(self, app, call_id = 'GLOBAL', logfile = '/var/log/sip.log'):
        self.app = app
        self.call_id = call_id
        bend = os.environ.get('SIPLOG_BEND', 'stderr').lower()
        if bend == 'stderr':
            self.write = self.write_stderr
        elif bend == 'none':
            self.write = self.donoting
        else:
            self.wi_available = Condition()
            self.wi = []
            AsyncLogger(self)
            self.write = self.write_logfile
            self.logfile = os.environ.get('SIPLOG_LOGFILE_FILE', logfile)
            Signal(SIGUSR1, self.reopen)
        self.level = eval('SIPLOG_' + os.environ.get('SIPLOG_LVL', 'INFO'))
        self.pid = os.getpid()

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
            self.discarded += 1000 - len(self.wi)
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
        return '%s.%.3d/%s/%s[%d]: %s\n' % (strftime('%d %b %H:%M:%S', localtime(ltime)), \
          (ltime % 1) * 1000, call_id, self.app, self.pid, \
          reduce(lambda x, y: x + y, [str(x) for x in args]))

    def reopen(self):
        self.wi_available.acquire()
        self.wi.append(('reopen', None, None))
        self.wi_available.notify()
        self.wi_available.release()
