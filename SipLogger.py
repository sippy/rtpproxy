# Copyright (c) 2003-2005 Maxim Sobolev. All rights reserved.
# Copyright (c) 2006-2007 Sippy Software, Inc. All rights reserved.
#
# This file is part of SIPPY, a free RFC3261 SIP stack and B2BUA.
#
# SIPPY is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# For a license to use the SIPPY software under conditions
# other than those described here, or to purchase support for this
# software, please contact Sippy Software, Inc. by e-mail at the
# following addresses: sales@sippysoft.com.
#
# SIPPY is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

from Signal import Signal
from time import time, localtime, strftime
from fcntl import flock, LOCK_EX, LOCK_UN
from signal import SIGUSR1
from errno import EINTR
import sys, os

SIPLOG_DBUG = 0
SIPLOG_INFO = 1
SIPLOG_WARN = 2
SIPLOG_ERR = 3
SIPLOG_CRIT = 4

class SipLogger(object):
    app = None
    call_id = None
    log = None
    level = None
    flock = lambda x, y, z: None

    def __init__(self, app, call_id = 'GLOBAL', logfile = '/var/log/sip.log'):
        self.app = app
        self.call_id = call_id
        bend = os.environ.get('SIPLOG_BEND', 'stderr').lower()
        if bend == 'stderr':
            self.log = sys.__stderr__
        elif bend == 'none':
            self.write = self.donoting
        else:
            logfile = os.environ.get('SIPLOG_LOGFILE_FILE', logfile)
            self.log = file(logfile, 'a')
            self.flock = flock
            Signal(SIGUSR1, self.reopen, logfile)
        self.level = eval('SIPLOG_' + os.environ.get('SIPLOG_LVL', 'INFO'))

    def donoting(self, *args, **kwargs):
        pass

    def write(self, *args, **kwargs):
        if kwargs.get('level', SIPLOG_INFO) < self.level:
            return
        ltime = kwargs.get('ltime', None)
        if ltime == None:
            ltime = time()
        call_id = kwargs.get('call_id', self.call_id)
        obuf = '%s.%.3d/%s/%s: %s\n' % (strftime('%d %b %H:%M:%S', localtime(ltime)), \
          (ltime % 1) * 1000, call_id, self.app, \
          reduce(lambda x, y: x + y, [str(x) for x in args]))
        try:
            self.flock(self.log, LOCK_EX)
        except IOError, e:
            # Catch ENOTSUP
            if e.args[0] != 45:
                raise e
            self.flock = lambda x, y: None
        try:
            self.log.write(obuf)
        except IOError, e:
            if e.args[0] != EINTR:
                raise e
        self.log.flush()
        self.flock(self.log, LOCK_UN)

    def reopen(self, logfile):
        self.log = file(logfile, 'a')
