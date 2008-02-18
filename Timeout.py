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
#
# $Id: Timeout.py,v 1.3 2008/02/18 19:49:45 sobomax Exp $

from datetime import datetime
from twisted.internet import task
from traceback import print_exc, format_list, extract_stack
from sys import stdout

class Timeout:
    _task = None
    _ticks_left = None
    _timeout_callback = None

    def __init__(self, timeout_callback, interval, ticks = 1, *callback_arguments):
        self._ticks_left = ticks
        self._timeout_callback = timeout_callback
        self._task = task.LoopingCall(self._run, *callback_arguments)
        self._task.start(interval, False)

    def _run(self, *callback_arguments):
        try:
            self._timeout_callback(*callback_arguments)
        except:
            print datetime.now(), 'Timeout: unhandled exception in timeout callback'
            print '-' * 70
            print_exc(file = stdout)
            print '-' * 70
            stdout.flush()
        if self._ticks_left == 1:
            self.cancel()
        elif self._ticks_left != -1:
            self._ticks_left -= 1

    def cancel(self):
        self._task.stop()
        self._task = None
        self._timeout_callback = None

class Timeout_debug(Timeout):
    _traceback = None

    def __init__(self, *parameters, **kparameters):
        self._traceback = format_list(extract_stack())
        Timeout.__init__(self, *parameters, **kparameters)

    def cancel(self):
        if self._task == None:
            print self._traceback
        Timeout.cancel(self)

if __name__ == '__main__':
    from twisted.internet import reactor
    
    def test1(arguments):
        print 'test1'
        arguments['test'] = True
        reactor.crash()

    def test2(arguments):
        print 'test2'
        arguments['test'] = 'bar'
        reactor.crash()

    arguments = {'test':False}
    timeout_1 = Timeout(test1, 0, 1, arguments)
    reactor.run()
    assert(arguments['test'])
    timeout_1 = Timeout(test1, 0.1, 1, arguments)
    timeout_2 = Timeout(test2, 0.2, 1, arguments)
    timeout_1.cancel()
    reactor.run()
    assert(arguments['test'] == 'bar')
