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

from datetime import datetime
from twisted.internet import task, reactor
from traceback import print_exc, format_list, extract_stack
from sys import stdout

class Timeout(object):
    _task = None
    _ticks_left = None
    _timeout_callback = None

    def __init__(self, timeout_callback, interval, ticks = 1, *callback_arguments):
        self._timeout_callback = timeout_callback
        if ticks == 1:
            # Special case for just one call
            self._task = reactor.callLater(interval, self._run_once, *callback_arguments)
            self.cancel = self.cancel_callLater
            return
        self._ticks_left = ticks
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

    def _run_once(self, *callback_arguments):
        try:
            self._timeout_callback(*callback_arguments)
        except:
            print datetime.now(), 'Timeout: unhandled exception in timeout callback'
            print '-' * 70
            print_exc(file = stdout)
            print '-' * 70
            stdout.flush()
        self._task = None
        self._timeout_callback = None

    def cancel(self):
        self._task.stop()
        self._task = None
        self._timeout_callback = None

    def cancel_callLater(self):
        self._task.cancel()
        self._task = None
        self._timeout_callback = None

class TimeoutAbs:
    _task = None
    _timeout_callback = None

    def __init__(self, timeout_callback, etime, *callback_arguments):
        etime -= reactor.seconds()
        if etime < 0:
            etime = 0
        self._timeout_callback = timeout_callback
        self._task = reactor.callLater(etime, self._run_once, *callback_arguments)

    def _run_once(self, *callback_arguments):
        try:
            self._timeout_callback(*callback_arguments)
        except:
            print datetime.now(), 'Timeout: unhandled exception in timeout callback'
            print '-' * 70
            print_exc(file = stdout)
            print '-' * 70
            stdout.flush()
        self._task = None
        self._timeout_callback = None

    def cancel(self):
        self._task.cancel()
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
    
    def test1(arguments, testnum):
        print testnum
        arguments['test'] = True
        reactor.crash()

    def test2(arguments, testnum):
        print testnum
        arguments['test'] = 'bar'
        reactor.crash()

    arguments = {'test':False}
    timeout_1 = Timeout(test1, 0, 1, arguments, 'test1')
    reactor.run()
    assert(arguments['test'])
    timeout_1 = Timeout(test1, 0.1, 1, arguments, 'test2')
    timeout_2 = Timeout(test2, 0.2, 1, arguments, 'test3')
    timeout_1.cancel()
    reactor.run()
    assert(arguments['test'] == 'bar')

    arguments = {'test':False}
    timeout_1 = TimeoutAbs(test1, reactor.seconds(), arguments, 'test4')
    reactor.run()
    assert(arguments['test'])

    timeout_1 = TimeoutAbs(test1, reactor.seconds() + 0.1, arguments, 'test5')
    timeout_2 = TimeoutAbs(test2, reactor.seconds() + 0.2, arguments, 'test6')
    timeout_1.cancel()
    reactor.run()
    assert(arguments['test'] == 'bar')
