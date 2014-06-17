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
