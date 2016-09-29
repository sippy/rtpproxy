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
from random import random

class TimeoutInact(object):
    _task = None
    _interval = None
    _ticks_left = None
    _timeout_callback = None
    _timeout_cb_args = None
    _randomize_runs = None

    def __init__(self, timeout_callback, interval, ticks = 1, *callback_arguments):
        #print('TimeoutInact.__init__(%s)' % (str(callback_arguments),))
        self._timeout_callback = timeout_callback
        self._interval = interval
        self._ticks_left = ticks
        self._timeout_cb_args = callback_arguments

    def _get_randomizer(self, p):
        return lambda x: x * (1.0 + p * (1.0 - 2.0 * random()))

    def spread_runs(self, p):
        self._randomize_runs = self._get_randomizer(p)

    def go(self):
        if self._ticks_left == 1 or self._randomize_runs != None:
            # Special case for just one call, we also use it when we need
            # to add some random noise into a schedule so that LoopingCall()
            # is not very convinient
            self._schedule_call_later()
            self.cancel = self.cancel_callLater
            if self._randomize_runs == None:
                self._timeout_cb_args = None
            return
        self._task = task.LoopingCall(self._run, *self._timeout_cb_args)
        self._timeout_cb_args = None
        self._task.start(self._interval, False)

    def _schedule_call_later(self):
        if self._randomize_runs == None:
            ival = self._interval
        else:
            ival = self._randomize_runs(self._interval)
        self._task = reactor.callLater(ival, self._run_once, \
          *self._timeout_cb_args)

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
        if self._ticks_left == 1:
            self._cleanup()
            return
        self._ticks_left -= 1
        self._schedule_call_later()

    def cancel(self):
        self._task.stop()
        self._cleanup()

    def cancel_callLater(self):
        self._task.cancel()
        self._cleanup()

    def _cleanup(self):
        self._task = None
        self._timeout_callback = None
        self._timeout_cb_args = None

class Timeout(TimeoutInact):
    def __init__(self, *args):
        TimeoutInact.__init__(self, *args)
        self.go()

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
