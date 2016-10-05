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

class TimeoutAbsMono:
    _task = None
    _timeout_callback = None

    def __init__(self, timeout_callback, etime, *callback_arguments):
        etime = -etime.offsetFromNow()
        if etime < 0:
            etime = 0
        self._timeout_callback = timeout_callback
        self._task = reactor.callLater(etime, self._run_once, *callback_arguments)

    def _run_once(self, *callback_arguments):
        try:
            self._timeout_callback(*callback_arguments)
        except:
            print datetime.now(), 'TimeoutAbsMono: unhandled exception in timeout callback'
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

if __name__ == '__main__':
    from twisted.internet import reactor
    from sippy.Time.MonoTime import MonoTime
    
    def test1(arguments, testnum, mtm):
        arguments['delay'] = mtm.offsetFromNow()
        print testnum, arguments['delay']
        arguments['test'] = True
        reactor.crash()

    def test2(arguments, testnum, mtm):
        arguments['delay'] = mtm.offsetFromNow()
        print testnum, arguments['delay']
        arguments['test'] = 'bar'
        reactor.crash()

    mt = MonoTime()
    arguments = {'test':False, 'delay':None}
    timeout_1 = TimeoutAbsMono(test1, mt, arguments, 'test1', mt)
    reactor.run()
    assert(arguments['test'])
    assert(arguments['delay'] < 0.1)
    mt1 = mt.getOffsetCopy(0.1)
    mt2 = mt.getOffsetCopy(0.2)
    arguments = {'test':False, 'delay':None}
    timeout_1 = TimeoutAbsMono(test1, mt1, arguments, 'test2', mt1)
    timeout_2 = TimeoutAbsMono(test2, mt2, arguments, 'test3', mt2)
    timeout_1.cancel()
    reactor.run()
    assert(arguments['test'] == 'bar')
    assert(arguments['delay'] < 0.1)
