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

from __future__ import print_function

#import sys
#sys.path.append('..')

from sippy.Core.EventDispatcher import ED2
from sippy.Time.MonoTime import MonoTime

def Timeout(timeout_cb, ival, nticks = 1, *cb_params):
    el = ED2.regTimer(timeout_cb, ival, nticks, False, *cb_params)
    el.go()
    return el

def TimeoutInact(timeout_cb, ival, nticks = 1, *cb_params):
    return ED2.regTimer(timeout_cb, ival, nticks, False, *cb_params)

def TimeoutAbsMono(timeout_cb, mtime, *cb_params):
    if not isinstance(mtime, MonoTime):
        raise TypeError('mtime is not MonoTime')
    el = ED2.regTimer(timeout_cb, mtime, None, True, *cb_params)
    el.go()
    return el

def testTimeout():
    def test1(arguments, testnum):
        print(testnum)
        arguments['test'] = True
        ED2.breakLoop()

    def test2(arguments, testnum):
        print(testnum)
        arguments['test'] = 'bar'
        ED2.breakLoop()

    arguments = {'test':False}
    timeout_1 = Timeout(test1, 0, 1, arguments, 'test1')
    ED2.loop()
    assert(arguments['test'])
    timeout_1 = Timeout(test1, 0.1, 1, arguments, 'test2')
    timeout_2 = Timeout(test2, 0.2, 1, arguments, 'test3')
    timeout_1.cancel()
    ED2.loop()
    assert(arguments['test'] == 'bar')

    arguments = {'test':False}
    timeout_1 = TimeoutAbsMono(test1, MonoTime(), arguments, 'test4')
    ED2.loop()
    assert(arguments['test'])

    timeout_1 = TimeoutAbsMono(test1, MonoTime().getOffsetCopy(0.1), arguments, 'test5')
    timeout_2 = TimeoutAbsMono(test2, MonoTime().getOffsetCopy(0.2), arguments, 'test6')
    timeout_1.cancel()
    ED2.loop()
    assert(arguments['test'] == 'bar')

def testTimeoutAbsMono():
    def test1(arguments, testnum, mtm):
        arguments['delay'] = mtm.offsetFromNow()
        print(testnum, arguments['delay'])
        arguments['test'] = True
        ED2.breakLoop()

    def test2(arguments, testnum, mtm):
        arguments['delay'] = mtm.offsetFromNow()
        print(testnum, arguments['delay'])
        arguments['test'] = 'bar'
        ED2.breakLoop()

    mt = MonoTime()
    arguments = {'test':False, 'delay':None}
    timeout_1 = TimeoutAbsMono(test1, mt, arguments, 'test1', mt)
    ED2.loop()
    assert(arguments['test'])
    assert(arguments['delay'] < 0.1)
    mt1 = mt.getOffsetCopy(0.1)
    mt2 = mt.getOffsetCopy(0.2)
    arguments = {'test':False, 'delay':None}
    timeout_1 = TimeoutAbsMono(test1, mt1, arguments, 'test2', mt1)
    timeout_2 = TimeoutAbsMono(test2, mt2, arguments, 'test3', mt2)
    timeout_1.cancel()
    ED2.loop()
    assert(arguments['test'] == 'bar')
    assert(arguments['delay'] < 0.1)

if __name__ == '__main__':
    testTimeout()
    testTimeoutAbsMono()
