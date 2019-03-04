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

from time import strftime, gmtime, localtime

import sys
from os.path import dirname, abspath
from inspect import getfile, currentframe
currentdir = dirname(abspath(getfile(currentframe())))
parentdir = dirname(currentdir)
sys.path.insert(0, parentdir)
from sippy.Math.recfilter import recfilter
from sippy.Time.clock_dtime import clock_getdtime, CLOCK_REALTIME, CLOCK_MONOTONIC
sys.path.pop(0)
from threading import local

class MonoGlobals(local):
    realt_flt = None
    monot_max = None

    def __init__(self):
        realt = clock_getdtime(CLOCK_REALTIME)
        self.monot_max = clock_getdtime(CLOCK_MONOTONIC)
        self.realt_flt = recfilter(0.99, realt - self.monot_max)

class MonoTime(object):
    monot = None
    realt = None
    globals = MonoGlobals()

    def __init__(self, s = None, monot = None, realt = None, trust_realt = False):
        if s != None:
            parts = s.split('-', 1)
            self.realt = float(parts[0])
            if len(parts) == 1:
                self.__initFromRealt()
            else:
                self.monot = float(parts[1])
            return
        if monot == None and realt == None:
            if trust_realt:
                raise TypeError('MonoTime.__init__: realt could not be None when trust_realt is set')
            realt = clock_getdtime(CLOCK_REALTIME)
            self.monot = clock_getdtime(CLOCK_MONOTONIC)
            diff_flt = self.globals.realt_flt.apply(realt - self.monot)
            if self.globals.monot_max < self.monot:
                self.globals.monot_max = self.monot
            self.realt = self.monot + diff_flt
            return
        if monot != None:
            self.monot = monot
            if realt != None:
                self.realt = realt
            else:
                self.realt = monot + self.globals.realt_flt.lastval
            return
        self.realt = realt
        self.__initFromRealt(trust_realt)

    def __initFromRealt(self, trust_realt = False):
        self.monot = self.realt - self.globals.realt_flt.lastval
        if not trust_realt and self.monot > self.globals.monot_max:
            monot_now = clock_getdtime(CLOCK_MONOTONIC)
            if monot_now > self.globals.monot_max:
                self.globals.monot_max = monot_now
            self.monot = self.globals.monot_max

    def getdiff(self):
        return (self.realt - self.monot)

    def __str__(self):
        rstr = '%.6f-%.6f' % (self.realt, self.monot)
        return (rstr)

    def ftime(self, base = None):
        if base != None:
            realt = base.realt - (base.monot - self.monot)
        else:
            realt = self.realt
        return strftime('%Y-%m-%d %H:%M:%S+00', gmtime(round(realt)))

    def fptime(self, base = None):
        if base != None:
            realt = base.realt - (base.monot - self.monot)
        else:
            realt = self.realt
        return '%s.%.3d' % (strftime('%d %b %H:%M:%S', localtime(realt)), \
          (realt % 1) * 1000)

    def frtime(self, base = None):
        if base != None:
            realt = base.realt - (base.monot - self.monot)
        else:
            realt = self.realt
        gt = gmtime(realt)
        day = strftime('%d', gt)
        if day[0] == '0':
            day = day[1]
        return strftime('%%H:%%M:%%S.000 GMT %%a %%b %s %%Y' % day, gt)

    def __add__(self, x):
        if isinstance(x, MonoTime):
            return (self.monot + x.monot)
        return (self.monot + x)

    def __sub__(self, x):
        if isinstance(x, MonoTime):
            return (self.monot - x.monot)
        return (self.monot - x)

    def __radd__(self, x):
        if isinstance(x, MonoTime):
            return (self.monot + x.monot)
        return (self.monot + x)

    def __rsub__(self, x):
        if isinstance(x, MonoTime):
            return (x.monot - self.monot)
        return (x - self.monot)

    def __cmp__(self, other):
        if other == None:
            return (1)
        if isinstance(other, int):
            otime = float(other)
        elif isinstance(other, float):
            otime = other
        else:
            otime = other.monot
        return cmp(self.monot, otime)

    def __lt__(self, other):
        return (self.monot < other.monot)

    def __le__(self, other):
        return (self.monot <= other.monot)

    def __eq__(self, other):
        if other == None:
            return (False)
        return (self.monot == other.monot)

    def __ne__(self, other):
        if other == None:
            return (True)
        return (self.monot != other.monot)

    def __gt__(self, other):
        return (self.monot > other.monot)

    def __ge__(self, other):
        return (self.monot >= other.monot)

    def offsetFromNow(self):
        now = clock_getdtime(CLOCK_MONOTONIC)
        return (now - self.monot)

    def getOffsetCopy(self, offst):
        return self.__class__(monot = self.monot + offst, realt = self.realt + offst)

    def offset(self, offst):
        self.monot += offst
        self.realt += offst

    def getCopy(self):
        return self.__class__(monot = self.monot, realt = self.realt)

class selftest(object):
    mg1 = None
    mg2 = None

    def run_t1(self):
        m = MonoTime()
        self.mg1 = m.globals.realt_flt

    def run_t2(self):
        m = MonoTime()
        self.mg2 = m.globals.realt_flt

    def run(self):
        for x in range (0, 100000):
            m1 = MonoTime()
            m2 = MonoTime()
            if x == 0:
                print(m1, m2)
                print(m1.ftime(), m2.ftime())
            #print (m1.getdiff() - m2.getdiff())
        print(m1, m2)
        print(m1 < m2, m1 > m2, m1 == m2, m1 <= m2, m1 >= m2, m1 != m2)
        print(m1.ftime(), m2.ftime())
        ms1 = str(m1)
        ms2 = str(m2)
        m3 = MonoTime(s = ms1)
        m4 = MonoTime(s = ms2)
        print(m3, m4)
        print(m3.ftime(), m4.ftime())
        m5 = MonoTime(realt = m3.realt)
        m6 = MonoTime(monot = m4.monot)
        print(m5.ftime(), m6.ftime())
        print(m5.globals.realt_flt == m1.globals.realt_flt)
        from threading import Thread
        t1 = Thread(target = self.run_t1)
        t2 = Thread(target = self.run_t2)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        print(self.mg1 != self.mg2)

if __name__ == '__main__':
    selftest().run()
