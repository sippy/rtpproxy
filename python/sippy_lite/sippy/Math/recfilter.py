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

from threading import local
from math import exp, pi

def calc_f_coef(Fs, Fc):
    if Fs < Fc * 2.0:
        raise ValueError('The cutoff frequency (%f) should be less ' \
          'than half of the sampling rate (%f)' %  (Fc, Fs))
    return exp(-2.0 * pi * Fc / Fs)

class recfilter(object):
    lastval = 0.0
    a = None
    b = None

    def __init__(self, fcoef, initval):
        #print 'recfilter::init()'
        self.lastval = float(initval)
        self.a = 1.0 - float(fcoef)
        self.b = float(fcoef)

    def apply(self, x):
        self.lastval = self.a * float(x) + self.b * self.lastval
        return self.lastval

class recfilter_ts(local, recfilter):
    def __init__(self, *args):
        #print 'recfilter_ts::init()'
        recfilter.__init__(self, *args)
