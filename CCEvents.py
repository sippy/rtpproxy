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

from time import time

class CCEventGeneric(object):
    data = None
    name = None
    rtime = None
    origin = None
    reason = None
    extra_headers = None
    seq = 1

    def __init__(self, data = None, rtime = None, origin = None):
        self.data = data
        if rtime == None:
            self.rtime = time()
        else:
            self.rtime = rtime
        self.seq = CCEventGeneric.seq
        CCEventGeneric.seq += 1
        self.origin = origin

    def getData(self):
        return self.data

    def getCopy(self):
        cself = self.__class__(self.data, self.rtime, self.origin)
        if self.reason != None:
            cself.reason = self.reason.getCopy()
        if self.extra_headers != None:
            cself.extra_headers = tuple([x.getCopy() for x in self.extra_headers])
        return cself

    def __str__(self):
        return self.name

class CCEventTry(CCEventGeneric):
    name = 'CCEventTry'
    pass

class CCEventRing(CCEventGeneric):
    name = 'CCEventRing'
    pass

class CCEventPreConnect(CCEventGeneric):
    name = 'CCEventPreConnect'
    pass

class CCEventConnect(CCEventGeneric):
    name = 'CCEventConnect'
    pass

class CCEventUpdate(CCEventGeneric):
    name = 'CCEventUpdate'
    pass

class CCEventInfo(CCEventGeneric):
    name = 'CCEventInfo'
    pass

class CCEventDisconnect(CCEventGeneric):
    name = 'CCEventDisconnect'
    pass

from SipHeader import SipHeader
from SipWarning import SipWarning

class CCEventFail(CCEventGeneric):
    name = 'CCEventFail'
    challenge = None
    warning = None

    def getCopy(self):
        cself = CCEventGeneric.getCopy(self)
        if self.challenge != None:
            cself.challenge = self.challenge.getCopy()
        return cself

    def setWarning(self, eistr):
        self.warning = SipHeader(body = SipWarning(text = eistr))

class CCEventRedirect(CCEventGeneric):
    name = 'CCEventRedirect'
    pass
