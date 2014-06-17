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

from SipMsg import SipMsg
from SipHeader import SipHeader

class SipResponse(SipMsg):
    scode = None
    reason = None
    sipver = None

    def __init__(self, buf = None, scode = None, reason = None, sipver = None, to = None, fr0m = None, callid = None, vias = None,
                 cseq = None, body = None, rrs = (), server = None):
        SipMsg.__init__(self, buf)
        if buf != None:
            return
        self.scode, self.reason, self.sipver = scode, reason, sipver
        self.appendHeaders([SipHeader(name = 'via', body = x) for x in vias])
        self.appendHeaders([SipHeader(name = 'record-route', body = x) for x in rrs])
        self.appendHeader(SipHeader(name = 'from', body = fr0m))
        self.appendHeader(SipHeader(name = 'to', body = to))
        self.appendHeader(SipHeader(name = 'call-id', body = callid))
        self.appendHeader(SipHeader(name = 'cseq', body = cseq))
        if server != None:
            self.appendHeader(SipHeader(name = 'server', bodys = server))
        else:
            self.appendHeader(SipHeader(name = 'server'))
        if body != None:
            self.setBody(body)

    def setSL(self, startline):
        sstartline = startline.split(None, 2)
        if len(sstartline) == 2:
            # Some brain-damaged UAs don't include reason in some cases
            self.sipver, scode = sstartline
            self.reason = 'Unspecified'
        else:
            self.sipver, scode, self.reason = startline.split(None, 2)
        self.scode = int(scode)
        if self.scode == 100 or self.scode >= 400:
            self.ignorebody = True

    def setSCode(self, scode, reason):
        self.scode = scode
        self.reason = reason

    def getSL(self):
        return self.sipver + ' ' + str(self.scode) + ' ' + self.reason

    def getSCode(self):
        return (self.scode, self.reason)
