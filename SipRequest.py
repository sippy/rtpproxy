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
from SipCSeq import SipCSeq
from SipTo import SipTo
from SipResponse import SipResponse
from SipURL import SipURL
from SipAddress import SipAddress
from SipExpires import SipExpires

class SipRequest(SipMsg):
    method = None
    ruri = None
    sipver = None
    user_agent = None

    def __init__(self, buf = None, method = None, ruri = None, sipver = 'SIP/2.0', to = None, fr0m = None, via = None, cseq = None, \
                 callid = None, maxforwards = None, body = None, contact = None, routes = (), target = None, cguid = None,
                 user_agent = None, expires = None):
        SipMsg.__init__(self, buf)
        if buf != None:
            return
        self.method = method
        self.ruri = ruri
        if target == None:
            if len(routes) == 0:
                self.setTarget(self.ruri.getAddr())
            else:
                self.setTarget(routes[0].getAddr())
        else:
            self.setTarget(target)
        self.sipver = sipver
        self.appendHeader(SipHeader(name = 'via', body = via))
        if via == None:
            self.getHFBody('via').genBranch()
        self.appendHeaders([SipHeader(name = 'route', body = x) for x in routes])
        self.appendHeader(SipHeader(name = 'max-forwards', body = maxforwards))
        self.appendHeader(SipHeader(name = 'from', body = fr0m))
        if to == None:
            to = SipTo(address = SipAddress(url = ruri))
        self.appendHeader(SipHeader(name = 'to', body = to))
        self.appendHeader(SipHeader(name = 'call-id', body = callid))
        self.appendHeader(SipHeader(name = 'cseq', body = SipCSeq(cseq = cseq, method = method)))
        if contact != None:
            self.appendHeader(SipHeader(name = 'contact', body = contact))
        if expires == None and method == 'INVITE':
            expires = SipHeader(name = 'expires')
            self.appendHeader(expires)
        elif expires != None:
            expires = SipHeader(name = 'expires', body = expires)
            self.appendHeader(expires)
        if user_agent != None:
            self.user_agent = user_agent
            self.appendHeader(SipHeader(name = 'user-agent', bodys = user_agent))
        else:
            self.appendHeader(SipHeader(name = 'user-agent'))
        if cguid != None:
            self.appendHeader(SipHeader(name = 'cisco-guid', body = cguid))
            self.appendHeader(SipHeader(name = 'h323-conf-id', body = cguid))
        if body != None:
            self.setBody(body)

    def setSL(self, startline):
        self.method, ruri, self.sipver = startline.split()
        self.ruri = SipURL(ruri)

    def getSL(self):
        return self.method + ' ' + str(self.ruri) + ' ' + self.sipver

    def getMethod(self):
        return self.method

    def getRURI(self):
        return self.ruri

    def setRURI(self, ruri):
        self.ruri = ruri

    def genResponse(self, scode, reason, body = None, server = None):
        # Should be done at the transaction level
        # to = self.getHF('to').getBody().getCopy()
        # if code > 100 and to.getTag() == None:
        #    to.genTag()
        return SipResponse(scode = scode, reason = reason, sipver = self.sipver, fr0m = self.getHFBCopy('from'), \
                           callid = self.getHFBCopy('call-id'), vias = self.getHFBCopys('via'), \
                           to = self.getHFBCopy('to'), cseq = self.getHFBCopy('cseq'), \
                           rrs = self.getHFBCopys('record-route'), body = body, \
                           server = server)

    def genACK(self, to = None):
        if to == None:
            to = self.getHFBody('to').getCopy()
        maxforwards = self.getHFBodys('max-forwards')
        if len(maxforwards) > 0:
            maxforward = maxforwards[0].getCopy()
        else:
            maxforward = None
        return SipRequest(method = 'ACK', ruri = self.ruri.getCopy(), sipver = self.sipver, \
                          fr0m = self.getHFBCopy('from'), to = to, \
                          via = self.getHFBCopy('via'), callid = self.getHFBCopy('call-id'), \
                          cseq = self.getHFBody('cseq').getCSeqNum(), maxforwards = maxforward, \
                          user_agent = self.user_agent)

    def genCANCEL(self):
        maxforwards = self.getHFBodys('max-forwards')
        if len(maxforwards) > 0:
            maxforward = maxforwards[0].getCopy()
        else:
            maxforward = None
        return SipRequest(method = 'CANCEL', ruri = self.ruri.getCopy(), sipver = self.sipver, \
                          fr0m = self.getHFBCopy('from'), to = self.getHFBCopy('to'), \
                          via = self.getHFBCopy('via'), callid = self.getHFBCopy('call-id'), \
                          cseq = self.getHFBody('cseq').getCSeqNum(), maxforwards = maxforward, \
                          routes = self.getHFBCopys('route'), target = self.getTarget(), \
                          user_agent = self.user_agent)

    def genRequest(self, method, cseq = None):
        if cseq == None:
            cseq = self.getHFBody('cseq').getCSeqNum()
        maxforwards = self.getHFBodys('max-forwards')
        if len(maxforwards) > 0:
            maxforward = maxforwards[0].getCopy()
        else:
            maxforward = None
        expires = self.getHFBodys('expires')
        if len(expires) > 0:
            expires = expires[0].getCopy()
        else:
            expires = None
        return SipRequest(method = method, ruri = self.ruri.getCopy(), sipver = self.sipver, \
                          fr0m = self.getHFBCopy('from'), to = self.getHFBCopy('to'), \
                          via = self.getHFBCopy('via'), callid = self.getHFBCopy('call-id'), \
                          cseq = cseq, maxforwards = maxforward, \
                          user_agent = self.user_agent, expires = expires)
