# Copyright (c) 2003-2005 Maxim Sobolev. All rights reserved.
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

    def __init__(self, buf = None, method = None, ruri = None, sipver = 'SIP/2.0', to = None, fr0m = None, via = None, cseq = None, \
                 callid = None, maxforwards = None, body = None, contact = None, routes = (), target = None, cguid = None):
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
        if method in ('INVITE', 'REGISTER'):
            self.appendHeader(SipHeader(name = 'expires'))
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

    def genResponse(self, scode, reason, body = None):
        # Should be done at the transaction level
        # to = self.getHF('to').getBody().getCopy()
        # if code > 100 and to.getTag() == None:
        #    to.genTag()
        return SipResponse(scode = scode, reason = reason, sipver = self.sipver, fr0m = self.getHFBody('from').getCopy(), \
                           callid = self.getHFBody('call-id').getCopy(), vias = [x.getCopy() for x in self.getHFBodys('via')], \
                           to = self.getHFBody('to').getCopy(), cseq = self.getHFBody('cseq').getCopy(), \
                           rrs = [x.getCopy() for x in self.getHFBodys('record-route')], body = body)

    def genACK(self, to = None):
        if to == None:
            to = self.getHFBody('to').getCopy()
        return SipRequest(method = 'ACK', ruri = self.ruri.getCopy(), sipver = self.sipver, \
                          fr0m = self.getHFBody('from').getCopy(), to = to, \
                          via = self.getHFBody('via').getCopy(), callid = self.getHFBody('call-id').getCopy(), \
                          cseq = self.getHFBody('cseq').getCSeqNum(), maxforwards = self.getHFBody('max-forwards').getCopy())

    def genCANCEL(self):
        return SipRequest(method = 'CANCEL', ruri = self.ruri.getCopy(), sipver = self.sipver, \
                          fr0m = self.getHFBody('from').getCopy(), to = self.getHFBody('to').getCopy(), \
                          via = self.getHFBody('via').getCopy(), callid = self.getHFBody('call-id').getCopy(), \
                          cseq = self.getHFBody('cseq').getCSeqNum(), maxforwards = self.getHFBody('max-forwards').getCopy(), \
                          routes = [x.getCopy() for x in self.getHFBodys('route')], target = self.getTarget())

    def genRequest(self, method, cseq = None):
        if cseq == None:
            cseq = self.getHFBody('cseq').getCSeqNum()
        return SipRequest(method = method, ruri = self.ruri.getCopy(), sipver = self.sipver, \
                          fr0m = self.getHFBody('from').getCopy(), to = self.getHFBody('to').getCopy(), \
                          via = self.getHFBody('via').getCopy(), callid = self.getHFBody('call-id').getCopy(), \
                          cseq = cseq, maxforwards = self.getHFBody('max-forwards').getCopy())
