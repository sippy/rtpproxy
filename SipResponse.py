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

class SipResponse(SipMsg):
    scode = None
    reason = None
    sipver = None

    def __init__(self, buf = None, scode = None, reason = None, sipver = None, to = None, fr0m = None, callid = None, vias = None,
                 cseq = None, body = None, rrs = ()):
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
