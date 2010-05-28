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

from SipGenericHF import SipGenericHF

class SipCSeq(SipGenericHF):
    hf_names = ('cseq',)
    cseq = None
    method = None

    def __init__(self, body = None, cseq = None, method = None):
        SipGenericHF.__init__(self, body)
        if body == None:
            self.parsed = True
            self.method = method
            if cseq != None:
                self.cseq = cseq
            else:
                self.cseq = 1

    def parse(self):
        self.parsed = True
        cseq, self.method = self.body.split()
        self.cseq = int(cseq)

    def __str__(self):
        if not self.parsed:
            return self.body
        return str(self.cseq) + ' ' + self.method

    def getCSeq(self):
        return (self.cseq, self.method)

    def getCSeqNum(self):
        return self.cseq

    def getCSeqMethod(self):
        return self.method

    def getCopy(self):
        if not self.parsed:
            return SipCSeq(self.body)
        return SipCSeq(cseq = self.cseq, method = self.method)

    def getCanName(self, name, compact = False):
        return 'CSeq'

    def incCSeqNum(self):
        self.cseq += 1
        return self.cseq
