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

from SipGenericHF import SipGenericHF
from SipAddress import SipAddress
from ESipHeaderCSV import ESipHeaderCSV

class SipAddressHF(SipGenericHF):
    address = None
    relaxedparser = False

    def __init__(self, body = None, address = None):
        SipGenericHF.__init__(self, body)
        if body != None:
            csvs = []
            pidx = 0
            while 1:
                idx = body.find(',', pidx)
                if idx == -1:
                    break;
                onum = body[:idx].count('<')
                cnum = body[:idx].count('>')
                qnum = body[:idx].count('"')
                if (onum == 0 and cnum == 0 and qnum == 0) or (onum > 0 and \
                  onum == cnum and (qnum % 2 == 0)):
                    csvs.append(body[:idx])
                    body = body[idx + 1:]
                    pidx = 0
                else:
                    pidx = idx + 1
            if (len(csvs) > 0):
                csvs.append(body)
                raise ESipHeaderCSV(None, csvs)
        else:
            self.parsed = True
            self.address = address

    def parse(self):
        self.address = SipAddress(self.body, relaxedparser = self.relaxedparser)
        self.parsed = True

    def __str__(self):
        return self.localStr()

    def localStr(self, local_addr = None, local_port = None):
        if not self.parsed:
            return self.body
        return self.address.localStr(local_addr, local_port)

    def getCopy(self):
        if not self.parsed:
            oret = self.__class__(self.body)
        else:
            oret = self.__class__(address = self.address.getCopy())
        oret.relaxedparser = self.relaxedparser
        return oret

    def setBody(self, body):
        self.address = body

    def getUri(self):
        return self.address

    def getUrl(self):
        return self.address.url
