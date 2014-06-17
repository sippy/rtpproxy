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
        cseq, self.method = self.body.split()
        self.cseq = int(cseq)
        self.parsed = True

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
