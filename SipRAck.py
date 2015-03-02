# Copyright (c) 2015 Sippy Software, Inc. All rights reserved.
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

from SipCSeq import SipCSeq

class SipRAck(SipCSeq):
    hf_names = ('rack',)
    rseq = None

    def __init__(self, body = None, rseq = None, cseq = None, method = None):
        if body == None:
            self.rseq = rseq
            SipCSeq.__init__(self, cseq = cseq, method = method)
            return
        SipCSeq.__init__(self, body)

    def parse(self):
        rseq, cseq, self.method = self.body.split(None, 2)
        self.rseq = int(rseq)
        self.cseq = int(cseq)
        self.parsed = True

    def getCopy(self):
        if not self.parsed:
            return SipRAck(self.body)
        return SipRAck(rseq = self.rseq, cseq = self.cseq, method = self.method)

    def getCanName(self, name, compact = False):
        return 'RAck'

    def getRSeq(self):
        cseq, method = SipCSeq.getCSeq(self)
        return (self.rseq, cseq, method)

    def __str__(self):
        if not self.parsed:
            return self.body
        return '%d %d %s' % (self.rseq, self.cseq, self.method)

if __name__ == '__main__':
    ra1 = SipRAck(body = '5 10 INVITE')
    ra1.parse()
    print ra1.rseq, ra1.cseq, ra1.method
    ra1.cseq = 100
    print str(ra1)
