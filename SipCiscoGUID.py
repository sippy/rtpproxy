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

from random import random
from hashlib import md5
from time import time
from SipGenericHF import SipGenericHF

class SipCiscoGUID(SipGenericHF):
    hf_names = ('cisco-guid', 'h323-conf-id')
    ciscoGUID = None

    def __init__(self, body = None, ciscoGUID = None):
        SipGenericHF.__init__(self, body)
        if body != None:
            return
        self.parsed = True
        if ciscoGUID != None:
            self.ciscoGUID = ciscoGUID
        else:
            s = md5(str((random() * 1000000000L) + time())).hexdigest()
            self.ciscoGUID = (long(s[0:8], 16), long(s[8:16], 16), long(s[16:24], 16), long(s[24:32], 16))

    def parse(self):
        self.ciscoGUID = tuple([int(x) for x in  self.body.split('-', 3)])
        self.parsed = True

    def __str__(self):
        if not self.parsed:
            return self.body
        return '%d-%d-%d-%d' % self.ciscoGUID

    def getCiscoGUID(self):
        return self.ciscoGUID

    def hexForm(self):
        return '%.8X %.8X %.8X %.8X' % self.ciscoGUID

    def getCanName(self, name, compact = False):
        if name.lower() == 'h323-conf-id':
            return 'h323-conf-id'
        else:
            return 'cisco-GUID'

    def getCopy(self):
        if not self.parsed:
            return SipCiscoGUID(self.body)
        return SipCiscoGUID(ciscoGUID = self.ciscoGUID)
