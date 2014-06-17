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
from SipConf import SipConf

class SipWWWAuthenticate(SipGenericHF):
    hf_names = ('www-authenticate',)
    realm = None
    nonce = None

    def __init__(self, body = None, realm = None, nonce = None):
        SipGenericHF.__init__(self, body)
        if body != None:
            return
        self.parsed = True
        if nonce == None:
            ctime = time()
            nonce = md5(str((random() * 1000000000L) + ctime)).hexdigest() + hex(int(ctime))[2:]
        if realm == None:
            realm = SipConf.my_address
        self.realm = realm
        self.nonce = nonce

    def parse(self):
        parts = self.body.split(' ', 1)[1].strip().split('"')
        if len(parts) % 2 != 0 and len(parts[-1]) == 0:
            parts.pop()
        while len(parts) > 0:
            parts1 = [x.strip().split('=', 1) for x in parts.pop(0).strip(' ,=').split(',')]
            if len(parts) > 0:
                parts1[-1].append(parts.pop(0))
            for name, value in parts1:
                if name == 'realm':
                    self.realm = value
                elif name == 'nonce':
                    self.nonce = value
        self.parsed = True

    def __str__(self):
        return self.localStr()

    def localStr(self, local_addr = None, local_port = None):
        if not self.parsed:
            return self.body
        if local_addr != None and 'my' in dir(self.realm):
            return 'Digest realm="%s",nonce="%s"' % (local_addr, self.nonce)
        return 'Digest realm="%s",nonce="%s"' % (self.realm, self.nonce)

    def getCopy(self):
        if not self.parsed:
            return self.__class__(self.body)
        return self.__class__(realm = self.realm, nonce = self.nonce)

    def getCanName(self, name, compact = False):
        return 'WWW-Authenticate'

    def getRealm(self):
        return self.realm

    def getNonce(self):
        return self.nonce
