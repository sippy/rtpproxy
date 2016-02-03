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

from SipConf import SipConf
from time import time
from random import random

class SdpOrigin(object):
    _session_id = int(random() * time() * 1000.0)
    username = None
    session_id = None
    version = None
    network_type = None
    address_type = None
    address = None
    session_id = None

    def __init__(self, body = None, cself = None):
        if body != None:
            self.username, self.session_id, self.version, self.network_type, self.address_type, self.address = body.split()
        elif cself == None:
            self.username = '-'
            self.session_id = SdpOrigin._session_id
            SdpOrigin._session_id += 1
            self.version = self.session_id
            self.network_type = 'IN'
            self.address_type = 'IP4'
            self.address = SipConf.my_address
        else:
            self.username = cself.username
            self.session_id = cself.session_id
            self.version = cself.version
            self.network_type = cself.network_type
            self.address_type = cself.address_type
            self.address = cself.address

    def __str__(self):
        return '%s %s %s %s %s %s' % (self.username, self.session_id, self.version, self.network_type, self.address_type, self.address)

    def localStr(self, local_addr = None, local_port = None):
        if local_addr != None and 'my' in dir(self.address):
            if local_addr.startswith('['):
                address_type = 'IP6'
                local_addr = local_addr[1:-1]
            else:
                address_type = 'IP4'
            return '%s %s %s %s %s %s' % (self.username, self.session_id, self.version, self.network_type, address_type, local_addr)
        return '%s %s %s %s %s %s' % (self.username, self.session_id, self.version, self.network_type, self.address_type, self.address)

    def getCopy(self):
        return self.__class__(cself = self)
