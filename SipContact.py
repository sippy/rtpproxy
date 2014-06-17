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

from SipAddressHF import SipAddressHF
from SipGenericHF import SipGenericHF
from SipConf import SipConf
from SipAddress import SipAddress
from SipURL import SipURL
from ESipHeaderIgnore import ESipHeaderIgnore

class SipContact(SipAddressHF):
    hf_names = ('contact', 'm')
    asterisk = False

    def __init__(self, body = None, address = None):
        if body == '*':
            SipGenericHF.__init__(self, body)
            self.asterisk = True
            return
        SipAddressHF.__init__(self, body, address)
        if body == None and address == None:
            self.address = SipAddress(name = 'Anonymous', url = SipURL(host = SipConf.my_address, port = SipConf.my_port))

    def getCanName(self, name, compact = False):
        if compact:
            return 'm'
        return 'Contact'

    def parse(self):
        if not self.asterisk:
            return SipAddressHF.parse(self)
