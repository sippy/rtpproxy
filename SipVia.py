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
from ESipHeaderCSV import ESipHeaderCSV

class SipVia(SipGenericHF):
    hf_names = ('via', 'v')

    sipver = None
    hostname = None
    port = None
    params = None

    def __init__(self, body = None, sipver = None, hostname = None, port = None, params = None):
        if body != None and body.find(',') > -1:
            raise ESipHeaderCSV(None, body.split(','))
        SipGenericHF.__init__(self, body)
        if body == None:
            self.parsed = True
            self.params = {}
            if sipver == None:
                self.sipver = 'SIP/2.0/UDP'
            else:
                self.sipver = sipver
            if hostname == None:
                self.hostname = SipConf.my_address
                self.port = SipConf.my_port
                self.params['rport'] = None
            else:
                self.hostname = hostname
                self.port = port
            if params != None:
                self.params = params

    def parse(self):
        self.params = {}
        self.sipver, hostname = self.body.split(None, 1)
        hcomps = [x.strip() for x in hostname.split(';')]
        for param in hcomps[1:]:
            sparam = param.split('=', 1)
            if len(sparam) == 1:
                val = None
            else:
                val = sparam[1]
            self.params[sparam[0]] = val
        if hcomps[0].startswith('['):
            hcomps = hcomps[0].split(']', 1)
            self.hostname = hcomps[0] + ']'
            hcomps = hcomps[1].split(':', 1)
        else:
            hcomps = hcomps[0].split(':', 1)
            self.hostname = hcomps[0]
        if len(hcomps) == 2:
            try:
                self.port = int(hcomps[1])
            except Exception, e:
                # XXX: some bad-ass devices send us port number twice
                # While not allowed by the RFC, deal with it
                portparts = hcomps[1].split(':', 1)
                if len(portparts) != 2 or portparts[0] != portparts[1]:
                    raise e
                self.port = int(portparts[0])
        else:
            self.port = None
        self.parsed = True

    def __str__(self):
        return self.localStr()

    def localStr(self, local_addr = None, local_port = None):
        if not self.parsed:
            return self.body
        if local_addr != None and 'my' in dir(self.hostname):
            s = self.sipver + ' ' + local_addr
        else:
            s = self.sipver + ' ' + str(self.hostname)
        if self.port != None:
            if local_port != None and 'my' in dir(self.port):
                s += ':' + str(local_port)
            else:
                s += ':' + str(self.port)
        for key, val in self.params.items():
            s += ';' + key
            if val != None:
                s += '=' + val
        return s

    def getCopy(self):
        if not self.parsed:
            return SipVia(self.body)
        return SipVia(sipver = self.sipver, hostname = self.hostname, port = self.port, params = self.params.copy())

    def genBranch(self):
        self.params['branch'] = 'z9hG4bK' + md5(str((random() * 1000000000L) + time())).hexdigest()

    def getBranch(self):
        return self.params.get('branch', None)

    def setParam(self, name, value = None):
        self.params[name] = value

    def getAddr(self):
        if self.port == '':
            return (self.hostname, SipConf.default_port)
        else:
            return (self.hostname, self.port)

    def getTAddr(self):
        rport = self.params.get('rport', None)
        if rport != None:
            rport = int(rport)
            if rport <= 0:
                rport = None
        if rport == None:
            rport = self.getAddr()[1]
            if rport == None:
                rport = SipConf.default_port
        return (self.params.get('received', self.getAddr()[0]), rport)

    def getCanName(self, name, compact = False):
        if compact:
            return 'v'
        return 'Via'

def _unit_test():
    via1 = 'SIP/2.0/UDP 203.193.xx.xx;branch=z9hG4bK2dd1.1102f3e2.0'
    v = SipVia(via1)
    v.parse()
    if via1 != str(v):
        return (False, 1)
    if v.getTAddr() != ('203.193.xx.xx', 5060):
        return (False, 2)
    return (True, None)
