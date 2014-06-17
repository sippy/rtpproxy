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

from SipURL import SipURL
from string import maketrans

def findquotes(s, pos = 1):
    rval = []
    while True:
        pos1 = s.find('"', pos)
        if pos1 == -1:
            break
        pos = pos1 + 1
        if pos1 == 0 or s[pos1 - 1] != '\\':
            rval.append(pos1)
    return rval

class SipAddress(object):
    name = None
    url = None
    params = None
    params_order = None
    hadbrace = None
    transtable = maketrans('-.!%*_+`\'~', 'a' * 10)

    def __init__(self, address = None, name = None, url = None, params = None,
      hadbrace = None, params_order = None, relaxedparser = False):
        self.params = {}
        self.params_order = []
        self.hadbrace = True
        if address == None:
            self.name = name
            self.url = url
            if params != None:
                self.params = params
            if params_order != None:
                self.params_order = params_order
            if hadbrace != None:
                self.hadbrace = hadbrace
            return
        # simple 'sip:foo' case
        if address.lower().startswith('sip:') and address.find('<') == -1:
            parts = address.split(';', 1)
            self.url = SipURL(parts[0], relaxedparser = relaxedparser)
            if len(parts) == 2:
                for l in parts[1].split(';'):
                    if not l:
                        continue
                    k_v = l.split('=', 1)
                    if len(k_v) == 2:
                        k, v = k_v
                    else:
                        k = k_v[0]
                        v = None
                    self.params[k] = v
                    if self.params_order.count(k) > 0:
                        self.params_order.remove(k)
                    self.params_order.append(k)
            self.hadbrace = False
            return
        if address.startswith('"'):
            qpos = findquotes(address)
            url = None
            if len(qpos) == 1:
                self.name = address[1:qpos[0]]
                url = address[qpos[0] + 1:].strip()
            else:
                for i in range(1, len(qpos)):
                    if address.find('<', 1, qpos[i]) != -1:
                        self.name = address[1:qpos[i - 1]]
                        url = address[qpos[i - 1] + 1:].strip()
                        break
                else:
                    self.name = address[1:qpos[i]]
                    url = address[qpos[i] + 1:].strip()
            if url == None:
                raise ValueError('Cannot separate name from URI: %s' % address)
            if url.startswith('<'):
                url = url[1:]
        else:
            self.name, url = address.split('<', 1)
            self.name = self.name.strip()
        url, paramstring = url.split('>', 1)
        self.url = SipURL(url, relaxedparser = relaxedparser)
        paramstring = paramstring.strip()
        if paramstring:
            for l in paramstring.split(';'):
                if not l:
                    continue
                k_v = l.split('=', 1)
                if len(k_v) == 2:
                    k, v = k_v
                else:
                    k = k_v[0]
                    v = None
                self.params[k] = v
                if self.params_order.count(k) > 0:
                    self.params_order.remove(k)
                self.params_order.append(k)

    def __str__(self):
        return self.localStr()

    def localStr(self, local_addr = None, local_port = None):
        if self.hadbrace:
            od = '<'
            cd = '>'
        else:
            od = ''
            cd = ''
        s = ''
        if self.name != None and len(self.name) > 0:
            if not self.name.translate(self.transtable).isalnum():
                s += '"%s" ' % self.name
            else:
                s += self.name + ' '
            od = '<'
            cd = '>'
        s += od + self.url.localStr(local_addr, local_port) + cd
        for k in self.params_order:
            v = self.params[k]
            if v != None:
                s += ';' + k + '=' + v
            else:
                s += ';' + k
        return s

    def getCopy(self):
        return SipAddress(name = self.name, url = self.url.getCopy(), params = self.params.copy(), \
          hadbrace = self.hadbrace, params_order = self.params_order[:])

    def getParam(self, name):
        return self.params.get(name, None)

    def setParam(self, name, value = None):
        self.params[name] = value
        if self.params_order.count(name) == 0:
            self.params_order.append(name)

    def delParam(self, name):
        del self.params[name]
        self.params_order.remove(name)
