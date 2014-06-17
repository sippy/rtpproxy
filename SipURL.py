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
from urllib import quote, unquote

class SipURL(object):
    username = None
    userparams = None
    password = None
    host = None
    port = None
    headers = None
    usertype = None
    transport = None
    ttl = None
    maddr = None
    method = None
    tag = None
    other = None
    lr = False

    def __init__(self, url = None, username = None, password = None, host = None, port = None, headers = None, \
      usertype = None, transport = None, ttl = None, maddr = None, method = None, tag = None, other = None, \
      userparams = None, lr = False, relaxedparser = False):
        self.other = []
        self.userparams = []
        if url == None:
            self.username = username
            if userparams != None:
                self.userparams = userparams
            self.password = password
            if host == None:
                self.host = SipConf.my_address
                self.port = SipConf.my_port
            else:
                self.host = host
                self.port = port
            self.headers = headers
            self.usertype = usertype
            self.transport = transport
            self.ttl = ttl
            self.maddr = maddr
            self.method = method
            self.tag = tag
            if other != None:
                self.other = other
            self.lr = lr
            return
        sidx = url.find(':')
        if sidx == 3 or (sidx != -1 and sidx < url.find('.')):
            if not url.lower().startswith('sip:'):
                raise ValueError('unsupported scheme: ' + url[:4])
            url = url[4:]
        # else:
        #     scheme is missing, assume sip:
        ear = url.find('@') + 1
        parts = url[ear:].split(';')
        userdomain, params = url[0:ear] + parts[0], parts[1:]
        if len(params) == 0 and '?' in userdomain:
            self.headers = {}
            userdomain, headers = userdomain.split('?', 1)
            for header in headers.split('&'):
                k, v = header.split('=')
                self.headers[k.lower()] = unquote(v)
        udparts = userdomain.split('@', 1)
        if len(udparts) == 2:
            userpass, hostport = udparts
            upparts = userpass.split(':', 1)
            if len(upparts) > 1:
                self.password = upparts[1]
            uparts = upparts[0].split(';')
            if len(uparts) > 1:
                self.userparams = uparts[1:]
            self.username = unquote(uparts[0])
        else:
            hostport = udparts[0]
        if relaxedparser and len(hostport) == 0:
            self.host = ''
        elif hostport[0] == '[':
            # IPv6 host
            hpparts = hostport.split(']', 1)
            self.host = hpparts[0] + ']'
            if len(hpparts[1]) > 0:
                hpparts = hpparts[1].split(':', 1)
                if len(hpparts) > 1:
                    self.port = int(hpparts[1])
        else:
            # IPv4 host
            hpparts = hostport.split(':', 1)
            if len(hpparts) == 1:
                self.host = hpparts[0]
            else:
                self.host = hpparts[0]
                try:
                    self.port = int(hpparts[1])
                except Exception, e:
                    # XXX: some bad-ass devices send us port number twice
                    # While not allowed by the RFC, deal with it
                    portparts = hpparts[1].split(':', 1)
                    if len(portparts) != 2 or portparts[0] != portparts[1]:
                        raise e
                    self.port = int(portparts[0])
        for p in params:
            if p == params[-1] and '?' in p:
                self.headers = {}
                p, headers = p.split('?', 1)
                for header in headers.split('&'):
                    k, v = header.split('=')
                    self.headers[k.lower()] = unquote(v)
            nv = p.split('=', 1)
            if len(nv) == 1:
                if p == 'lr':
                    self.lr = True
                else:
                    self.other.append(p)
                continue
            name, value = nv
            if name == 'user':
                self.usertype = value
            elif name == 'transport':
                self.transport = value
            elif name == 'ttl':
                self.ttl = int(value)
            elif name == 'maddr':
                self.maddr = value
            elif name == 'method':
                self.method = value
            elif name == 'tag':
                self.tag = value
            elif name == 'lr':
                # RFC 3261 doesn't allow lr parameter to have a value,
                # but many stupid implementation do it anyway
                self.lr = True
            else:
                self.other.append(p)

    def __str__(self):
        return self.localStr()

    def localStr(self, local_addr = None, local_port = None):
        l = []; w = l.append
        w('sip:')
        if self.username != None:
            w(self.username)
            for v in self.userparams:
                w(';%s' % v)
            if self.password != None:
                w(':%s' % self.password)
            w('@')
        if local_addr != None and 'my' in dir(self.host):
            w(local_addr)
        else:
            w(str(self.host))
        if self.port != None:
            if local_port != None and 'my' in dir(self.port):
                w(':%d' % local_port)
            else:
                w(':%d' % self.port)
        if self.usertype != None:
            w(';user=%s' % self.usertype)
        for n in ('transport', 'ttl', 'maddr', 'method', 'tag'):
            v = getattr(self, n)
            if v != None:
                w(';%s=%s' % (n, v))
        if self.lr:
            w(';lr')
        for v in self.other:
            w(';%s' % v)
        if self.headers:
            w('?')
            w('&'.join([('%s=%s' % (h.capitalize(), quote(v))) for (h, v) in self.headers.items()]))
        return ''.join(l)

    def getCopy(self):
        return SipURL(username = self.username, password = self.password, host = self.host, port = self.port, \
          headers = self.headers, usertype = self.usertype, transport = self.transport, ttl = self.ttl, \
          maddr = self.maddr, method = self.method, tag = self.tag, other = list(self.other), \
          userparams = list(self.userparams), lr = self.lr)

    def getHost(self):
        return self.host

    def getPort(self):
        if self.port != None:
            return self.port
        else:
            return SipConf.default_port

    def getAddr(self):
        if self.port != None:
            return (self.host, self.port)
        else:
            return (self.host, SipConf.default_port)

    def setAddr(self, addr):
        self.host, self.port = addr
