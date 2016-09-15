# Copyright (c) 2003-2005 Maxim Sobolev. All rights reserved.
# Copyright (c) 2006-2016 Sippy Software, Inc. All rights reserved.
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

from sippy.SipHeader import SipHeader
from sippy.SipConf import SipConf

from urllib import unquote
from socket import getaddrinfo, SOCK_STREAM, AF_INET, AF_INET6

class B2BRoute(object):
    rnum = None
    addrinfo = None
    cld = None
    cld_set = False
    hostport = None
    hostonly = None
    credit_time = None
    crt_set = False
    expires = None
    no_progress_expires = None
    forward_on_fail = False
    user = None
    passw = None
    cli = None
    cli_set = False
    params = None
    ainfo = None
    extra_headers = None

    def __init__(self, sroute = None, cself = None):
        if cself != None:
            self.rnum = cself.rnum
            self.addrinfo = cself.addrinfo
            self.cld = cself.cld
            self.cld_set = cself.cld_set
            self.hostport = cself.hostport
            self.hostonly = cself.hostonly
            self.credit_time = cself.credit_time
            self.crt_set = cself.crt_set
            self.expires = cself.expires
            self.no_progress_expires = cself.no_progress_expires
            self.forward_on_fail = cself.forward_on_fail
            self.user = cself.user
            self.passw = cself.passw
            self.cli = cself.cli
            self.cli_set = cself.cli_set
            self.params = dict(cself.params)
            self.ainfo = cself.ainfo
            if cself.extra_headers != None:
                self.extra_headers = tuple([x.getCopy() for x in cself.extra_headers])
            return
        route = sroute.split(';')
        if route[0].find('@') != -1:
            self.cld, self.hostport = route[0].split('@', 1)
            if len(self.cld) == 0:
                # Allow CLD to be forcefully removed by sending `Routing:@host' entry,
                # as opposed to the Routing:host, which means that CLD should be obtained
                # from the incoming call leg.
                self.cld = None
            self.cld_set = True
        else:
            self.hostport = route[0]
        if not self.hostport.startswith('['):
            hostport = self.hostport.split(':', 1)
            af = 0
            self.hostonly = hostport[0]
        else:
            hostport = self.hostport[1:].split(']', 1)
            if len(hostport) > 1:
                if len(hostport[1]) == 0:
                    del hostport[1]
                else:
                    hostport[1] = hostport[1][1:]
            af = AF_INET6
            self.hostonly = '[%s]' % hostport[0]
        if len(hostport) == 1:
            port = SipConf.default_port
        else:
            port = int(hostport[1])
        self.ainfo = getaddrinfo(hostport[0], port, af, SOCK_STREAM)
        self.params = {}
        extra_headers = []
        for a, v in [x.split('=', 1) for x in route[1:]]:
            if a == 'credit-time':
                self.credit_time = int(v)
                if self.credit_time < 0:
                    self.credit_time = None
                self.crt_set = True
            elif a == 'expires':
                self.expires = int(v)
                if self.expires < 0:
                    self.expires = None
            elif a == 'hs_scodes':
                self.params['huntstop_scodes'] = tuple([int(x) for x in v.split(',') if len(x.strip()) > 0])
            elif a == 'np_expires':
                self.no_progress_expires = int(v)
                if self.no_progress_expires < 0:
                    self.no_progress_expires = None
            elif a == 'forward_on_fail':
                self.forward_on_fail = True
            elif a == 'auth':
                self.user, self.passw = v.split(':', 1)
            elif a == 'cli':
                self.cli = v
                if len(self.cli) == 0:
                    self.cli = None
                self.cli_set = True
            elif a == 'cnam':
                caller_name = unquote(v)
                if len(caller_name) == 0:
                    caller_name = None
                self.params['caller_name'] = caller_name
            elif a == 'ash':
                ash = SipHeader(unquote(v))
                extra_headers.append(ash)
            elif a == 'rtpp':
                self.params['rtpp'] = (int(v) != 0)
            elif a == 'op':
                host_port = v.split(':', 1)
                if len(host_port) == 1:
                    self.params['outbound_proxy'] = (v, 5060)
                else:
                    self.params['outbound_proxy'] = (host_port[0], int(host_port[1]))
            else:
                self.params[a] = v
        if len(extra_headers) > 0:
            self.extra_headers = tuple(extra_headers)

    def customize(self, rnum, default_cld, default_cli, default_credit_time, \
      pass_headers, max_credit_time):
        self.rnum = rnum
        if not self.cld_set:
            self.cld = default_cld
        if not self.cli_set:
            self.cli = default_cli
        if not self.crt_set:
            self.crt_set = default_credit_time
        if self.params.has_key('gt'):
            timeout, skip = self.params['gt'].split(',', 1)
            self.params['group_timeout'] = (int(timeout), rnum + int(skip))
        if self.extra_headers != None:
            self.extra_headers = self.extra_headers + tuple(pass_headers)
        else:
            self.extra_headers = tuple(pass_headers)
        if max_credit_time != None:
            if self.credit_time == None or self.credit_time > max_credit_time:
                self.credit_time = max_credit_time

    def getCopy(self):
        return self.__class__(cself = self)

    def getNHAddr(self, source):
        if source[0].startswith('['):
            af = AF_INET6
        else:
            af = AF_INET
        amatch = [x[4] for x in self.ainfo if x[0] == af]
        same_af = True
        if len(amatch) == 0:
            same_af = False
            amatch = self.ainfo[0][4]
            af = self.ainfo[0][0]
        else:
            amatch = amatch[0]
        if af == AF_INET6:
            return ((('[%s]' % amatch[0], amatch[1]), same_af))
        return (((amatch[0], amatch[1]), same_af))
