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

from urllib import unquote

class B2BRoute(object):
    rnum = None
    addrinfo = None
    cld = None
    host = None
    credit_time = None
    expires = None
    no_progress_expires = None
    forward_on_fail = False
    user = None
    passw = None
    cli = None
    params = None

    def __init__(self, sroute, rnum, default_cld = None, default_cli = None, \
      default_credit_time = None):
        self.rnum = rnum
        route = sroute.split(';')
        if route[0].find('@') != -1:
            self.cld, self.host = route[0].split('@', 1)
            if len(self.cld) == 0:
                # Allow CLD to be forcefully removed by sending `Routing:@host' entry,
                # as opposed to the Routing:host, which means that CLD should be obtained
                # from the incoming call leg.
                self.cld = None
        else:
            self.cld = default_cld
            self.host = route[0]
        self.credit_time = default_credit_time
        self.cli = default_cli
        self.params = {}
        for a, v in [x.split('=', 1) for x in route[1:]]:
            if a == 'credit-time':
                self.credit_time = int(v)
                if self.credit_time < 0:
                    self.credit_time = None
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
            elif a == 'cnam':
                caller_name = unquote(v)
                if len(caller_name) == 0:
                    caller_name = None
                self.params['caller_name'] = caller_name
            elif a == 'ash':
                ash = SipHeader(unquote(v))
                self.params['extra_headers'].append(ash)
            elif a == 'rtpp':
                self.params['rtpp'] = (int(v) != 0)
            elif a == 'gt':
                timeout, skip = v.split(',', 1)
                self.params['group_timeout'] = (int(timeout), rnum + int(skip))
            elif a == 'op':
                host_port = v.split(':', 1)
                if len(host_port) == 1:
                    self.params['outbound_proxy'] = (v, 5060)
                else:
                    self.params['outbound_proxy'] = (host_port[0], int(host_port[1]))
            else:
                self.params[a] = v
