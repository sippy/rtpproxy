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

from SipGenericHF import SipGenericHF

class SipReplaces(SipGenericHF):
    hf_names = ('replaces',)
    call_id = None
    from_tag = None
    to_tag = None
    early_only = False
    params = None

    def __init__(self, body = None, call_id = None, from_tag = None, to_tag = None, \
      early_only = False, params = None):
        SipGenericHF.__init__(self, body)
        if body != None:
            return
        self.parsed = True
        self.params = []
        self.call_id = call_id
        self.from_tag = from_tag
        self.to_tag = to_tag
        self.early_only = early_only
        if params != None:
            self.params = params[:]

    def parse(self):
        self.params = []
        params = self.body.split(';')
        self.call_id = params.pop(0)
        for param in params:
            if param.startswith('from-tag='):
                self.from_tag = param[len('from-tag='):]
            elif param.startswith('to-tag='):
                self.to_tag = param[len('to-tag='):]
            elif param == 'early-only':
                self.early_only = True
            else:
                self.params.append(param)
        self.parsed = True

    def __str__(self):
        if not self.parsed:
            return self.body
        res = '%s;from-tag=%s;to-tag=%s' % (self.call_id, self.from_tag, self.to_tag)
        if self.early_only:
            res += ';early-only'
        for param in self.params:
            res += ';' + param
        return res

    def getCopy(self):
        if not self.parsed:
            return SipReplaces(self.body)
        return SipReplaces(call_id = self.call_id, from_tag = self.from_tag, to_tag = self.to_tag, \
          early_only = self.early_only, params = self.params)
