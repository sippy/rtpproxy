# Copyright (c) 2005 Maxim Sobolev. All rights reserved.
# Copyright (c) 2006-2007 Sippy Software, Inc. All rights reserved.
#
# This file is part of SIPPY, a free RFC3261 SIP stack and B2BUA.
#
# SIPPY is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# For a license to use the SIPPY software under conditions
# other than those described here, or to purchase support for this
# software, please contact Sippy Software, Inc. by e-mail at the
# following addresses: sales@sippysoft.com.
#
# SIPPY is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

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
        self.parsed = True
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
