# Copyright (c) 2003-2005 Maxim Sobolev. All rights reserved.
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

from SipURL import SipURL
from string import maketrans

class SipAddress(object):
    name = None
    url = None
    params = None
    hadbrace = None
    transtable = maketrans('-.!%*_+`\'~', 'a' * 10)

    def __init__(self, address = None, name = None, url = None, params = None, hadbrace = None):
        self.params = {}
        self.hadbrace = True
        if address == None:
            self.name = name
            self.url = url
            if params != None:
                self.params = params
            if hadbrace != None:
                self.hadbrace = hadbrace
            return
        # simple 'sip:foo' case
        if address.lower().startswith('sip:') and address.find('<') == -1:
            parts = address.split(';', 1)
            self.url = SipURL(parts[0])
            if len(parts) == 2:
                for l in parts[1].split(';'):
                    if not l:
                        continue
                    k, v = l.split('=')
                    self.params[k] = v
            self.hadbrace = False
            return
        self.name, url = address.split('<', 1)
        self.name = self.name.strip()
        if self.name.startswith('"'):
            self.name = self.name[1:]
        if self.name.endswith('"'):
            self.name = self.name[:-1]
        url, paramstring = url.split('>', 1)
        self.url = SipURL(url)
        paramstring = paramstring.strip()
        if paramstring:
            for l in paramstring.split(';'):
                if not l:
                    continue
                k, v = l.split('=')
                self.params[k] = v

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
        for k, v in self.params.items():
            s += ';' + k + '=' + v
        return s

    def getCopy(self):
        return SipAddress(name = self.name, url = self.url.getCopy(), params = self.params.copy(), hadbrace = self.hadbrace)

    def getParam(self, name):
        try:
            return self.params[name]
        except KeyError:
            return None

    def setParam(self, name, value):
        self.params[name] = value

    def delParam(self, name):
        del self.params[name]
