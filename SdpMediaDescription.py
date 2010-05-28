# Copyright (c) 2009 Sippy Software, Inc. All rights reserved.
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

from SdpConnecton import SdpConnecton
from SdpMedia import SdpMedia
from SdpGeneric import SdpGeneric

f_types = {'m':SdpMedia, 'i':SdpGeneric, 'c':SdpConnecton, 'b':SdpGeneric, \
  'k':SdpGeneric}

class SdpMediaDescription(object):
    m_header = None
    i_header = None
    c_header = None
    b_header = None
    k_header = None
    a_headers = None
    all_headers = ('m', 'i', 'c', 'b', 'k')
    needs_update = True

    def __init__(self, cself = None):
        if cself != None:
            for header_name in [x + '_header' for x in self.all_headers]:
                try:
                    setattr(self, header_name, getattr(cself, header_name).getCopy())
                except AttributeError:
                    pass
            self.a_headers = [x for x in cself.a_headers]
            return
        self.a_headers = []

    def __str__(self):
        s = ''
        for name in self.all_headers:
            header = getattr(self, name + '_header')
            if header != None:
                s += '%s=%s\r\n' % (name, str(header))
        for header in self.a_headers:
            s += 'a=%s\r\n' % str(header)
        return s

    def localStr(self, local_addr = None, local_port = None, noC = False):
        s = ''
        for name in self.all_headers:
            if noC and name == 'c':
                continue
            header = getattr(self, name + '_header')
            if header != None:
                s += '%s=%s\r\n' % (name, header.localStr(local_addr, local_port))
        for header in self.a_headers:
            s += 'a=%s\r\n' % str(header)
        return s

    def __iadd__(self, other):
        self.addHeader(*other.strip().split('=', 1))
        return self

    def getCopy(self):
        return SdpMediaDescription(cself = self)

    def addHeader(self, name, header):
        if name == 'a':
            self.a_headers.append(header)
        else:
            setattr(self, name + '_header', f_types[name](header))
