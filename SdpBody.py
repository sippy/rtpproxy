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

from SdpMediaDescription import SdpMediaDescription
from SdpGeneric import SdpGeneric
from SdpOrigin import SdpOrigin
from SdpConnecton import SdpConnecton

f_types = {'v':SdpGeneric, 'o':SdpOrigin, 's':SdpGeneric, 'i':SdpGeneric, \
  'u':SdpGeneric, 'e':SdpGeneric, 'p':SdpGeneric, 'c':SdpConnecton, \
  'b':SdpGeneric, 't':SdpGeneric, 'r':SdpGeneric, 'z':SdpGeneric, \
  'k':SdpGeneric}

class SdpBody(object):
    v_header = None
    o_header = None
    s_header = None
    i_header = None
    u_header = None
    e_header = None
    p_header = None
    c_header = None
    b_header = None
    t_header = None
    r_header = None
    z_header = None
    k_header = None
    a_headers = None
    first_half = ('v', 'o', 's', 'i', 'u', 'e', 'p')
    second_half = ('b', 't', 'r', 'z', 'k')
    all_headers = ('v', 'o', 's', 'i', 'u', 'e', 'p', 'c', 'b', 't', 'r', 'z', 'k')
    sections = None

    def __init__(self, body = None, cself = None):
        if cself != None:
            for header_name in [x + '_header' for x in self.all_headers]:
                try:
                    setattr(self, header_name, getattr(cself, header_name).getCopy())
                except AttributeError:
                    pass
            self.a_headers = [x for x in cself.a_headers]
            self.sections = [x.getCopy() for x in cself.sections]
            return
        self.a_headers = []
        self.sections = []
        if body == None:
            return
        avpairs = [x.split('=', 1) for x in body.strip().splitlines() if len(x.strip()) > 0]
        current_snum = 0
        c_header = None
        for name, v in avpairs:
            name = name.lower()
            if name == 'm':
                current_snum += 1
                self.sections.append(SdpMediaDescription())
            if current_snum == 0:
                if name == 'c':
                    c_header = v
                elif name == 'a':
                    self.a_headers.append(v)
                else:
                    setattr(self, name + '_header', f_types[name](v))
            else:
                self.sections[-1].addHeader(name, v)
        if c_header != None:
            for section in self.sections:
                if section.c_header == None:
                    section.addHeader('c', c_header)
            if len(self.sections) == 0:
                self.addHeader('c', c_header)

    def __str__(self):
        s = ''
        if len(self.sections) == 1 and self.sections[0].c_header != None:
            for name in self.first_half:
                header = getattr(self, name + '_header')
                if header != None:
                    s += '%s=%s\r\n' % (name, str(header))
            s += 'c=%s\r\n' % str(self.sections[0].c_header)
            for name in self.second_half:
                header = getattr(self, name + '_header')
                if header != None:
                    s += '%s=%s\r\n' % (name, str(header))
            for header in self.a_headers:
                s += 'a=%s\r\n' % str(header)
            s += self.sections[0].localStr(noC = True)
            return s
        for name in self.all_headers:
            header = getattr(self, name + '_header')
            if header != None:
                s += '%s=%s\r\n' % (name, str(header))
        for header in self.a_headers:
            s += 'a=%s\r\n' % str(header)
        for section in self.sections:
            s += str(section)
        return s

    def localStr(self, local_addr = None, local_port = None):
        s = ''
        if len(self.sections) == 1 and self.sections[0].c_header != None:
            for name in self.first_half:
                header = getattr(self, name + '_header')
                if header != None:
                    s += '%s=%s\r\n' % (name, header.localStr(local_addr, local_port))
            s += 'c=%s\r\n' % self.sections[0].c_header.localStr(local_addr, local_port)
            for name in self.second_half:
                header = getattr(self, name + '_header')
                if header != None:
                    s += '%s=%s\r\n' % (name, header.localStr(local_addr, local_port))
            for header in self.a_headers:
                s += 'a=%s\r\n' % str(header)
            s += self.sections[0].localStr(local_addr, local_port, noC = True)
            return s
        for name in self.all_headers:
            header = getattr(self, name + '_header')
            if header != None:
                s += '%s=%s\r\n' % (name, header.localStr(local_addr, local_port))
        for header in self.a_headers:
            s += 'a=%s\r\n' % str(header)
        for section in self.sections:
            s += section.localStr(local_addr, local_port)
        return s

    def __iadd__(self, other):
        if len(self.sections) > 0:
            self.sections[-1].addHeader(*other.strip().split('=', 1))
        else:
            self.addHeader(*other.strip().split('=', 1))
        return self

    def getCopy(self):
        return SdpBody(cself = self)

    def addHeader(self, name, header):
        if name == 'a':
            self.a_headers.append(header)
        else:
            setattr(self, name + '_header', f_types[name](header))
