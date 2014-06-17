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
        # Special code to optimize for the cases when there are many media streams pointing to
        # the same IP. Only include c= header into the top section of the SDP and remove it from
        # the streams that match.
        optimize_c_headers = False
        if len(self.sections) > 1 and self.c_header == None and self.sections[0].c_header != None and \
          str(self.sections[0].c_header) == str(self.sections[1].c_header):
            # Special code to optimize for the cases when there are many media streams pointing to
            # the same IP. Only include c= header into the top section of the SDP and remove it from
            # the streams that match.
            optimize_c_headers = True
            sections_0_str = str(self.sections[0].c_header)
        if optimize_c_headers:
            for name in self.first_half:
                header = getattr(self, name + '_header')
                if header != None:
                    s += '%s=%s\r\n' % (name, str(header))
            s += 'c=%s\r\n' % sections_0_str
            for name in self.second_half:
                header = getattr(self, name + '_header')
                if header != None:
                    s += '%s=%s\r\n' % (name, str(header))
        else:
            for name in self.all_headers:
                header = getattr(self, name + '_header')
                if header != None:
                    s += '%s=%s\r\n' % (name, str(header))
        for header in self.a_headers:
            s += 'a=%s\r\n' % str(header)
        for section in self.sections:
            if optimize_c_headers and section.c_header != None and \
              str(section.c_header) == sections_0_str:
                s += section.localStr(noC = True)
            else:
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
        # Special code to optimize for the cases when there are many media streams pointing to
        # the same IP. Only include c= header into the top section of the SDP and remove it from
        # the streams that match.
        optimize_c_headers = False
        if len(self.sections) > 1 and self.c_header == None and self.sections[0].c_header != None and \
          self.sections[0].c_header.localStr(local_addr, local_port) == self.sections[1].c_header.localStr(local_addr, local_port):
            # Special code to optimize for the cases when there are many media streams pointing to
            # the same IP. Only include c= header into the top section of the SDP and remove it from
            # the streams that match.
            optimize_c_headers = True
            sections_0_str = self.sections[0].c_header.localStr(local_addr, local_port)
        if optimize_c_headers:
            for name in self.first_half:
                header = getattr(self, name + '_header')
                if header != None:
                    s += '%s=%s\r\n' % (name, header.localStr(local_addr, local_port))
            s += 'c=%s\r\n' % sections_0_str
            for name in self.second_half:
                header = getattr(self, name + '_header')
                if header != None:
                    s += '%s=%s\r\n' % (name, header.localStr(local_addr, local_port))
        else:
            for name in self.all_headers:
                header = getattr(self, name + '_header')
                if header != None:
                    s += '%s=%s\r\n' % (name, header.localStr(local_addr, local_port))
        for header in self.a_headers:
            s += 'a=%s\r\n' % str(header)
        for section in self.sections:
            if optimize_c_headers and section.c_header != None and \
              section.c_header.localStr(local_addr, local_port) == sections_0_str:
                s += section.localStr(local_addr, local_port, noC = True)
            else:
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
