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

    def optimize_a(self):
        new_a_headers = []
        for ah in self.a_headers:
            pt = None
            try:
                if ah.startswith('rtpmap:'):
                    pt = int(ah[7:].split(' ')[0])
                elif ah.startswith('fmtp:'):
                    pt = int(ah[5:].split(' ')[0])
            except:
                pass
            if pt != None and not pt in self.m_header.formats:
                continue
            new_a_headers.append(ah)
        self.a_headers = new_a_headers
