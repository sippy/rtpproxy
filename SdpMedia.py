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

class MTAudio(object):
    pass

class MTOther(object):
    pass

class SdpMedia(object):
    type = None
    stype = None
    port = None
    transport = None
    formats = None

    def __init__(self, body = None, cself = None):
        if body != None:
            params = body.split()
            self.stype = params[0]
            if self.stype.lower() == 'audio':
                self.type = MTAudio
            else:
                self.type = MTOther
            self.port = int(params[1])
            self.transport = params[2]
            if self.type == MTAudio:
                self.formats = [int(x) for x in params[3:]]
            else:
                self.formats = params[3:]
        else:
            self.type = cself.type
            self.stype = cself.stype
            self.port = cself.port
            self.transport = cself.transport
            self.formats = cself.formats[:]

    def __str__(self):
        rval = '%s %d %s' % (self.stype, self.port, self.transport)
        if self.type == MTAudio:
            for format in self.formats:
                rval += ' %d' % format
        else:
            for format in self.formats:
                rval += ' %s' % format
        return rval

    def localStr(self, local_addr = None, local_port = None):
        return str(self)

    def getCopy(self):
        return SdpMedia(cself = self)
