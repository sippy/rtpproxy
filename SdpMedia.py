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
