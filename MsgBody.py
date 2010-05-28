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

from SdpBody import SdpBody
from types import StringType

b_types = {'application/sdp':SdpBody}

class MsgBody(object):
    content = None
    mtype = None
    needs_update = True
    parsed = False

    def __init__(self, content = None, mtype = 'application/sdp', cself = None):
        if content != None:
            self.mtype = mtype
            self.content = content
        else:
            self.parsed = True
            if type(cself.content) == StringType:
                self.content = cself.content
            else:
                self.content = cself.content.getCopy()
            self.mtype = cself.mtype

    def parse(self):
        if not self.parsed:
            self.parsed = True
            if b_types.has_key(self.mtype):
                self.content = b_types[self.mtype](self.content)

    def __str__(self):
        return str(self.content)

    def localStr(self, local_addr = None, local_port = None):
        if type(self.content) == StringType:
            return self.content
        return self.content.localStr(local_addr, local_port)

    def getType(self):
        return self.mtype

    def getCopy(self):
        if not self.parsed:
            return MsgBody(self.content)
        return MsgBody(cself = self)
