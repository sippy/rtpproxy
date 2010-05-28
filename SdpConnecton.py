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

class SdpConnecton(object):
    ntype = None
    atype = None
    addr = None

    def __init__(self, body = None, cself = None):
        if body != None:
            self.ntype, self.atype, self.addr = body.split()[:3]
        else:
            self.ntype = cself.ntype
            self.atype = cself.atype
            self.addr = cself.addr

    def __str__(self):
        return '%s %s %s' % (self.ntype, self.atype, self.addr)

    def localStr(self, local_addr = None, local_port = None):
        return '%s %s %s' % (self.ntype, self.atype, self.addr)

    def getCopy(self):
        return SdpConnecton(cself = self)
