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
#
# $Id: SdpBodySection.py,v 1.4 2008/04/24 23:39:03 sobomax Exp $

from SdpField import SdpField

class SdpBodySection:
    headers = None
    needs_update = True

    def __init__(self, body = None, cself = None, headers = None):
        if body != None:
            self.headers = map(lambda x: SdpField(x), body.strip().splitlines())
        elif cself != None:
            self.headers = map(lambda x: x.getCopy(), cself.headers)
        elif headers != None:
            self.headers = headers
        else:
            self.headers = []

    def insertFAfter(self, iheader, header):
        self.headers.insert(self.headers.index(iheader) + 1, header)

    def __str__(self):
        if len(self.headers) > 1:
            return reduce(lambda x, y: str(x) + '\r\n' + str(y), self.headers) + '\r\n'
        return str(self.headers[0]) + '\r\n'

    def __iadd__(self, other):
        self.headers.append(SdpField(other))
        return self

    def getCopy(self):
        return SdpBodySection(cself = self)

    def getFs(self, name):
        return filter(lambda x: x.isName(name), self.headers)

    def countFs(self, name, value = None):
        if value == None:
            return len(filter(lambda x: x.isName(name), self.headers))
        return len(filter(lambda x: x.isName(name) and str(x.body) == value, self.headers))

    def delFs(self, name, value = None):
        if value == None:
            self.headers = filter(lambda x: not x.isName(name), self.headers)
        else:
            self.headers = filter(lambda x: not (x.isName(name) and str(x.body) == value), self.headers)

    def getF(self, name):
        return filter(lambda x: x.isName(name), self.headers)[0]
