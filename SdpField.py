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
# $Id: SdpField.py,v 1.5 2009/01/05 20:14:00 sobomax Exp $

from SdpConnecton import SdpConnecton
from SdpMedia import SdpMedia
from SdpOrigin import SdpOrigin
from types import StringType

f_types = {'c':SdpConnecton, 'm':SdpMedia, 'o':SdpOrigin}

class SdpField(object):
    name = None
    body = None

    def __init__(self, body = None, cself = None):
        if body != None:
            if len(body.strip()) == 0:
                return
            name, body = [s.strip() for s in body.split('=', 1)]
            self.name = name.lower()
            try:
                self.body = f_types[self.name](body)
            except KeyError:
                self.body = body
        else:
            self.name = cself.name
            if type(cself.body) == StringType:
                self.body = cself.body
            elif cself.body != None:
                self.body = cself.body.getCopy()

    def __str__(self):
        if self.name == None and self.body == None:
            return ''
        return str(self.name) + '=' + str(self.body)

    def isName(self, name):
        return name.lower() == self.name

    def getCopy(self):
        return SdpField(cself = self)
