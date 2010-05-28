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

from SipGenericHF import SipGenericHF

class SipNumericHF(SipGenericHF):
    number = None

    def __init__(self, body = None, number = 0):
        SipGenericHF.__init__(self, body)
        if body == None:
            self.parsed = True
            self.number = number

    def parse(self):
        self.parsed = True
        self.number = int(self.body)

    def __str__(self):
        if not self.parsed:
            return self.body
        return str(self.number)

    def getCopy(self):
        if not self.parsed:
            return self.__class__(body = self.body)
        return self.__class__(number = self.number)

    def getNum(self):
        return self.number
