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

class SipGenericHF(object):
    hf_names = None	# Set this in each subclass!!
    body = None
    parsed = False

    def __init__(self, body, name = None):
        self.body = body
        if name != None:
            self.hf_names = (name.lower(),)

    def parse(self):
        pass

    def localStr(self, local_addr = None, local_port = None):
        return self.__str__()

    def __str__(self):
        return self.body

    def getCopy(self):
        return self.__class__(self.body)

    def getCanName(self, name, compact = False):
        return name.capitalize()
