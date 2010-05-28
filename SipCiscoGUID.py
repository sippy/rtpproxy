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

from random import random
from hashlib import md5
from time import time
from SipGenericHF import SipGenericHF

class SipCiscoGUID(SipGenericHF):
    hf_names = ('cisco-guid', 'h323-conf-id')
    ciscoGUID = None

    def __init__(self, body = None, ciscoGUID = None):
        SipGenericHF.__init__(self, body)
        if body != None:
            return
        self.parsed = True
        if ciscoGUID != None:
            self.ciscoGUID = ciscoGUID
        else:
            s = md5(str((random() * 1000000000L) + time())).hexdigest()
            self.ciscoGUID = (long(s[0:8], 16), long(s[8:16], 16), long(s[16:24], 16), long(s[24:32], 16))

    def parse(self):
        self.parsed = True
        self.ciscoGUID = tuple([int(x) for x in  self.body.split('-', 3)])

    def __str__(self):
        if not self.parsed:
            return self.body
        return '%d-%d-%d-%d' % self.ciscoGUID

    def getCiscoGUID(self):
        return self.ciscoGUID

    def hexForm(self):
        return '%.8X %.8X %.8X %.8X' % self.ciscoGUID

    def getCanName(self, name, compact = False):
        if name.lower() == 'h323-conf-id':
            return 'h323-conf-id'
        else:
            return 'cisco-GUID'

    def getCopy(self):
        if not self.parsed:
            return SipCiscoGUID(self.body)
        return SipCiscoGUID(ciscoGUID = self.ciscoGUID)
