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
# $Id: SipWWWAuthenticate.py,v 1.3 2008/02/18 19:49:45 sobomax Exp $

from random import random
from md5 import md5
from time import time
from SipGenericHF import SipGenericHF
from SipConf import SipConf

class SipWWWAuthenticate(SipGenericHF):
    hf_names = ('www-authenticate',)
    realm = None
    nonce = None

    def __init__(self, body = None, realm = None, nonce = None):
        if body != None:
            parts = body.split(' ', 1)[1].strip().split('"')
            if len(parts) % 2 != 0 and len(parts[-1]) == 0:
                parts.pop()
            while len(parts) > 0:
                parts1 = map(lambda x: x.strip().split('=', 1), parts.pop(0).strip(' ,=').split(','))
                if len(parts) > 0:
                    parts1[-1].append(parts.pop(0))
                for name, value in parts1:
                    if name == 'realm':
                        self.realm = value
                    elif name == 'nonce':
                        self.nonce = value
            return
        if nonce == None:
            ctime = time()
            nonce = md5(str((random() * 1000000000L) + ctime)).hexdigest() + hex(int(ctime))[2:]
        if realm == None:
            realm = SipConf.my_address
        self.realm = realm
        self.nonce = nonce

    def __str__(self):
        return 'Digest realm="%s",nonce="%s"' % (self.realm, self.nonce)

    def getCopy(self):
        return SipWWWAuthenticate(realm = self.realm, nonce = self.nonce)

    def getCanName(self, name):
        return 'WWW-Authenticate'

    def getRealm(self):
        return self.realm

    def getNonce(self):
        return self.nonce
