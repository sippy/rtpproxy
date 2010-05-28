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
from hashlib import md5
from time import time

class SipAuthorization(SipGenericHF):
    hf_names = ('authorization',)
    username = None
    uri = None
    realm = None
    nonce = None
    response = None
    qop = None
    cnonce = None
    nc = None
    otherparams = None

    def __init__(self, body = None, username = None, uri = None, realm = None, nonce = None, response = None, \
                 password = None, method = None, cself = None):
        SipGenericHF.__init__(self, body)
        if body != None:
            return
        self.parsed = True
        if cself != None:
            self.username = cself.username
            self.uri = cself.uri
            self.realm = cself.realm
            self.nonce = cself.nonce
            self.response = cself.response
            self.qop = cself.qop
            self.cnonce = cself.cnonce
            self.nc = cself.nc
            self.otherparams = cself.otherparams[:]
            return
        self.username = username
        self.uri = uri
        self.realm = realm
        self.nonce = nonce
        if response == None:
            HA1 = DigestCalcHA1('md5', username, realm, password, nonce, '')
            self.response = DigestCalcResponse(HA1, nonce, 0, '', '', method, uri, '')
        else:
            self.response = response
        self.otherparams = []

    def parse(self):
        self.parsed = True
        self.otherparams = []
        for name, value in [x.strip(', ').split('=', 1) for x in self.body.split(' ', 1)[1].split(',')]:
            if name == 'username':
                self.username = value.strip('"')
            elif name == 'uri':
                self.uri = value.strip('"')
            elif name == 'realm':
                self.realm = value.strip('"')
            elif name == 'nonce':
                self.nonce = value.strip('"')
            elif name == 'response':
                self.response = value.strip('"')
            elif name == 'qop':
                self.qop = value.strip('"')
            elif name == 'cnonce':
                self.cnonce = value.strip('"')
            elif name == 'nc':
                self.nc = value.strip('"')
            else:
                self.otherparams.append((name, value))

    def __str__(self):
        if not self.parsed:
            return self.body
        rval = 'Digest username="%s",realm="%s",nonce="%s",uri="%s",response="%s"' % \
               (self.username, self.realm, self.nonce, self.uri, self.response)
        if self.qop != None:
            rval += ',nc="%s",cnonce="%s",qop=%s' % (self.nc, self.cnonce, \
              self.qop)
        for param in self.otherparams:
            rval += ',%s=%s' % param
        return rval

    def getCopy(self):
        if not self.parsed:
            return self.__class__(self.body)
        return self.__class__(cself = self)

    def verify(self, password, method):
        if not self.parsed:
            self.parse()
        return self.verifyHA1(DigestCalcHA1('md5', self.username, self.realm, password, self.nonce, ''), method)

    def verifyHA1(self, HA1, method):
        if not self.parsed:
            self.parse()
        response = DigestCalcResponse(HA1, self.nonce, self.nc, \
          self.cnonce, self.qop, method, self.uri, '')
        return response == self.response

    def getCanName(self, name, compact = False):
        return 'Authorization'

    def hasValidNonce(self, timeout = 300):
        if self.nonce == None:
            return False
        try:
            if time() - timeout < int(self.nonce[32:], 16):
                return True
        except:
            pass
        return False

def DigestCalcHA1(pszAlg, pszUserName, pszRealm, pszPassword, pszNonce, pszCNonce):
    m = md5()
    m.update(pszUserName)
    m.update(":")
    m.update(pszRealm)
    m.update(":")
    m.update(pszPassword)
    HA1 = m.digest()
    if pszAlg == "md5-sess":
        m = md5()
        m.update(HA1)
        m.update(":")
        m.update(pszNonce)
        m.update(":")
        m.update(pszCNonce)
        HA1 = m.digest()
    return HA1.encode('hex')

def DigestCalcResponse(HA1, pszNonce, pszNonceCount, pszCNonce, pszQop, pszMethod, pszDigestUri, pszHEntity):
    m = md5()
    m.update(pszMethod)
    m.update(":")
    m.update(pszDigestUri)
    if pszQop == "auth-int":
        m.update(":")
        m.update(pszHEntity)
    HA2 = m.digest().encode('hex')
    m = md5()
    m.update(HA1)
    m.update(":")
    m.update(pszNonce)
    m.update(":")
    if pszNonceCount and pszCNonce: # pszQop:
        m.update(pszNonceCount)
        m.update(":")
        m.update(pszCNonce)
        m.update(":")
        m.update(pszQop)
        m.update(":")
    m.update(HA2)
    response = m.digest().encode('hex')
    return response
