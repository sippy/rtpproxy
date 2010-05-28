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
from SipCSeq import SipCSeq
from SipCallId import SipCallId
from SipFrom import SipFrom
from SipTo import SipTo
from SipMaxForwards import SipMaxForwards
from SipVia import SipVia
from SipContentLength import SipContentLength
from SipContentType import SipContentType
from SipExpires import SipExpires
from SipRecordRoute import SipRecordRoute
from SipRoute import SipRoute
from SipContact import SipContact
from SipWWWAuthenticate import SipWWWAuthenticate
from SipAuthorization import SipAuthorization
from SipServer import SipServer
from SipUserAgent import SipUserAgent
from SipCiscoGUID import SipCiscoGUID
from SipAlso import SipAlso
from SipReferTo import SipReferTo
from SipCCDiversion import SipCCDiversion
from SipReferredBy import SipReferredBy
from SipProxyAuthenticate import SipProxyAuthenticate
from SipProxyAuthorization import SipProxyAuthorization
from SipReplaces import SipReplaces
from SipPAssertedIdentity import SipPAssertedIdentity
from SipReason import SipReason
from ESipHeaderCSV import ESipHeaderCSV

_hf_types = (SipCSeq, SipCallId, SipFrom, SipTo, SipMaxForwards, SipVia, SipContentLength, \
             SipContentType, SipExpires, SipRecordRoute, SipRoute, SipContact, SipWWWAuthenticate, \
             SipAuthorization, SipServer, SipUserAgent, SipCiscoGUID, SipAlso, SipReferTo, \
             SipCCDiversion, SipReferredBy, SipProxyAuthenticate, SipProxyAuthorization, \
             SipReplaces, SipPAssertedIdentity, SipReason)

hf_types = {}
for hf_type in _hf_types:
    for hf_name in hf_type.hf_names:
        hf_types[hf_name] = hf_type

class SipHeader(object):
    name = None
    body = None

    def __init__(self, s = None, name = None, body = None, bodys = None, fixname = False):
        if s != None:
            name, bodys = [x.strip() for x in s.split(':', 1)]
        if name != None:
            self.name = name.lower()
        if body == None:
            try:
                try:
                    body = hf_types[self.name](bodys)
                except KeyError:
                    body = SipGenericHF(bodys, name)
            except ESipHeaderCSV, einst:
                einst.name = self.name
                raise einst
        self.body = body
        # If no name is provided use canonic name from the body-specific
        # class.
        if self.name == None or fixname:
            self.name = body.hf_names[0]

    def __str__(self):
        return str(self.body.getCanName(self.name)) + ': ' + str(self.body)

    def localStr(self, local_addr = None, local_port = None, compact = False):
        return str(self.body.getCanName(self.name, compact)) + ': ' + \
          self.body.localStr(local_addr, local_port)

    def getBody(self):
        if not self.body.parsed:
            self.body.parse()
        return self.body
