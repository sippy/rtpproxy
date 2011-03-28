# Copyright (c) 2003-2005 Maxim Sobolev. All rights reserved.
# Copyright (c) 2006-2011 Sippy Software, Inc. All rights reserved.
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

from SipVia import SipVia
from SipHeader import SipHeader

class StatefulProxy:
    global_config = None
    destination = None

    def __init__(self, global_config, destination):
        print destination
        self.global_config = global_config
        self.destination = destination

    def recvRequest(self, req):
        via0 = SipVia()
        via0.genBranch()
        via1 = req.getHF('via')
        req.insertHeaderBefore(via1, SipHeader(name = 'via', body = via0))
        req.setTarget(self.destination)
        print req
        self.global_config['_sip_tm'].newTransaction(req, self.recvResponse)
        return (None, None, None)

    def recvResponse(self, resp):
        resp.removeHeader(resp.getHF('via'))
        self.global_config['_sip_tm'].sendResponse(resp)
