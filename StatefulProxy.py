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
from SipConf import SipConf
from SipWWWAuthenticate import SipWWWAuthenticate
from RegistrationB2B import RegistrationB2B

class StatefulProxy:
    global_config = None
    destination = None

    def __init__(self, global_config, destination):
        self.global_config = global_config
        self.destination = destination

    def recvRequest(self, req):
        ruri = req.getRURI()
        if req.getMethod() == 'REGISTER':
            if req.countHFs('authorization') == 0:
                resp = req.genResponse(401, 'Unauthorized')
                resp.appendHeader(SipHeader(body = SipWWWAuthenticate(realm = 'pennytel.com')))
                return (resp, None, None)
            if req.countHFs('contact') == 0:
               resp = req.genResponse(400, 'Bad Request')
               return (resp, None, None)
            try:
                auth = req.getHFBody('authorization')
            except:
               resp = req.genResponse(400, 'Bad Request')
               return (resp, None, None) 
            self.global_config['_radius_client'].do_auth(auth.username, self.authDone, auth, req)
            return (None, None, None)
        via0 = SipVia()
        via0.genBranch()
        via1 = req.getHF('via')
        req.insertHeaderBefore(via1, SipHeader(name = 'via', body = via0))
        req.setTarget(self.destination)
        contact = req.getHFBody('contact')
        curl = contact.getUrl()
        if req.getMethod() != 'REGISTER':
            ruri = req.getRURI()
            ruri.host = 'pennytel.com'
            from_h = req.getHFBody('from').getUrl()
            from_h.host = 'pennytel.com'
            to_h = req.getHFBody('to').getUrl()
            to_h.host = 'pennytel.com'
            to_h.username = from_h.username
            ruri.username = from_h.username
        if req.getMethod() in ('REGISTER', 'SUBSCRIBE'):
            fakeusername = '%s__%d_%s' % (curl.host.replace('.', '_'), curl.getPort(), curl.username)
            curl.username = fakeusername
        curl.host, curl.port = (SipConf.my_address, SipConf.my_port)
        req.delHFs('user-agent')
        req.delHFs('server')
        req.appendHeader(SipHeader(name = 'user-agent'))
        self.global_config['_sip_tm'].newTransaction(req, self.recvResponse)
        return (None, None, None)

    def authDone(self, result, auth, req):
        if result == None:
            resp = req.genResponse(403, 'Auth Failed - 1')
            self.global_config['_sip_tm'].sendResponse(resp)
            return
        password_in, password_out, outbound_proxy, domain = result
        if not auth.verify(password_in, 'REGISTER'):
            resp = req.genResponse(403, 'Auth Failed - 2')
            self.global_config['_sip_tm'].sendResponse(resp)
            return
        reg_b2b = RegistrationB2B(self.global_config, req)
        return reg_b2b.proxyReq(outbound_proxy, domain, auth.username, password_out)

    def recvRequestDial(self, req):
        via0 = SipVia()
        via0.genBranch()
        via1 = req.getHF('via')
        req.insertHeaderBefore(via1, SipHeader(name = 'via', body = via0))
        ruri = req.getRURI()
        host, port_cld = ruri.username.split('__', 1)
        port, cld = port_cld.split('_', 1)
        ruri.username = cld
        req.setTarget((host.replace('_', '.'), int(port)))
        req.delHFs('user-agent')
        req.delHFs('server')
        req.appendHeader(SipHeader(name = 'user-agent'))
        self.global_config['_sip_tm'].newTransaction(req, self.recvResponse)
        return (None, None, None)

    def recvResponse(self, resp):
        resp.removeHeader(resp.getHF('via'))
        if resp.scode >= 200 and resp.scode < 300 and resp.getHFBody('cseq').getCSeqMethod() == 'REGISTER':
            curl = resp.getHFBody('contact').getUrl()
            host, port_cld = curl.username.split('__', 1)
            port, cld = port_cld.split('_')
            curl.username = cld
        resp.delHFs('user-agent')
        resp.delHFs('server')
        resp.appendHeader(SipHeader(name = 'server'))
        self.global_config['_sip_tm'].sendResponse(resp)
