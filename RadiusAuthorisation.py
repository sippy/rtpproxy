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

from Radius_client import Radius_client
from time import time

class RadiusAuthorisation(Radius_client):
    def do_auth(self, username, caller, callee, h323_cid, sip_cid, remote_ip, res_cb, \
      realm = None, nonce = None, uri = None, response = None, extra_attributes = None):
        sip_cid = str(sip_cid)
        attributes = None
        if None not in (realm, nonce, uri, response):
            attributes = [('User-Name', username), ('Digest-Realm', realm), \
              ('Digest-Nonce', nonce), ('Digest-Method', 'INVITE'), ('Digest-URI', uri), \
              ('Digest-Algorithm', 'MD5'), ('Digest-User-Name', username), ('Digest-Response', response)]
        else:
            attributes = [('User-Name', remote_ip), ('Password', 'cisco')]
        if caller == None:
            caller = ''
        attributes.extend((('Calling-Station-Id', caller), ('Called-Station-Id', callee), ('h323-conf-id', h323_cid), \
          ('call-id', sip_cid), ('h323-remote-address', remote_ip), ('h323-session-protocol', 'sipv2')))
        if extra_attributes != None:
            for a, v in extra_attributes:
                attributes.append((a, v))
        message = 'sending AAA request:\n' 
        message += reduce(lambda x, y: x + y, ['%-32s = \'%s\'\n' % (x[0], str(x[1])) for x in attributes])
        self.global_config['_sip_logger'].write(message, call_id = sip_cid)
        Radius_client.do_auth(self, attributes, self._process_result, res_cb, sip_cid, time())

    def _process_result(self, results, res_cb, sip_cid, btime):
        delay = time() - btime
        rcode = results[1]
        if rcode in (0, 1):
            if rcode == 0:
                message = 'AAA request accepted (delay is %.3f), processing response:\n' % delay
            else:
                message = 'AAA request rejected (delay is %.3f), processing response:\n' % delay
            if len(results[0]) > 0:
                message += reduce(lambda x, y: x + y, ['%-32s = \'%s\'\n' % x for x in results[0]])
        else:
            message = 'Error sending AAA request (delay is %.3f)\n' % delay
        self.global_config['_sip_logger'].write(message, call_id = sip_cid)
        res_cb(results)
