# Copyright (c) 2003-2005 Maxim Sobolev. All rights reserved.
# Copyright (c) 2006-2014 Sippy Software, Inc. All rights reserved.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation and/or
# other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
