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

from sippy.Rtp_proxy_client_stream import Rtp_proxy_client_stream

import socket

class Rtp_proxy_client_local(Rtp_proxy_client_stream):
    is_local = True

    def __init__(self, global_config, address = '/var/run/rtpproxy.sock', \
      bind_address = None, nworkers = 1):
        Rtp_proxy_client_stream.__init__(self, global_config = global_config, \
          address = address, bind_address = bind_address, nworkers = nworkers, \
          family = socket.AF_UNIX)

if __name__ == '__main__':
    from sippy.Core.EventDispatcher import ED2
    class robj(object):
        rval = None
    r = robj()
    def display(res, ro, arg):
        print(res, arg)
        ro.rval = (res, arg)
        ED2.breakLoop()
    rc = Rtp_proxy_client_local({'_sip_address':'1.2.3.4'})
    rc.send_command('VF 123456', display, r, 'abcd')
    ED2.loop()
    rc.shutdown()
    assert(r.rval == ('0', 'abcd'))
