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

from UaStateGeneric import UaStateGeneric

class UaStateDead(UaStateGeneric):
    sname = 'Dead'
    dead = True

    def __init__(self, ua):
        UaStateGeneric.__init__(self, None)
        if ua.cId != None:
            ua.global_config['_sip_tm'].unregConsumer(ua, str(ua.cId))
        ua.tr = None
        ua.event_cb = None
        ua.conn_cbs = ()
        ua.disc_cbs = ()
        ua.fail_cbs = ()
        ua.on_local_sdp_change = None
        ua.on_remote_sdp_change = None
        ua.expire_timer = None
        ua.no_progress_timer = None
        ua.credit_timer = None
        # Keep this at the very end of processing
        for callback in ua.dead_cbs:
            callback(ua)
        ua.dead_cbs = ()
        ua.cleanup()
        # Break cross-ref chain
        self.ua = None
