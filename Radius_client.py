#
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

from External_command import External_command

class Radius_client(External_command):
    global_config = None
    _avpair_names = ('call-id', 'h323-session-protocol', 'h323-ivr-out', 'h323-incoming-conf-id', \
      'release-source', 'alert-timepoint', 'provisional-timepoint')
    _cisco_vsa_names = ('h323-remote-address', 'h323-conf-id', 'h323-setup-time', 'h323-call-origin', \
      'h323-call-type', 'h323-connect-time', 'h323-disconnect-time', 'h323-disconnect-cause', \
      'h323-voice-quality', 'h323-credit-time', 'h323-return-code', 'h323-redirect-number', \
      'h323-preferred-lang', 'h323-billing-model', 'h323-currency')

    def __init__(self, global_config = {}):
        self.global_config = global_config
        command = global_config.getdefault('radiusclient', '/usr/local/sbin/radiusclient')
        config = global_config.getdefault('radiusclient.conf', None)
        max_workers = global_config.getdefault('max_radiusclients', 20)
        if config != None:
            External_command.__init__(self, (command, '-f', config, '-s'), max_workers = max_workers)
        else:
            External_command.__init__(self, (command, '-s'), max_workers = max_workers)

    def _prepare_attributes(self, type, attributes):
        data = [type]
        for a, v in attributes:
            if a in self._avpair_names:
                v = '%s=%s' % (str(a), str(v))
                a = 'Cisco-AVPair'
            elif a in self._cisco_vsa_names:
                v = '%s=%s' % (str(a), str(v))
            data.append('%s="%s"' % (str(a), str(v)))
        return data

    def do_auth(self, attributes, result_callback, *callback_parameters):
        return External_command.process_command(self, self._prepare_attributes('AUTH', attributes), result_callback, *callback_parameters)

    def do_acct(self, attributes, result_callback = None, *callback_parameters):
        External_command.process_command(self, self._prepare_attributes('ACCT', attributes), result_callback, *callback_parameters)

    def process_result(self, result_callback, result, *callback_parameters):
        if result_callback == None:
            return
        nav = []
        for av in result[:-1]:
            a, v = [x.strip() for x in av.split(' = ', 1)]
            v = v.strip('\'')
            if (a == 'Cisco-AVPair' or a in self._cisco_vsa_names):
                t = v.split('=', 1)
                if len(t) > 1:
                    a, v = t
            elif v.startswith(a + '='):
                v = v[len(a) + 1:]
            nav.append((a, v))
        External_command.process_result(self, result_callback, (tuple(nav), int(result[-1])), *callback_parameters)
