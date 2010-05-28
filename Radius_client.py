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
