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

from SdpOrigin import SdpOrigin

from hashlib import md5
from random import random
from time import time
from datetime import datetime
from traceback import print_exc
import sys

class Rtp_proxy_session(object):
    rtp_proxy_client = None
    call_id = None
    from_tag = None
    to_tag = None
    caller_session_exists = False
    caller_codecs = None
    caller_raddress = None
    callee_session_exists = False
    callee_codecs = None
    callee_raddress = None
    max_index = -1
    origin = None
    notify_socket = None
    notify_tag = None
    global_config = None

    def __init__(self, global_config, call_id = None, from_tag = None, to_tag = None,
      notify_socket = None, notify_tag = None):
        self.global_config = global_config
        if global_config.has_key('_rtp_proxy_clients'):
            rtp_proxy_clients = [x for x in global_config['_rtp_proxy_clients'] if x.online]
            n = len(rtp_proxy_clients)
            if n == 0:
                raise Exception('No online RTP proxy client has been found')
            self.rtp_proxy_client = rtp_proxy_clients[int(random() * n)]
        else:
            self.rtp_proxy_client = global_config['rtp_proxy_client']
            if not self.rtp_proxy_client.online:
                raise Exception('No online RTP proxy client has been found')
        if call_id != None:
            self.call_id = call_id
        else:
            self.call_id = md5(str(random()) + str(time())).hexdigest()
        if from_tag != None:
            self.from_tag = from_tag
        else:
            self.from_tag = md5(str(random()) + str(time())).hexdigest()
        if to_tag != None:
            self.to_tag = to_tag
        else:
            self.to_tag = md5(str(random()) + str(time())).hexdigest()
        self.origin = SdpOrigin()
        self.notify_socket = notify_socket
        self.notify_tag = notify_tag

    def version(self, result_callback):
        self.rtp_proxy_client.send_command('V', self.version_result, result_callback)

    def version_result(self, result, result_callback):
        result_callback(result)

    def play_caller(self, prompt_name, times = 1, result_callback = None, index = 0):
        if not self.caller_session_exists:
            return
        if not self.callee_session_exists:
            self.update_callee('0.0.0.0', 0, self._play_caller, '', index, prompt_name, times, result_callback, index)
            return
        self._play_caller(None, prompt_name, times, result_callback, index)

    def _play_caller(self, result, prompt_name, times, result_callback, index):
        command = 'P%d %s %s %s %s %s' % (times, '%s-%d' % (self.call_id, index), prompt_name, self.caller_codecs, self.from_tag, self.to_tag)
        self.rtp_proxy_client.send_command(command, self.command_result, result_callback)

    def play_callee(self, prompt_name, times = 1, result_callback = None, index = 0):
        if not self.callee_session_exists:
            return
        if not self.caller_session_exists:
            self.update_caller('0.0.0.0', 0, self._play_callee, '', index, prompt_name, times, result_callback, index)
            return
        self._play_callee(None, prompt_name, times, result_callback, index)

    def _play_callee(self, result, prompt_name, times, result_callback, index):
        command = 'P%d %s %s %s %s %s' % (times, '%s-%d' % (self.call_id, index), prompt_name, self.callee_codecs, self.to_tag, self.from_tag)
        self.rtp_proxy_client.send_command(command, self.command_result, result_callback)

    def stop_play_caller(self, result_callback = None, index = 0):
        if not self.caller_session_exists:
            return
        command = 'S %s %s %s' % ('%s-%d' % (self.call_id, index), self.from_tag, self.to_tag)
        self.rtp_proxy_client.send_command(command, self.command_result, result_callback)

    def stop_play_callee(self, result_callback = None, index = 0):
        if not self.caller_session_exists:
            return
        command = 'S %s %s %s' % ('%s-%d' % (self.call_id, index), self.to_tag, self.from_tag)
        self.rtp_proxy_client.send_command(command, self.command_result, result_callback)

    def copy_caller(self, remote_ip, remote_port, result_callback = None, index = 0):
        if not self.caller_session_exists:
            self.update_caller('0.0.0.0', 0, self._copy_caller, '', index, remote_ip, remote_port, result_callback, index)
            return
        self._copy_caller(None, remote_ip, remote_port, result_callback, index)

    def _copy_caller(self, result, remote_ip, remote_port, result_callback = None, index = 0):
        command = 'C %s udp:%s:%d %s %s' % ('%s-%d' % (self.call_id, index), remote_ip, remote_port, self.from_tag, self.to_tag)
        self.rtp_proxy_client.send_command(command, self.command_result, result_callback)

    def copy_callee(self, remote_ip, remote_port, result_callback = None, index = 0):
        if not self.callee_session_exists:
            self.update_callee('0.0.0.0', 0, self._copy_callee, '', index, remote_ip, remote_port, result_callback, index)
            return
        self._copy_callee(None, remote_ip, remote_port, result_callback, index)

    def _copy_callee(self, result, remote_ip, remote_port, result_callback = None, index = 0):
        command = 'C %s udp:%s:%d %s %s' % ('%s-%d' % (self.call_id, index), remote_ip, remote_port, self.to_tag, self.from_tag)
        self.rtp_proxy_client.send_command(command, self.command_result, result_callback)

    def start_recording(self, rname = None, result_callback = None, index = 0):
        if not self.caller_session_exists:
            self.update_caller('0.0.0.0', 0, self._start_recording, '', index, rname, result_callback, index)
            return
        self._start_recording(None, rname, result_callback, index)

    def _start_recording(self, result, rname, result_callback, index):
        if rname == None:
            command = 'R %s %s %s' % ('%s-%d' % (self.call_id, index), self.from_tag, self.to_tag)
            return self.rtp_proxy_client.send_command(command, self.command_result, result_callback)
        command = 'C %s %s.a %s %s' % ('%s-%d' % (self.call_id, index), rname, self.from_tag, self.to_tag)
        return self.rtp_proxy_client.send_command(command, self._start_recording1, \
          (rname, result_callback, index))

    def _start_recording1(self, result, args):
        rname, result_callback, index = args
        command = 'C %s %s.o %s %s' % ('%s-%d' % (self.call_id, index), rname, self.to_tag, self.from_tag)
        return self.rtp_proxy_client.send_command(command, self.command_result, result_callback)

    def command_result(self, result, result_callback):
        if result_callback != None:
            result_callback(result)

    def update_caller(self, remote_ip, remote_port, result_callback, options = '', index = 0, *callback_parameters):
        command = 'U'
        self.max_index = max(self.max_index, index)
        if self.rtp_proxy_client.sbind_supported and self.caller_raddress != None:
            if self.rtp_proxy_client.is_local:
                options += 'L%s' % self.global_config['_sip_tm'].l4r.getServer( \
                  self.caller_raddress).laddress[0]
            else:
                options += 'R%s' % self.caller_raddress[0]
        command += options
        command += ' %s %s %d %s' % ('%s-%d' % (self.call_id, index), remote_ip, remote_port, self.from_tag)
        if self.caller_session_exists:
            command += ' %s' % self.to_tag
        if self.notify_socket != None and index == 0 and \
          self.rtp_proxy_client.tnot_supported:
            command += ' %s %s' % (self.notify_socket, self.notify_tag)
        self.rtp_proxy_client.send_command(command, self.update_result, (result_callback, 'caller', callback_parameters))

    def update_callee(self, remote_ip, remote_port, result_callback, options = '', index = 0, *callback_parameters):
        command = 'U'
        self.max_index = max(self.max_index, index)
        if self.rtp_proxy_client.sbind_supported and self.callee_raddress != None:
            if self.rtp_proxy_client.is_local:
                options += 'L%s' % self.global_config['_sip_tm'].l4r.getServer( \
                  self.callee_raddress).laddress[0]
            else:
                options += 'R%s' % self.callee_raddress[0]
        command += options
        command += ' %s %s %d %s %s' % ('%s-%d' % (self.call_id, index), remote_ip, remote_port, self.to_tag, self.from_tag)
        if self.notify_socket != None and index == 0 \
          and self.rtp_proxy_client.tnot_supported:
            command += ' %s %s' % (self.notify_socket, self.notify_tag)
        self.rtp_proxy_client.send_command(command, self.update_result, (result_callback, 'callee', callback_parameters))

    def update_result(self, result, args):
        result_callback, face, callback_parameters = args
        if face == 'caller':
            self.caller_session_exists = True
        else:
            self.callee_session_exists = True
        if result == None:
            result_callback(None, *callback_parameters)
            return
        t1 = result.split()
        rtpproxy_port = int(t1[0])
        if rtpproxy_port == 0:
            result_callback(None, *callback_parameters)
        family = 'IP4'
        if len(t1) > 1:
            rtpproxy_address = t1[1]
            if len(t1) > 2 and t1[2] == '6':
                family = 'IP6'
        else:
            rtpproxy_address = self.rtp_proxy_client.proxy_address
        result_callback((rtpproxy_address, rtpproxy_port, family), *callback_parameters)

    def delete(self):
        while self.max_index >= 0:
            command = 'D %s %s %s' % ('%s-%d' % (self.call_id, self.max_index), self.from_tag, self.to_tag)
            self.rtp_proxy_client.send_command(command)
            self.max_index -= 1

    def on_caller_sdp_change(self, sdp_body, result_callback):
        self.on_xxx_sdp_change(self.update_caller, sdp_body, result_callback)

    def on_callee_sdp_change(self, sdp_body, result_callback):
        self.on_xxx_sdp_change(self.update_callee, sdp_body, result_callback)

    def on_xxx_sdp_change(self, update_xxx, sdp_body, result_callback):
        sects = []
        try:
            sdp_body.parse()
        except Exception, exception:
            print datetime.now(), 'can\'t parse SDP body: %s:' % str(exception)
            print '-' * 70
            print_exc(file = sys.stdout)
            print '-' * 70
            print sdp_body.content
            print '-' * 70
            sys.stdout.flush()
            return
        for i in range(0, len(sdp_body.content.sections)):
            sect = sdp_body.content.sections[i]
            if sect.m_header.transport.lower() not in ('udp', 'udptl', 'rtp/avp'):
                continue
            sects.append(sect)
        if len(sects) == 0:
            sdp_body.needs_update = False
            result_callback(sdp_body)
            return
        formats = sects[0].m_header.formats
        if update_xxx == self.update_caller:
            if len(formats) > 1:
                self.caller_codecs = reduce(lambda x, y: str(x) + ',' + str(y), formats)
            else:
                self.caller_codecs = str(formats[0])
        else:
            if len(formats) > 1:
                self.callee_codecs = reduce(lambda x, y: str(x) + ',' + str(y), formats)
            else:
                self.callee_codecs = str(formats[0])
        for sect in sects:
            options = ''
            if sect.c_header.atype == 'IP6':
                options = '6'
            update_xxx(sect.c_header.addr, sect.m_header.port, self.xxx_sdp_change_finish, options, \
              sects.index(sect), sdp_body, sect, sects, result_callback)
        return

    def xxx_sdp_change_finish(self, address_port, sdp_body, sect, sects, result_callback):
        sect.needs_update = False
        if address_port != None:
            sect.c_header.atype = address_port[2]
            sect.c_header.addr = address_port[0]
            if sect.m_header.port != 0:
                sect.m_header.port = address_port[1]
        if len([x for x in sects if x.needs_update]) == 0:
            sdp_body.content.o_header = self.origin
            sdp_body.needs_update = False
            result_callback(sdp_body)

    def __del__(self):
        self.delete()
        self.rtp_proxy_client = None
