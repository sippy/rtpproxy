#!/usr/local/bin/python
#
# Copyright (c) 2009 Sippy Software, Inc. All rights reserved.
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

from ConfigParser import RawConfigParser
from SipConf import SipConf

SUPPORTED_OPTIONS = { \
 'acct_enable':       ('B', 'enable or disable Radius accounting'), \
 'precise_acct':      ('B', 'do Radius accounting with millisecond precision'), \
 'alive_acct_int':    ('I', 'interval for sending alive Radius accounting in ' \
                             'second (0 to disable alive accounting)'), \
 'config':            ('S', 'load configuration from file (path to file)'), \
 'auth_enable':       ('B', 'enable or disable Radius authentication'), \
 'b2bua_socket':      ('S', 'path to the B2BUA command socket or address to listen ' \
                             'for commands in the format "udp:host[:port]"'), \
 'digest_auth':       ('B', 'enable or disable SIP Digest authentication of ' \
                             'incoming INVITE requests'), \
 'foreground':        ('B', 'run in foreground'), \
 'hide_call_id':      ('B', 'do not pass Call-ID header value from ingress call ' \
                             'leg to egress call leg'), \
 'keepalive_ans':     ('I', 'send periodic "keep-alive" re-INVITE requests on ' \
                             'answering (ingress) call leg and disconnect a call ' \
                             'if the re-INVITE fails (period in seconds, 0 to ' \
                             'disable)'), \
 'keepalive_orig':    ('I', 'send periodic "keep-alive" re-INVITE requests on ' \
                             'originating (egress) call leg and disconnect a call ' \
                             'if the re-INVITE fails (period in seconds, 0 to ' \
                             'disable)'), \
 'logfile':           ('S', 'path to the B2BUA log file'), \
 'max_credit_time':   ('I', 'upper limit of session time for all calls in ' \
                             'seconds'), \
 'max_radiusclients': ('I', 'maximum number of Radius Client helper ' \
                             'processes to start'), \
 'pidfile':           ('S', 'path to the B2BUA PID file'), \
 'radiusclient.conf': ('S', 'path to the radiusclient.conf file'), \
 'sip_address':       ('S', 'local SIP address to listen for incoming SIP requests ' \
                             '("*", "0.0.0.0" or "::" to listen on all IPv4 ' \
                             'or IPv6 interfaces)'),
 'sip_port':          ('I', 'local UDP port to listen for incoming SIP requests'), \
 'start_acct_enable': ('B', 'enable start Radius accounting'), \
 'static_route':      ('S', 'static route for all SIP calls'), \
 'static_tr_in':      ('S', 'translation rule (regexp) to apply to all incoming ' \
                             '(ingress) destination numbers'), \
 'static_tr_out':     ('S', 'translation rule (regexp) to apply to all outgoing ' \
                             '(egress) destination numbers'), \
 'allowed_pts':       ('S', 'list of allowed media (RTP) IANA-assigned payload ' \
                             'types that the B2BUA will pass from input to ' \
                             'output, payload types not in this list will be ' \
                             'filtered out (comma separated list)'), \
 'pass_headers':      ('S', 'list of SIP header field names that the B2BUA will ' \
                             'pass from ingress call leg to egress call leg ' \
                             'unmodified (comma-separated list)'), \
 'accept_ips':        ('S', 'IP addresses that we will only be accepting incoming ' \
                             'calls from (comma-separated list). If the parameter ' \
                             'is not specified, we will accept from any IP and ' \
                             'then either try to authenticate if authentication ' \
                             'is enabled, or just let them to pass through'),
 'digest_auth_only':  ('B', 'only use SIP Digest method to authenticate ' \
                             'incoming INVITE requests. If the option is not ' \
                             'specified or set to "off" then B2BUA will try to ' \
                             'do remote IP authentication first and if that fails '
                             'then send a challenge and re-authenticate when ' \
                             'challenge response comes in'), \
 'rtp_proxy_clients': ('S', 'comma-separated list of paths or addresses of the ' \
                             'RTPproxy control socket. Address in the format ' \
                             '"udp:host[:port]" (comma-separated list)')}

class MyConfigParser(RawConfigParser):
    default_section = None
    _private_keys = None

    def __init__(self, default_section = 'general'):
        self.default_section = default_section
        self._private_keys = {}
        RawConfigParser.__init__(self)
        self.add_section(self.default_section)

    def __getitem__(self, key):
        if key.startswith('_'):
            return self._private_keys[key]
        value_type  = SUPPORTED_OPTIONS[key][0]
        if value_type  == 'B':
            return self.getboolean(self.default_section, key)
        elif value_type == 'I':
            return self.getint(self.default_section, key)
        return self.get(self.default_section, key)

    def __setitem__(self, key, value):
        if key.startswith('_'):
            self._private_keys[key] = value
        else:
            self.set(self.default_section, key, str(value))
        return

    def has_key(self, key):
        return self.__contains__(key)

    def __contains__(self, key):
        if key.startswith('_'):
            return self._private_keys.has_key(key)
        return self.has_option(self.default_section, key)

    def get(self, *args):
        if len(args) == 1:
            return self.__getitem__(args[0])
        return RawConfigParser.get(self, *args)

    def getdefault(self, key, default_value):
        if self.__contains__(key):
            return self.__getitem__(key)
        return default_value

    def get_longopts(self):
        return tuple([x + '=' for x in SUPPORTED_OPTIONS.keys()])

    def read(self, fname):
        RawConfigParser.readfp(self, open(fname))
        for key in tuple(self.options(self.default_section)):
            self.check_and_set(key, RawConfigParser.get(self, \
              self.default_section, key), False)

    def check_and_set(self, key, value, compat = True):
        value = value.strip()
        if compat:
            if key == 'rtp_proxy_client':
                # XXX compatibility option
                if self.has_key('_rtp_proxy_clients'):
                    self['_rtp_proxy_clients'].append(value)
                else:
                    self['_rtp_proxy_clients'] = [value,]
                if self.has_key('rtp_proxy_clients'):
                    self['rtp_proxy_clients'] += ',' + value
                else:
                    self['rtp_proxy_clients'] = value
                return
            elif key == 'pass_header':
                # XXX compatibility option
                if self.has_key('_pass_headers'):
                    self['_pass_headers'].append(value)
                else:
                    self['_pass_headers'] = [value,]
                if self.has_key('pass_headers'):
                    self['pass_headers'] += ',' + value
                else:
                    self['pass_headers'] = value
                return

        value_type  = SUPPORTED_OPTIONS[key][0]
        if value_type == 'B':
            if value.lower() not in self._boolean_states:
                raise ValueError, 'Not a boolean: %s' % value
        elif value_type == 'I':
            _value = int(value)
        if key in ('keepalive_ans', 'keepalive_orig'):
            if _value < 0:
                raise ValueError, 'keepalive_ans should be non-negative'
        elif key == 'max_credit_time':
            if _value <= 0:
                raise ValueError, 'max_credit_time should be more than zero'
        elif key == 'allowed_pts':
            self['_allowed_pts'] = [int(x) for x in value.split(',')]
        elif key in ('accept_ips', 'pass_headers', 'rtp_proxy_clients'):
            self['_' + key] = [x.strip() for x in value.split(',')]
        elif key == 'sip_address':
            if 'my' in dir(value):
                self['_sip_address'] = value
                value = '*'
            elif value in ('*', '0.0.0.0', '::'):
                self['_sip_address'] = SipConf.my_address
            else:
                self['_sip_address'] = value
        elif key == 'sip_port':
            if _value <= 0 or _value > 65535:
                raise ValueError, 'sip_port should be in the range 1-65535'
            self['_sip_port'] = _value
        self[key] = value

    def options_help(self):
        supported_options = SUPPORTED_OPTIONS.items()
        supported_options.sort()
        for option, (value_type, helptext) in supported_options:
            if value_type == 'B':
                value = 'on/off'
            elif value_type == 'I':
                value = 'number'
            else:
                value = '"string"'
            print '--%s=%s\n\t%s\n' % (option, value, helptext)

if __name__ == '__main__':
    m = MyConfigParser()
    m['_foo'] = 'bar'
    m['b2bua_socket'] = 'bar1'
    m['acct_enable'] = True
    m['auth_enable'] = 'False'
    assert m.has_key('_foo')
    assert m['_foo'] == 'bar'
    assert m['b2bua_socket'] == 'bar1'
    assert m.get('_foo') == 'bar'
    assert m.get('b2bua_socket') == 'bar1'
    assert m.get('general', 'b2bua_socket') == 'bar1'
    assert m.get('acct_enable')
    assert not m.get('auth_enable')
    m.check_and_set('keepalive_ans', '15')
    assert m['keepalive_ans'] == 15
    m.check_and_set('pass_header', 'a')
    m.check_and_set('pass_header', 'b')
    assert m['pass_headers'] == 'a,b'
    assert m['_pass_headers'][0] == 'a'
    assert m['_pass_headers'][1] == 'b'
    m.check_and_set('accept_ips', '1.2.3.4, 5.6.7.8')
    assert m['accept_ips'] == '1.2.3.4, 5.6.7.8'
    assert m['_accept_ips'][0] == '1.2.3.4'
    assert m['_accept_ips'][1] == '5.6.7.8'
