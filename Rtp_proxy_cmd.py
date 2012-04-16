# Copyright (c) 2012 Sippy Software, Inc. All rights reserved.
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

def extract_to_next_token(s, match, invert = False):
    i = 0
    while i < len(s):
        if (not invert and s[i] not in match) or \
          (invert and s[i] in match):
            break
        i += 1
    if i == 0:
        return ('', s)
    if i == len(s):
        return (s, '')
    return (s[:i], s[i:])

class UpdateLookupOpts(object):
    destination_ip = None
    codecs = None
    otherparams = None

    def __init__(self, s = None, *params):
        if s == None:
            self.destination_ip, self.codecs, self.otherparams = params
            return
        self.otherparams = ''
        while len(s) > 0:
            if s[0] == 'R':
                val, s = extract_to_next_token(s[1:], ('1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '.'))
                val = val.strip()
                if len(val) > 0:
                    self.destination_ip = val
            elif s[0] == 'c':
                val, s = extract_to_next_token(s[1:], ('1', '2', '3', '4', '5', '6', '7', '8', '9', '0', ','))
                val = val.strip()
                if len(val) > 0:
                    self.codecs = [int(x) for x in val.split(',')]
            else:
                val, s = extract_to_next_token(s, ('c', 'R'), True)
                if len(val) > 0:
                    self.otherparams += val

    def __str__(self):
        s = ''
        if self.destination_ip != None:
            s = '%sR%s' % (s, self.destination_ip)
        if self.codecs != None:
            s = s + 'c'
            for codec in self.codecs:
                s = '%s%s,' % (s, codec)
            s = s[:-1]
        if self.otherparams != None and len(self.otherparams) > 0:
            s = s + self.otherparams
        return s

class Rtp_proxy_cmd(object):
    type = None
    ul_opts = None
    command_opts = None
    call_id = None
    args = None

    def __init__(self, cmd):
        self.type = cmd[0].upper()
        if self.type in ('U', 'L', 'D', 'P', 'S', 'R', 'C', 'Q'):
            command_opts, self.call_id, self.args = cmd.split(None, 2)
            if self.type in ('U', 'L'):
                self.ul_opts = UpdateLookupOpts(command_opts[1:])
            else:
                self.command_opts = command_opts[1:]
        else:
            self.command_opts = cmd[1:]

    def __str__(self):
        s = self.type
        if self.ul_opts != None:
            s += str(self.ul_opts)
        elif self.command_opts != None:
            s += self.command_opts
        if self.call_id != None:
            s = '%s %s' % (s, self.call_id)
        if self.args != None:
            s = '%s %s' % (s, self.args)
        return s
