# Copyright (c) 2003-2005 Maxim Sobolev. All rights reserved.
# Copyright (c) 2006-2015 Sippy Software, Inc. All rights reserved.
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

from __future__ import print_function

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
    local_ip = None
    codecs = None
    otherparams = None
    remote_ip = None
    remote_port = None
    from_tag = None
    to_tag = None
    notify_socket = None
    notify_tag = None

    def __init__(self, s = None, *params):
        if s == None:
            self.destination_ip, self.local_ip, self.codecs, self.otherparams = params
            return
        self.otherparams = ''
        while len(s) > 0:
            if s[0] == 'R':
                val, s = extract_to_next_token(s[1:], ('1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '.'))
                val = val.strip()
                if len(val) > 0:
                    self.destination_ip = val
            if s[0] == 'L':
                val, s = extract_to_next_token(s[1:], ('1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '.'))
                val = val.strip()
                if len(val) > 0:
                    self.local_ip = val
            elif s[0] == 'c':
                val, s = extract_to_next_token(s[1:], ('1', '2', '3', '4', '5', '6', '7', '8', '9', '0', ','))
                val = val.strip()
                if len(val) > 0:
                    self.codecs = [int(x) for x in val.split(',')]
            else:
                val, s = extract_to_next_token(s, ('c', 'R'), True)
                if len(val) > 0:
                    self.otherparams += val

    def getstr(self, call_id, swaptags = False):
        s = ''
        if self.destination_ip != None:
            s += 'R%s' % (self.destination_ip,)
        if self.local_ip != None:
            s += 'L%s' % (self.local_ip,)
        if self.codecs != None:
            s += 'c'
            for codec in self.codecs:
                s += '%s,' % (codec,)
            s = s[:-1]
        if self.otherparams != None and len(self.otherparams) > 0:
            s += self.otherparams
        s = '%s %s' % (s, call_id)
        if self.remote_ip != None:
            s = '%s %s' % (s, self.remote_ip)
        if self.remote_port != None:
            s = '%s %s' % (s, self.remote_port)
        if not swaptags:
            from_tag, to_tag = (self.from_tag, self.to_tag)
        else:
            if self.to_tag == None:
                raise Exception('UpdateLookupOpts::getstr(swaptags = True): to_tag is not set')
            to_tag, from_tag = (self.from_tag, self.to_tag)
        if self.from_tag != None:
            s = '%s %s' % (s, self.from_tag)
        if self.to_tag != None:
            s = '%s %s' % (s, self.to_tag)
        if self.notify_socket != None:
            s = '%s %s' % (s, self.notify_socket)
        if self.notify_tag != None:
            s = '%s %s' % (s, self.notify_tag)
        return s

class Rtp_proxy_cmd(object):
    type = None
    ul_opts = None
    command_opts = None
    call_id = None
    args = None
    nretr = None

    def __init__(self, cmd):
        self.type = cmd[0].upper()
        if self.type in ('U', 'L', 'D', 'P', 'S', 'R', 'C', 'Q'):
            command_opts, self.call_id, args = cmd.split(None, 2)
            if self.type in ('U', 'L'):
                self.ul_opts = UpdateLookupOpts(command_opts[1:])
                self.ul_opts.remote_ip, self.ul_opts.remote_port, args = args.split(None, 2)
                args = args.split(None, 1)
                self.ul_opts.from_tag = args[0]
                if len(args) > 1:
                    args = args[1].split(None, 2)
                    if len(args) == 1:
                        self.ul_opts.to_tag = args[0]
                    elif len(args) == 2:
                        self.ul_opts.notify_socket, self.ul_opts.notify_tag = args
                    else:
                        self.ul_opts.to_tag, self.ul_opts.notify_socket, self.ul_opts.notify_tag = args
            else:
                self.args = args
                self.command_opts = command_opts[1:]
        elif self.type in ('G',):
            if not cmd[1].isspace():
                cparts = cmd[1:].split(None, 1)
                if len(cparts) > 1:
                    self.command_opts, self.args = cparts
                else:
                    self.command_opts = cparts[0]
            else:
                self.args = cmd[1:].strip()
        else:
            self.command_opts = cmd[1:]

    def __str__(self):
        s = self.type
        if self.ul_opts != None:
            s += self.ul_opts.getstr(self.call_id)
        else:
            if self.command_opts != None:
                s += self.command_opts
            if self.call_id != None:
                s = '%s %s' % (s, self.call_id)
        if self.args != None:
            s = '%s %s' % (s, self.args)
        return s

class Rtpp_stats(object):
    spookyprefix = ''
    verbose = False

    def __init__(self, snames):
        all_types = []
        for sname in snames:
            if sname != 'total_duration':
                stype = int
            else:
                stype = float
            self.__dict__[self.spookyprefix + sname] = stype()
            all_types.append(stype)
        self.all_names = tuple(snames)
        self.all_types = tuple(all_types)

    def __iadd__(self, other):
        for sname in self.all_names:
            aname = self.spookyprefix + sname
            self.__dict__[aname] += other.__dict__[aname]
        return self

    def parseAndAdd(self, rstr):
        rparts = rstr.split(None, len(self.all_names) - 1)
        for i in range(0, len(self.all_names)):
            stype = self.all_types[i]
            rval = stype(rparts[i])
            aname = self.spookyprefix + self.all_names[i]
            self.__dict__[aname] += rval

    def __str__(self):
        aname = self.spookyprefix + self.all_names[0]
        if self.verbose:
            rval = '%s=%s' % (self.all_names[0], str(self.__dict__[aname]))
        else:
            rval = str(self.__dict__[aname])
        for sname in self.all_names[1:]:
            aname = self.spookyprefix + sname
            if self.verbose:
                rval += ' %s=%s' % (sname, str(self.__dict__[aname]))
            else:
                rval += ' %s' % str(self.__dict__[aname])
        return rval

if __name__ == '__main__':
    rc = Rtp_proxy_cmd('G nsess_created total_duration')
    print(rc)
    print(rc.args)
    print(rc.command_opts)
    rc = Rtp_proxy_cmd('Gv nsess_created total_duration')
    print(rc)
    print(rc.args)
    print(rc.command_opts)
