# Copyright (c) 2003-2005 Maxim Sobolev. All rights reserved.
# Copyright (c) 2006-2009 Sippy Software, Inc. All rights reserved.
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

from Timeout import Timeout

from time import time
from hashlib import md5
from random import random

class Rtp_proxy_client(object):
    worker = None
    address = None
    online = False
    copy_supported = False
    stat_supported = False
    tnot_supported = False
    sbind_supported = False
    shutdown = False
    proxy_address = None
    caps_done = False

    def __init__(self, global_config, address):
        self.address = address
        self.heartbeat()

    def caps_query1(self, result):
        if self.shutdown:
            self.worker.shutdown()
            return
        if result != '1':
            if result != None:
                self.copy_supported = False
                self.stat_supported = False
                self.tnot_supported = False
                self.sbind_supported = False
                self.caps_done = True
            Timeout(self.heartbeat, 60)
            return
        self.copy_supported = True
        self.send_command('VF 20080403', self.caps_query2)

    def caps_query2(self, result):
        if self.shutdown:
            self.worker.shutdown()
            return
        if result != None:
            if result == '1':
                self.stat_supported = True
                self.send_command('VF 20081224', self.caps_query3)
                return
            else:
                self.stat_supported = False
                self.tnot_supported = False
                self.sbind_supported = False
                self.caps_done = True
        Timeout(self.heartbeat, 60)

    def caps_query3(self, result):
        if self.shutdown:
            self.worker.shutdown()
            return
        if result != None:
            if result == '1':
                self.tnot_supported = True
                self.send_command('VF 20090810', self.caps_query4)
                return
            else:
                self.tnot_supported = False
                self.sbind_supported = False
                self.caps_done = True
        Timeout(self.heartbeat, 60)

    def caps_query4(self, result):
        if self.shutdown:
            self.worker.shutdown()
            return
        if result != None:
            if result == '1':
                self.sbind_supported = True
            else:
                self.sbind_supported = False
            self.caps_done = True
        Timeout(self.heartbeat, 60)

    def heartbeat(self):
        self.send_command('V', self.heartbeat_reply)

    def heartbeat_reply(self, version):
        if self.shutdown:
            self.worker.shutdown()
            return
        if version == '20040107':
            self.online = True
            if not self.caps_done:
                self.send_command('VF 20071218', self.caps_query1)
                return
        else:
            self.online = False
        Timeout(self.heartbeat, 60)
