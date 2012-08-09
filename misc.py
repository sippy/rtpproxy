#!/usr/local/bin/python
#
# Copyright (c) 2003-2005 Maxim Sobolev. All rights reserved.
# Copyright (c) 2006-2012 Sippy Software, Inc. All rights reserved.
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

import os, sys

def daemonize(logfile = None):
    # Fork once
    if os.fork() != 0:
        os._exit(0)
    # Create new session
    os.setsid()
    if os.fork() != 0:
        os._exit(0)
    os.chdir('/')
    fd = os.open('/dev/null', os.O_RDWR)
    os.dup2(fd, sys.__stdin__.fileno())
    if logfile != None:
        fake_stdout = file(logfile, 'a', 1)
        sys.stdout = fake_stdout
        sys.stderr = fake_stdout
        fd = fake_stdout.fileno()
    os.dup2(fd, sys.__stdout__.fileno())
    os.dup2(fd, sys.__stderr__.fileno())
    if logfile == None:
        os.close(fd)
