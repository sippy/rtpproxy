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

from SQLTransactionManager import SQLTransactionManager
from time import time

class IVoiSysAuthorisation(object):
    def __init__(self, global_config):
        dsn = 'mysql://sbcfront:gb19!lDLn2#)F$NFbd2*@sbcdb1.pennytel.com/sbc'
        self.sql_tm = SQLTransactionManager(dsn, nworkers = 4, lazy_connect = True)

    def do_auth(self, username, res_cb, *cb_args):
        self.sql_tm.sendQuery(('SELECT password, outbound_proxy, domain, ' \
          'altpassword, use_alt_password FROM SBC_Reg_Config ' \
          'WHERE account_number = \'%s\'' % username), self._process_result, 0, False, None,
          res_cb, cb_args)

    def _process_result(self, results, exceptions, res_cb, cb_args):
        print results, exceptions
        if exceptions[0] != None or len(results[0]) == 0:
            res_cb(None, *cb_args)
        else:
            password, outbound_proxy, domain, altpassword, use_alt_password = results[0][0]
            if use_alt_password == 0:
                altpassword = password
            res_cb((password, altpassword, (outbound_proxy, 5060), domain), *cb_args)
