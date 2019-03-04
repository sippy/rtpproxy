# Copyright (c) 2017 Sippy Software, Inc. All rights reserved.
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

from datetime import datetime
from traceback import print_exception, extract_stack, print_list, format_exception_only
import sys

SEPT = '-' * 70 + '\n'

class StdException(Exception):
    traceback = None

    def __init__(self, *args):
        pin_exception(self, 2)
        super(self.__class__, self).__init__(*args)

def dump_exception(msg, f = sys.stdout, extra = None):
    exc_type, exc_value, exc_traceback = sys.exc_info()
    if isinstance(exc_value, StdException):
        cus_traceback = exc_value.traceback
    else:
        if hasattr(exc_value, 'traceback'):
            exc_traceback = exc_value.traceback
        cus_traceback = None
    f.write('%s %s:\n' % (datetime.now(), msg))
    f.write(SEPT)
    if cus_traceback != None:
        f.write('Traceback (most recent call last):\n')
        print_list(cus_traceback, file = f)
        f.write(format_exception_only(exc_type, exc_value)[0])
    else:
        print_exception(exc_type, exc_value, exc_traceback, file = f)
    f.write(SEPT)
    if extra != None:
        f.write(extra)
        f.write(SEPT)
    f.flush()

def pin_exception(exc_value, undepth = 1):
    if not hasattr(exc_value, 'traceback'):
        exc_value.traceback = sys.exc_info()[2]
    elif exc_value.traceback == None:
        exc_value.traceback = extract_stack()[:-undepth]

if __name__ == '__main__':
    for f in sys.stdout, sys.stderr:
        for etype in Exception, StdException:
            try:
                raise etype("test: %s" % str(etype))
            except:
                dump_exception("test ok", f = f)
            try:
                try:
                    raise etype("test: %s" % str(etype))
                except Exception as e:
                    raise e
            except:
                dump_exception("test ok", f = f)
            try:
                try:
                    raise etype("test: %s" % str(etype))
                except Exception as e:
                    pin_exception(e)
                    raise e
            except:
                dump_exception("test ok", f = f)
