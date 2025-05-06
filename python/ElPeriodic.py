# Copyright (c) 2006-2019 Sippy Software, Inc. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from ctypes import cdll, c_double, c_void_p, c_int, c_long, Structure, \
  pointer, POINTER, CFUNCTYPE, byref, py_object, PYFUNCTYPE
from ctypes import pythonapi
from math import modf
from functools import partial
import os, sys, site, sysconfig

class timespec(Structure):
    _fields_ = [
        ('tv_sec', c_long),
        ('tv_nsec', c_long)
    ]

_esuf = sysconfig.get_config_var('EXT_SUFFIX')
if not _esuf:
    _esuf = '.so'
try:
    import pathlib
    _ROOT = str(pathlib.Path(__file__).parent.absolute())
except ImportError:
    _ROOT = os.path.abspath(os.path.dirname(__file__))
#print('ROOT: ' + str(_ROOT))
modloc = site.getsitepackages()
modloc.insert(0, os.path.join(_ROOT, ".."))
for p in modloc:
   try:
       #print("Trying %s" % os.path.join(p, '_elperiodic' + _esuf))
       _elpl = cdll.LoadLibrary(os.path.join(p, '_elperiodic' + _esuf))
   except:
       continue
   break
else:
   _elpl = cdll.LoadLibrary('libelperiodic.so')
_elpl.prdic_init.argtypes = [c_double, c_double]
_elpl.prdic_init.restype = c_void_p
_elpl.prdic_procrastinate.argtypes = [c_void_p,]
_elpl.prdic_free.argtypes = [c_void_p,]
_elpl.prdic_addband.argtypes = [c_void_p, c_double]
_elpl.prdic_addband.restype = c_int
_elpl.prdic_useband.argtypes = [c_void_p, c_int]
_elpl.prdic_set_epoch.argtypes = [c_void_p, POINTER(timespec)]
_elpl_cbtype = PYFUNCTYPE(None, py_object)
_elpl.prdic_call_from_thread.argtypes = [c_void_p, _elpl_cbtype, py_object]
_elpl.prdic_call_from_thread.restype = c_int
_elpl.prdic_CFT_enable.argtypes = [c_void_p, c_int]
_elpl.prdic_CFT_enable.restype = c_int

class _elpl_cb(object):
    def __init__(self, handler, args):
        self.handler = handler
        self.args = args

#    def __del__(self):
#        print('_ptrcall.__del__(%s)' % (self,))

#h = _elpl.prdic_init(200.0, 0.0)
#sleep(20)

def _elpl_ptrcall_safe(cbobj):
#    print(f'_ptrcall({cbobj=})')
    if pythonapi == None:
        # Happens when interpreter is being shut down
        return
    try:
        cbobj()
    except Exception as e:
        sys.stderr.write('call_from_thread %s%s failed: %s\n' % (cbobj.handler, cbobj.args, e))
        sys.stderr.flush()
    pyo = py_object(cbobj)
    pythonapi.Py_DecRef(pyo)

def _elpl_ptrcall_bare(cbobj):
    if pythonapi == None:
        # Happens when interpreter is being shut down
        return
    try:
        cbobj()
    except Exception as e:
        pyo = py_object(cbobj)
        pythonapi.Py_DecRef(pyo)
        raise e
    pyo = py_object(cbobj)
    pythonapi.Py_DecRef(pyo)

class CFTRuntimeError(RuntimeError): pass

class ElPeriodic(object):
    _hndl = None
    _elpl = None
    _cbfunc = None

    def __init__(self, freq, offst = 0.0):
        self._elpl = _elpl
        _hndl = self._elpl.prdic_init(freq, offst)
        if not bool(_hndl):
            raise Exception('prdic_init() failed')
        self._hndl = _hndl

    def procrastinate(self):
        self._elpl.prdic_procrastinate(self._hndl)

    def addband(self, freq_hz):
        r = self._elpl.prdic_addband(self._hndl, freq_hz)
        return int(r)

    def useband(self, bandnum):
        self._elpl.prdic_useband(self._hndl, c_int(bandnum))

    def set_epoch(self, dtime):
        ts = timespec()
        tv_frac, tv_sec = modf(dtime)
        ts.tv_sec = int(tv_sec)
        ts.tv_nsec = int(tv_frac * 1e+09)
        self._elpl.prdic_set_epoch(self._hndl, byref(ts))

    def __del__(self):
        if self._hndl is not None:
            self._elpl.prdic_free(self._hndl)
            self._hndl = None

    def CFT_enable(self, signum, ptrcall_class = _elpl_ptrcall_bare):
        if pythonapi == None:
            raise Exception('pythonapi is None')
        r = self._elpl.prdic_CFT_enable(self._hndl, c_int(signum))
        if r != 0:
            raise Exception('prdic_CFT_enable() = %d' % (r,))
        self._cbfunc = _elpl_cbtype(ptrcall_class)

    def call_from_thread(self, handler, *args, **kw_args):
        if not bool(self._hndl):
            raise CFTRuntimeError("self._hndl is NULL, interpreter shutdown?")
        cbobj = partial(handler, *args, **kw_args)
        pyo = py_object(cbobj)
        pythonapi.Py_IncRef(pyo)
        rval = self._elpl.prdic_call_from_thread(self._hndl, \
          self._cbfunc, cbobj)
        if rval != 0:
            pythonapi.Py_DecRef(pyo)
            raise CFTRuntimeError('call_from_thread() = %d' % (rval,))
