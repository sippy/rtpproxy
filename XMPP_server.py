#!/usr/local/bin/python
# Copyright (c) 2012 Sippy Software, Inc. All rights reserved.
#
# Warning: This computer program is protected by copyright law and
# international treaties. Unauthorized reproduction or distribution of this
# program, or any portion of it, may result in severe civil and criminal
# penalties, and will be prosecuted under the maximum extent possible under
# law.
#
# $Id: XMPP_server.py,v 1.9 2012/09/12 11:25:35 bamby Exp $

import select
import iksemel
import threading
import base64
import datetime, time
import traceback, sys, os
from select import poll, POLLIN
from twisted.internet import reactor

MAX_WORKERS = 10

class Worker(iksemel.Stream):
    def __init__(self, owner, id):
        self.__owner = owner
        self.__id = id
        self.__reconnect = True
        iksemel.Stream.__init__(self)
        rx_thr = threading.Thread(target = self.run_rx)
        rx_thr.setDaemon(True)
        tx_thr = threading.Thread(target = self.run_tx)
        tx_thr.setDaemon(True)
        rx_thr.start()
        tx_thr.start()

    def on_xml(self, *args):
        pass

    def on_stanza(self, doc):
        if doc.name() == 'incoming_packet':
            data = base64.b64decode(doc.get('msg'))
            reactor.callFromThread(self.__owner.handle_read, data, (doc.get('src_addr'), int(doc.get('src_port'))))

    def run_rx(self):
        pollobj = poll()
        while True:
            if self.__owner._shutdown:
                return
            if self.__reconnect:
                time.sleep(0.1)
                continue
            try:
                pollobj.register(self.fileno(), POLLIN)
                pollret = dict(pollobj.poll())
                if pollret.get(self.fileno(), 0) & POLLIN == 0:
                    continue
                self.recv()
            except:
                print datetime.datetime.now(), 'XMPP_server: unhandled exception when processing incoming data'
                print '-' * 70
                traceback.print_exc(file = sys.stdout)
                print '-' * 70
                sys.stdout.flush()
                self.__reconnect = True
                self.__owner._wi_available.acquire()
                self.__owner._wi_available.notifyAll()
                self.__owner._wi_available.release()
                time.sleep(0.1)


    def run_tx(self):
        try:
            self.__run_tx()
        except:
            print datetime.datetime.now(), 'XMPP_server: unhandled exception when processing outgoing data'
            print '-' * 70
            traceback.print_exc(file = sys.stdout)
            print '-' * 70
            sys.stdout.flush()

    def __run_tx(self):
        buf = ''
        first_time = True
        while True:
            if self.__owner._shutdown:
                return
            if self.__reconnect:
                if not first_time:
                    time.sleep(0.1)
                    first_time = False
                buf = '' # throw away unsent data
            if len(buf) == 0:
                data, addr = None, None
                self.__owner._wi_available.acquire()
                while len(self.__owner._wi) == 0 and not self.__reconnect:
                    self.__owner._wi_available.wait()
                    if self.__owner._shutdown:
                        os.close(self.fileno())
                        self.__owner._wi_available.release()
                        return
                if len(self.__owner._wi) > 0:
                    data, addr = self.__owner._wi.pop(0)
                self.__owner._wi_available.release()
                if self.__reconnect:
                    #try:
                    #    os.close(self.fileno())
                    #except:
                    #    pass
                    try:
                        self.connect(jid=iksemel.JID('127.0.0.1'), tls=False, port=22223)
                        os.write(self.fileno(), '<b2bua_slot id="%s"/>' % self.__id)
                    except iksemel.StreamError:
                        continue
                    except:
                        traceback.print_exc(file = sys.stdout)
                        sys.stdout.flush()
                        continue
                    self.__reconnect = False
                if data == None:
                    continue
                dst_addr, dst_port = addr
                buf = '<outgoing_packet dst_addr="%s" dst_port="%s" ' \
                                'src_addr="%s" src_port="%s" ' \
                                'msg="%s"/>' % (dst_addr, dst_port, 
                                                self.__owner.laddress[0], self.__owner.laddress[1], 
                                                base64.b64encode(data))
            if self.__owner._shutdown:
                os.close(self.fileno())
                return
            try:
                sent = os.write(self.fileno(), buf)
                buf = buf[sent:]
            except IOError:
                # wait for reconnect
                self.__reconnect = True
            except OSError:
                # wait for reconnect
                self.__reconnect = True

class XMPP_server(object):
    def __init__(self, global_config, address, data_callback):
        self._shutdown = False
        self.laddress = address
        self.__data_callback = data_callback
        self._wi_available = threading.Condition()
        self._wi = []
        id = global_config.get('xmpp_b2bua_id', 5061)
        for i in range(0, MAX_WORKERS):
            Worker(self, id)

    def handle_read(self, data, address):
        if len(data) > 0 and self.__data_callback != None:
            try:
                self.__data_callback(data, address, self)
            except:
                print datetime.datetime.now(), 'XMPP_server: unhandled exception when processing incoming data'
                print '-' * 70
                traceback.print_exc(file = sys.stdout)
                print '-' * 70
                sys.stdout.flush()

    def send_to(self, data, address):
        self._wi_available.acquire()
        self._wi.append((data, address))
        self._wi_available.notify()
        self._wi_available.release()

    def shutdown(self):
        self._shutdown = True
        self._wi_available.acquire()
        self._wi_available.notifyAll()
        self._wi_available.release()
