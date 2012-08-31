from SipConf import SipConf
from SipAuthorization import SipAuthorization
from SipProxyAuthorization import SipProxyAuthorization
from SipHeader import SipHeader

class RegistrationB2B(object):
    global_config = None
    orig_req = None
    username = None
    password = None
    req = None

    def __init__(self, global_config, orig_req):
        self.global_config = global_config
        self.orig_req = orig_req

    def proxyReq(self, destination, domain, username, password):
        self.username = username
        self.password = password
        orig_cseq = self.orig_req.getHFBody('cseq').getCSeqNum()
        self.req = self.orig_req.genRequest('REGISTER', orig_cseq * 2)
        self.req.setTarget(destination)
        via0 = SipHeader(name = 'via')
        via0.getBody().genBranch()
        self.req.replaceHeader(self.req.getHF('via'), via0)
        contact = self.orig_req.getHF('contact')
        if not contact.getBody().asterisk:
            contact = contact.getCopy()
            curl = contact.getBody().getUrl()
            fakeusername = '%s__%d_%s' % (curl.host.replace('.', '_'), curl.getPort(), curl.username)
            curl.username = fakeusername
            curl.host, curl.port = (SipConf.my_address, SipConf.my_port)
        self.req.appendHeader(contact)
        ruri = self.req.getRURI()
        ruri.host = domain
        from_h = self.req.getHFBody('from').getUrl()
        from_h.host = domain
        to_h = self.req.getHFBody('to').getUrl()
        to_h.host = domain
        to_h.username = username
        allows = self.orig_req.getHFs('allow')
        if len(allows) > 0:
            self.req.appendHeader(allows[0].getCopy())
        supporteds = self.orig_req.getHFs('supported')
        if len(supporteds) > 0:
            self.req.appendHeader(supporteds[0].getCopy())
        if self.orig_req.countHFs('user-agent') > 0:
            orig_user_agent = self.orig_req.getHFBody('user-agent').name
            user_agent = self.req.getHFBody('user-agent')
            user_agent.name = '%s:%s' % (user_agent.name, orig_user_agent)
        self.global_config['_sip_tm'].newTransaction(self.req, self.recvResponse)
        return (None, None, None)

    def recvResponse(self, resp):
        if resp.scode == 407 and resp.countHFs('proxy-authenticate') != 0:
            challenge = resp.getHFBody('proxy-authenticate')
            auth = SipProxyAuthorization(realm = challenge.getRealm(), nonce = challenge.getNonce(), \
              method = 'REGISTER', uri = str(self.req.getRURI()), username = self.username, \
              password = self.password)
            self.req.delHFs('proxy-authorization')
            self.req.appendHeader(SipHeader(body = auth))
            self.req.getHFBody('cseq').incCSeqNum()
            self.req.getHFBody('from').genTag()
            self.req.getHFBody('via').genBranch()
            self.global_config['_sip_tm'].newTransaction(self.req, self.recvResponse)
            return None
 
        if resp.scode == 401 and resp.countHFs('www-authenticate') != 0:
            challenge = resp.getHFBody('www-authenticate')
            auth = SipAuthorization(realm = challenge.getRealm(), nonce = challenge.getNonce(), \
              method = 'REGISTER', uri = str(self.req.getRURI()), username = self.username, \
              password = self.password)
            self.req.delHFs('authorization')
            self.req.appendHeader(SipHeader(body = auth))
            self.req.getHFBody('cseq').incCSeqNum()
            self.req.getHFBody('from').genTag()
            self.req.getHFBody('via').genBranch()
            self.global_config['_sip_tm'].newTransaction(self.req, self.recvResponse)
            return None

        my_resp = self.orig_req.genResponse(resp.scode, resp.reason)
        supporteds = resp.getHFs('supported')
        if len(supporteds) > 0:
            my_resp.appendHeader(supporteds[0])
        portabillings = resp.getHFs('portabilling')
        if len(portabillings) > 0:
            my_resp.appendHeader(portabillings[0])
        contacts = resp.getHFs('contact')
        for contact in contacts:
            cbody = contact.getBody()
            if not cbody.asterisk:
                curl = cbody.getUrl()
                if curl.username != None and curl.username.find('__') != -1:
                    host, port_username = curl.username.split('__', 1)
                    port, curl.username = port_username.split('_', 1)
                    curl.host = host.replace('_', '.')
                    curl.port = int(port)
            my_resp.appendHeader(contact)
        for expire in resp.getHFs('expires'):
            my_resp.appendHeader(expire)
        self.global_config['_sip_tm'].sendResponse(my_resp)
        if resp.scode > 199:
            self.global_config = None
            self.orig_req = None
            self.req = None
