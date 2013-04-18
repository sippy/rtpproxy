import sys
sys.path.append('..')

from SdpBody import SdpBody

s_body = file('0000.sip').read()
body = SdpBody(s_body)
print body.localStr('1.2.3.4', 12345)
