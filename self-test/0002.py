import sys
sys.path.append('..')

from SdpBody import SdpBody

s_body = file('0002.sip').read()
body = SdpBody(s_body)
print str(body)
