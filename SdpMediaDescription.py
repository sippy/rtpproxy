
from SdpConnecton import SdpConnecton
from SdpMedia import SdpMedia
from SdpGeneric import SdpGeneric

f_types = {'m':SdpMedia, 'i':SdpGeneric, 'c':SdpConnecton, 'b':SdpGeneric, \
  'k':SdpGeneric}

class SdpMediaDescription(object):
    m_header = None
    i_header = None
    c_header = None
    b_header = None
    k_header = None
    a_headers = None
    all_headers = ('m', 'i', 'c', 'b', 'k')

    def __init__(self, cself = None):
        if cself != None:
            for header_name in [x + '_header' for x in self.all_headers]:
                try:
                    setattr(self, header_name, getattr(cself, header_name).getCopy())
                except AttributeError:
                    pass
            self.a_headers = [x for x in cself.a_headers]
            return
        self.a_headers = []

    def __str__(self):
        s = ''
        for name in self.all_headers:
            header = getattr(self, name + '_header')
            if header != None:
                s += '%s=%s\r\n' % (name, str(header))
        for header in self.a_headers:
            s += 'a=%s\r\n' % str(header)
        return s

    def noCStr(self):
        s = ''
        for name in self.all_headers:
            if name == 'c':
                continue
            header = getattr(self, name + '_header')
            if header != None:
                s += '%s=%s\r\n' % (name, str(header))
        for header in self.a_headers:
            s += 'a=%s\r\n' % str(header)
        return s

    def __iadd__(self, other):
        self.addHeader(*other.strip().split('=', 1))
        return self

    def getCopy(self):
        return SdpMediaDescription(cself = self)

    def addHeader(self, name, header):
        if name == 'a':
            self.a_headers.append(header)
        else:
            setattr(self, name + '_header', f_types[name](header))
