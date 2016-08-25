from crypto_pb2 import crypto_request, AES_CM_128_HMAC_SHA1_80
from crypto_pb2 import km_inline, AES_CM_128_HMAC_SHA1_32, F8_128_HMAC_SHA1_80
from crypto_pb2 import UNENCRYPTED_SRTCP, UNENCRYPTED_SRTP

cro = crypto_request()
co = cro.offer
sinfo = co.session
sinfo.from_tag = 'from_tag1'
strm = co.streams.add()
strm.info.idx = 0
cat = strm.attributes.add()
cat.inb.tag = 1
cat.inb.suite = AES_CM_128_HMAC_SHA1_80
cat.inb.key_method = km_inline
ckey = cat.inb.keys.add()
ckey.key_salt = 'UHXu88YuDj8guQxhCqEeue0CSr+JcQ/Uii4NdaS5'
cat = strm.attributes.add()
cat.inb.tag = 4
cat.inb.suite = AES_CM_128_HMAC_SHA1_80
cat.inb.key_method = km_inline
cat_prm = cat.inb.session_parameters.add()
cat_prm.flag = UNENCRYPTED_SRTCP
cat_prm = cat.inb.session_parameters.add()
cat_prm.flag = UNENCRYPTED_SRTP
cat_prm = cat.inb.session_parameters.add()
cat_prm.kdr.value = 2
ckey = cat.inb.keys.add()
ckey.key_salt = 'NhqBK/JjtVJgmOgPyDKpvMTEjvFCQ4eiyVQelF6x'
strm = co.streams.add()
strm.info.idx = 1
cat = strm.attributes.add()
cat.inb.tag = 1
cat.inb.suite = AES_CM_128_HMAC_SHA1_80
cat.inb.key_method = km_inline
ckey = cat.inb.keys.add()
ckey.key_salt = 'd0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj'
ckey.lifetime = '2^20'
ckey.mki.value = 1
ckey.mki.length = 32
cat = strm.attributes.add()
cat.inb.tag = 2
cat.inb.suite = F8_128_HMAC_SHA1_80
cat.inb.key_method = km_inline
ckey = cat.inb.keys.add()
ckey.key_salt = 'MTIzNDU2Nzg5QUJDREUwMTIzNDU2Nzg5QUJjZGVm'
ckey.lifetime = '2^20'
ckey.mki.value = 1
ckey.mki.length = 4
ckey = cat.inb.keys.add()
ckey.key_salt = 'QUJjZGVmMTIzNDU2Nzg5QUJDREUwMTIzNDU2Nzg5'
ckey.lifetime = '2^20'
ckey.mki.value = 2
ckey.mki.length = 4
print(len(co.SerializeToString()))
#print(co.SerializeToString())

cra = crypto_request()
ca = cra.answer
sinfo = ca.session
sinfo.from_tag = 'from_tag1'
sinfo.to_tag = 'to_tag1'
strm = ca.streams.add()
strm.info.idx = 0
strm.attribute.inb.tag = 4
strm.attribute.inb.suite = AES_CM_128_HMAC_SHA1_80
strm.attribute.inb.key_method = km_inline
ckey = strm.attribute.inb.keys.add()
ckey.key_salt = '9sOd+W72ilwfNgNt0FzlGYj6YZPMqN1sJJx43UuS'
strm = ca.streams.add()
strm.info.idx = 1
strm.attribute.inb.tag = 1
strm.attribute.inb.suite = AES_CM_128_HMAC_SHA1_32
strm.attribute.inb.key_method = km_inline
ckey = strm.attribute.inb.keys.add()
ckey.key_salt = 'NzB4d1BINUAvLEw6UzF3WSJ+PSdFcGdUJShpX1Zj'
ckey.lifetime = '2^20'
ckey.mki.value = 1
ckey.mki.length = 32
print(len(ca.SerializeToString()))

from rtpp_request_pb2 import rtpp_request, CLS_MOD_CRYPTO
req = rtpp_request()
req.call_id = 'call_id1'
req.dest.mclass = CLS_MOD_CRYPTO
req.cmd_pb = cro.SerializeToString()
print(len(req.SerializeToString()))

req = rtpp_request()
req.call_id = 'call_id1'
req.dest.mclass = CLS_MOD_CRYPTO
req.cmd_pb = cra.SerializeToString()
print(len(req.SerializeToString()))
