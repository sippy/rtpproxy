from crypto_pb2 import crypto_offer, crypto_answer, AES_CM_128_HMAC_SHA1_80
from crypto_pb2 import km_inline

co = crypto_offer()
co.sinfo.from_tag = 'from_tag1'
co.sinfo.call_id = 'call_id1'
cat = co.attributes.add()
cat.inb.tag = 1
cat.inb.suite = AES_CM_128_HMAC_SHA1_80
cat.inb.key_method = km_inline
cat.inb.key_info = 'UHXu88YuDj8guQxhCqEeue0CSr+JcQ/Uii4NdaS5'
cat = co.attributes.add()
cat.inb.tag = 4
cat.inb.suite = AES_CM_128_HMAC_SHA1_80
cat.inb.key_method = km_inline
cat.inb.key_info = 'NhqBK/JjtVJgmOgPyDKpvMTEjvFCQ4eiyVQelF6x'
print(len(co.SerializeToString()))
#print(co.SerializeToString())

ca = crypto_answer()
ca.sinfo.from_tag = 'from_tag1'
ca.sinfo.to_tag = 'to_tag1'
ca.sinfo.call_id = 'call_id1'
ca.attribute.inb.tag = 4
ca.attribute.inb.suite = AES_CM_128_HMAC_SHA1_80
ca.attribute.inb.key_method = km_inline
ca.attribute.inb.key_info = '9sOd+W72ilwfNgNt0FzlGYj6YZPMqN1sJJx43UuS'
print(len(ca.SerializeToString()))
