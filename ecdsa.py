from ctypes import *
try:
	EC = CDLL("libcrypto.so")
except:
	try:
		EC = CDLL("libeay32.dll")
	except:
		raise RuntimeError("Could not load crypto library")

import base58

NID_secp256k1 = 714

class Key:
	def __init__(self):
		key = EC.EC_KEY_new_by_curve_name(NID_secp256k1)
		if not key:
			raise RuntimeError("EC_KEY_new_by_curve_name failed")
		self.pkey = key
		self.set = False

	def make_new_key(self):
		if not EC.EC_KEY_generate_key(self.pkey):
			raise RuntimeError("EC_KEY_generate_key failed")
		self.set = True

	def get_public_key(self):
		size = EC.i2o_ECPublicKey(self.pkey, None)
		if size == 0:
			raise RuntimeError("i2o_ECPublicKey failed")
		c = c_long()
		if size != EC.i2o_ECPublicKey(self.pkey, byref(c)):
			raise RuntimeError("i2o_ECPublicKey returned unexpected size")
		return string_at(c.value, size)

	def get_private_key(self):
		size = EC.i2d_ECPrivateKey(self.pkey, None)
		if size == 0:
			raise RuntimeError("i2d_ECPrivateKey failed")
		c = c_long()
		if size != EC.i2d_ECPrivateKey(self.pkey, byref(c)):
			raise RuntimeError("i2d_ECPrivateKey returned unexpected size")
		return string_at(c.value, size)

	def sign(self, data):
		size = c_int()
		sig = create_string_buffer(10000)
		result = EC.ECDSA_sign(0, data, len(data), sig, byref(size), self.pkey)
		if result != 1:
			return None
		return sig.raw[:size.value]

	def verify(self, data, sig):
		result = EC.ECDSA_verify(0, data, len(data), sig, len(sig), self.pkey)
		return result == 1


import time
d = c_int(int(time.time() * 10000000))
EC.RAND_add(byref(d), sizeof(d), c_float(1.5))

k = Key()
k.make_new_key()
pub = k.get_public_key()
prv = k.get_private_key()

sig = k.sign("hello world"*100)

print k.verify("hello world"*100, sig)

print pub.encode("hex_codec")
#print prv.encode("hex_codec")
print base58.public_key_to_bc_address(pub)

