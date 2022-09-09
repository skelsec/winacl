import io
import math

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

class RSAPrivateKeyBlob:
	def __init__(self):
		self.type = None
		self.version = None
		self.reserved = None
		self.keyalg = None
		self.magic = None
		self.bitlen = None
		self.pubexp = None
		self.modulus = None
		self.p = None
		self.q = None
		self.dp = None
		self.dq = None
		self.iq = None
		self.d = None

	@staticmethod
	def from_bytes(data):
		return RSAPrivateKeyBlob.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		pk = RSAPrivateKeyBlob()
		pk.type = buff.read(1)[0]
		pk.version = buff.read(1)[0]
		pk.reserved = int.from_bytes(buff.read(2), byteorder='little', signed=False)
		pk.keyalg = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		pk.magic = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		pk.bitlen = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		c8 = int(math.ceil(pk.bitlen/8))
		c16 = int(math.ceil(pk.bitlen/16))
		pk.pubexp = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		pk.modulus = int.from_bytes(buff.read(c8), byteorder='little', signed=False)
		pk.p = int.from_bytes(buff.read(c16), byteorder='little', signed=False)
		pk.q = int.from_bytes(buff.read(c16), byteorder='little', signed=False)
		pk.dp = int.from_bytes(buff.read(c16), byteorder='little', signed=False)
		pk.dq = int.from_bytes(buff.read(c16), byteorder='little', signed=False)
		pk.iq = int.from_bytes(buff.read(c16), byteorder='little', signed=False)
		pk.d = int.from_bytes(buff.read(c8), byteorder='little', signed=False)
		return pk

	def get_key(self):
		public_numbers = rsa.RSAPublicNumbers(self.pubexp, self.modulus)
		numbers = rsa.RSAPrivateNumbers(self.p, self.q, self.d, self.dp, self.dq, self.iq, public_numbers)
		return default_backend().load_rsa_private_numbers(numbers)


	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
		return t