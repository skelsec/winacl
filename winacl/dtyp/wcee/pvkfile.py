import io
from winacl.dtyp.wcee.rsaprivkey import RSAPrivateKeyBlob


# https://github.com/openssl/openssl/blob/9dddcd90a1350fa63486cbf3226c3eee79f9aff5/crypto/pem/pvkfmt.c
class PVKFile:
	def __init__(self):
		self.magic = None
		self.reserved = None
		self.keytype = None
		self.isencrypted = None
		self.saltlength = None
		self.keylength = None
		self.saltblob = None
		self.keyblob = None

	@staticmethod
	def from_file(filepath):
		with open(filepath, 'rb') as f:
			return PVKFile.from_buffer(f)
	
	
	@staticmethod
	def from_bytes(data):
		return PVKFile.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		pvk = PVKFile()
		pvk.magic = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		assert 0xb0b5f11e == pvk.magic
		pvk.reserved = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		pvk.keytype = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		pvk.isencrypted = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		pvk.saltlength = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		pvk.keylength = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		pvk.saltblob = buff.read(pvk.saltlength)
		pvk.keyblob = buff.read(pvk.keylength)
		return pvk

	def get_key(self):
		if self.keyblob[8:].startswith(b'RSA2'):
			return RSAPrivateKeyBlob.from_bytes(self.keyblob).get_key()

	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
		return t