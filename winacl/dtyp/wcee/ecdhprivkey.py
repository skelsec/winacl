import io

class ECDHPrivateKeyBlob:
	def __init__(self):
		self.magic = None
		self.length = None
		self.x = None
		self.y = None
		self.privateexp = None

	@staticmethod
	def from_bytes(data):
		return ECDHPrivateKeyBlob.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		pk = ECDHPrivateKeyBlob()
		pk.magic = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		pk.length = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		pk.x = int.from_bytes(buff.read(pk.length), byteorder='little', signed=False)
		pk.y = int.from_bytes(buff.read(pk.length), byteorder='little', signed=False)
		pk.privateexp = int.from_bytes(buff.read(pk.length), byteorder='little', signed=False)
		return pk

	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
		return t