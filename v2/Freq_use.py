import socket
import binascii
import struct
import random 


def Mac2Hex(strmac) :
	hexmac = binascii.unhexlify(strmac.replace(':', ''))
	return bytes(hexmac)

def ip2int(addr):
	return struct.unpack("!I" , socket.inet_aton(addr))[0]

def ip2str(intaddr):
	return socket.inet_ntoa(struct.pack('>I', intaddr ))

def rand_mac(MacSign1 , MacSign2):
	return "%02x:%02x:%02x:%02x:%02x:%02x" % (
		MacSign1,
		MacSign2,
		random.randint(0, 255),
		random.randint(0, 255),
		random.randint(0, 255),
		random.randint(0, 255)
	)

