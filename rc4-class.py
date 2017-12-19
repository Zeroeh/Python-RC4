#!/usr/bin/env python3

import binascii

decrypt_key = '72c5583cafb6818995cdd74b80'

failure_packet = b's \xb4;\xc6\x90\x0f\xd4\xf4k\xe1s\xc8\x81\xa53\xe8\xbei-\xed\xa2IZCd\x00\x00\x00\x12\x00P\xcb\x84\x9b\x11,(\xf4:\xa9>\x0f\xbc\xff'

class BotCrypto(object):
	decrypt_key = '72c5583cafb6818995cdd74b80' # key to decrypt incoming packets
	encrypt_key = '311f80691451c71d09a13a2a6e' # key to encrypt outgoing packets
	p = None
	q = None

	def string_to_list(input_srt):
		res = [ch for ch in binascii.unhexlify(input_srt)]
		return res

	def list_to_string(lst):
		res = ''.join(["%0.2X" % el for el in lst])
		return res

	def bytesGenerator(state):
		global p, q
		p = (p + 1) % 256
		q = (q + state[p]) % 256	
		state[p], state[q] = state[q], state[p]
		return state[(state[p] + state[q]) % 256]

	''' RC4 function to cipher our data '''
	def rc4(data, key, is_encrypt):
		global p, q
		bin_data = BotCrypto.string_to_list(data)
		new_key = BotCrypto.string_to_list(key)
		# TODO: implement protocol for proxy
		#if (is_encrypt == True):
		#	pass
		#elif (is_encrypt == False):
		#	pass
		#else:
		#	print('ERROR! ONLY BOOLEAN ALLOWED FOR THIRD PARAMETER!')
		# reset our states
		state = [None] * 256
		p = q = None
		state = [n for n in range(256)]
		p = q = j = 0
		for i in range(256):
			j = (j + state[i] + new_key[i % len(new_key)]) % 256
			state[i], state[j] = state[j], state[i]
		xor_list = [x ^ BotCrypto.bytesGenerator(state) for x in bin_data]
		return BotCrypto.list_to_string(xor_list)

	''' RSA encrypts the string with a public key and returns the string encoded as base64 '''
	def guidEncrypt(string):
		pass

def main():
	print(failure_packet) #we receive raw hex from server
	yaz = bytes.hex(failure_packet) #we change the raw bytes to something comprehensible
	print(yaz)
	maz = BotCrypto.rc4(yaz, BotCrypto.decrypt_key, False).encode('utf-8') #remove the encryption
	print(maz)
	taz = binascii.unhexlify(maz) #convert the data to something readable
	print(taz)
	gaz = BotCrypto.rc4(maz, BotCrypto.decrypt_key, True) #re encrypt
	print(gaz)
	waz = bytes.fromhex(gaz) #convert it back to binary puke that the server understands
	print(waz)

if __name__ == '__main__':
	main()
