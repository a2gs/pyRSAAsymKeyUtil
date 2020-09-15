#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Andre Augusto Giannotti Scota (https://sites.google.com/view/a2gs/)

from sys import exit, argv, stdin
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import UnsupportedAlgorithm

def printHelp(exec):
	print('Usage:\n')
	print(f'1) Generating private key:\n\t{exec} GENKEY KEY_SIZE > privateKey.pem\n')
	print(f'2) Get public key from a private key:\n\tcat privateKey.pem | {exec} GETPUB > publicKey.pem\n')
	print(f'3) Encrypting:\n\tcat plainMsg.text | {exec} ENC publicKey.pem > msgOut.text.rsa\n')
	print(f'4) Decrypting:\n\tcat msgOut.text.rsa | {exec} DEC privateKey.pem > plainMsg.text\n')
	print(f'5) Sign:\n\tcat msg.text | {exec} SIGN privateKey.pem > singedMsg.text\n\t(or publicKey.pem)\n')
	print(f"6) Check sign:\n\tcat signedMsg.text | {exec} CHECKSIGN publicKey.pem\n\tReturn: 'Ok' or 'NOk' to stdout (and 0 and 1 to shell)")

def generatePrivKey(keySize : int = 2048) -> [bool, str]:

	if keySize < 512:
		return([False, "Key size must not be less than 512"])

	try:

		private_key = rsa.generate_private_key(public_exponent = 65537,
		                                       key_size = keySize,
		                                       backend = default_backend())

	except UnsupportedAlgorithm as e:
		return([False, f"Generate Private Key Unsupported Algorithm error: [{e}]"])

	except Exception as e:
		return([False, f"Generate Private Key error: [{e}]"])

	except:
		return([False, "Generate Private Key generic error"])

	pem = private_key.private_bytes(encoding = serialization.Encoding.PEM,
	                                format = serialization.PrivateFormat.PKCS8,
	                                encryption_algorithm = serialization.NoEncryption())

	[print(x.decode('ascii')) for x in pem.splitlines()]

	return([True, "Ok"])

def getPublicKey() -> [bool, str]:

	# reading from stdin pipe
	if stdin.isatty() == True:
		return([False, "Pipe private key from stdin"])

	privKey = ''.join([i for i in stdin]).encode('ascii')

	try:

		private_key = serialization.load_pem_private_key(privKey,
		                                                 password = None,
		                                                 backend = default_backend())

	except ValueError as e:
		return([False, f"Load Private Key Value error: [{e}]"])

	except TypeError as e:
		return([False, f"Load Private Key Type error: [{e}]"])

	except UnsupportedAlgorithm as e:
		return([False, f"Load Private Key Unsupported Algorithm error: [{e}]"])

	except Exception as e:
		return([False, f"Load Private Key error: [{e}]"])

	except:
		return([False, "Load Private Key generic error"])

	try:

		public_key = private_key.public_key()

	except Exception as e:
		return([False, f"Public key error: [{e}]"])

	except:
		return([False, "Public key generic error"])

	try:

		pem = public_key.public_bytes(encoding = serialization.Encoding.PEM,
		                              format = serialization.PublicFormat.SubjectPublicKeyInfo)

	except Exception as e:
		return([False, f"Public Bytes error: [{e}]"])

	except:
		return([False, "Public Bytes generic error"])

	[print(x.decode('ascii')) for x in pem.splitlines()]

	return([True, "Ok"])

def encrypt(pubKeyFile : str = '') -> [bool, str]:

	with open(pubKeyFile, "rb") as pubKeyFileHandle:
		public_key = serialization.load_pem_public_key(pubKeyFileHandle.read(),
		                                               backend = default_backend())

	# reading from stdin pipe
	if stdin.isatty() == True:
		return([False, "Pipe private key from stdin"])

	message = ''.join([i for i in stdin]).encode('ascii')

	try:

		ciphertext = public_key.encrypt(message,
		                                padding.OAEP(mgf = padding.MGF1(algorithm = hashes.SHA256()),
		                                             algorithm = hashes.SHA256(),
		                                             label = None))
	except Exception as e:
		return([False, f"Encrypt error: [{e}]"])

	except:
		return([False, "Encrypt generic error"])

	return([True, "Ok"])



def decrypt(privKeyFile : str = '') -> [bool, str]:
	'''
	>>> plaintext = private_key.decrypt(
	...     ciphertext,
	...     padding.OAEP(
	...         mgf=padding.MGF1(algorithm=hashes.SHA256()),
	...         algorithm=hashes.SHA256(),
	...         label=None
	...     )
	... )
	>>> plaintext == message
	True
	'''

	return([True, "Ok"])

# ------------------------------------------------------------------

if __name__ == '__main__':

	if len(argv) == 1:
		printHelp(argv[0])
		exit(-1)

	if argv[1] == 'GENKEY':
		if len(argv) == 3:
			ret, msgRet = generatePrivKey(int(argv[2]))
			if ret == False:
				print(f'Error: {msgRet}')
				exit(-1)
		else:
			print(f'Syntax error GENKEY. Usage:\n{argv[0]} GENKEY KEY_SIZE > privateKey.pem')
			exit(-1)

	elif argv[1] == 'GETPUB':
		if len(argv) == 2:
			ret, msgRet = getPublicKey()
			if ret == False:
				print(f'Error: {msgRet}')
				exit(-1)
		else:
			print(f'Syntax error GETPUB. Usage:\ncat privateKey.pem | {argv[0]} GETPUB > publicKey.pem')
			exit(-1)

	elif argv[1] == 'ENC':
		if len(argv) == 3:
			ret, msgRet = encrypt(argv[2])
			if ret == False:
				print(f'Error: {msgRet}')
				exit(-1)
		else:
			print(f'Syntax error ENC. Usage:\ncat plainMsg.text | {exec} ENC publicKey.pem > msgOut.text.rsa\n')
			exit(-1)

	elif argv[1] == 'DEC':
		if len(argv) == 3:
			ret, msgRet = decrypt(argv[1])
			if ret == False:
				print(f'Error: {msgRet}')
				exit(-1)
		else:
			print(f'Syntax error ENC. Usage:\ncat msgOut.text.rsa | {exec} DEC privateKey.pem > plainMsg.text\n')
			exit(-1)

	elif argv[1] == 'SIGN':
		pass

	elif argv[1] == 'CHECKSIGN':
		pass

	else:
		printHelp(argv[0])
		exit(-1)

	exit(0)
