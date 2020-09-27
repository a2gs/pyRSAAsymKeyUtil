#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Andre Augusto Giannotti Scota (https://sites.google.com/view/a2gs/)

from base64 import b64encode, b64decode
from sys import exit, argv, stdin
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import UnsupportedAlgorithm, InvalidSignature

def printHelp(exec):

	print('Usage:\n')
	print(f'1) Generating private key:\n\t{exec} GENKEY KEY_SIZE > privateKey.pem\n')
	print(f'2) Get public key from a private key:\n\tcat privateKey.pem | {exec} GETPUB > publicKey.pem\n')
	print(f'3) Encrypting:\n\tcat plainMsg.text | {exec} ENC publicKey.pem > msgOut.text.rsa\n')
	print(f'4) Decrypting:\n\tcat msgOut.text.rsa | {exec} DEC privateKey.pem > plainMsg.text\n')
	print(f'5) Sign:\n\tcat msg.text | {exec} SIGN privateKey.pem > singedMsg.text\n\t(or publicKey.pem)\n')
	print(f"6) Check sign:\n\tcat signedMsg.text | {exec} CHECKSIGN publicKey.pem\n\tReturn: 'Ok' or 'NOk' to stdout (and 0 and 1 to shell)")

# ------------------------------------------------------------------

def readBinFromStdinPipe() -> [bool, bytes]:

	if stdin.isatty() == True:
		return([False, b''])

	return([True, ''.join([i for i in stdin]).encode('ascii')])

# ------------------------------------------------------------------

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

	try:
		pem = private_key.private_bytes(encoding = serialization.Encoding.PEM,
		                                format = serialization.PrivateFormat.PKCS8,
		                                encryption_algorithm = serialization.NoEncryption())

	except Exception as e:
		return([False, f"Generate Private Key Bytes error: [{e}]"])

	except:
		return([False, "Generate Private Key Bytes generic error"])

	[print(x.decode('ascii')) for x in pem.splitlines()]

	return([True, "Ok"])

# ------------------------------------------------------------------

def getPublicKey() -> [bool, str]:

	ret, privKey = readBinFromStdinPipe()
	if ret == False:
		return([False, "Unable to read from stdin pipe"])

	try:
		private_key = serialization.load_pem_private_key(privKey,
		                                                 password = None,
		                                                 backend = default_backend())

	except ValueError as e:
		return([False, f"Load PEM Private Key Value error: [{e}]"])

	except TypeError as e:
		return([False, f"Load PEM Private Key Type error: [{e}]"])

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

# ------------------------------------------------------------------

def encrypt(pubKeyFile : str = '') -> [bool, str]:

	ret, message = readBinFromStdinPipe()
	if ret == False:
		return([False, "Unable to read from stdin pipe"])

	with open(pubKeyFile, "rb") as pubKeyFileHandle:

		try:
			public_key = serialization.load_pem_public_key(pubKeyFileHandle.read(),
			                                               backend = default_backend())

		except Exception as e:
			return([False, f"Encrypt Load PEM Public Key error: [{e}]"])

		except:
			return([False, "Encrypt Load PEM Public Key generic error"])

	try:
		encryptMessage = public_key.encrypt(message,
		                                    padding.OAEP(mgf = padding.MGF1(algorithm = hashes.SHA256()),
		                                                 algorithm = hashes.SHA256(),
		                                                 label = None))
	except Exception as e:
		return([False, f"Encrypt error: [{e}]"])

	except:
		return([False, "Encrypt generic error"])

	print(b64encode(encryptMessage).decode("ascii"))

	return([True, "Ok"])

# ------------------------------------------------------------------

def decrypt(privKeyFile : str = '') -> [bool, str]:

	ret, encryptMessage = readBinFromStdinPipe()
	if ret == False:
		return([False, "Unable to read from stdin pipe"])

	with open(privKeyFile, "rb") as privKeyFileHandle:

		try:
			private_key = serialization.load_pem_private_key(privKeyFileHandle.read(),
		                                                    password = None,
			                                                 backend = default_backend())

		except Exception as e:
			return([False, f"Decrypt Load PEM Private Key error: [{e}]"])

		except:
			return([False, "Decrypt Load PEM Private Key generic error"])

	try:
		plaintext = private_key.decrypt(b64decode(encryptMessage),
		                                padding.OAEP(mgf = padding.MGF1(algorithm = hashes.SHA256()),
		                                             algorithm = hashes.SHA256(),
		                                             label = None))

	except Exception as e:
		return([False, f"Decrypt error: [{e}]"])

	except:
		return([False, "Decrypt generic error"])

	[print(x.decode('ascii')) for x in plaintext.splitlines()]
	#print(plaintext)

	return([True, "Ok"])

# ------------------------------------------------------------------

def sign(privKeyFile : str = '') -> [bool, str]:

	ret, message = readBinFromStdinPipe()
	if ret == False:
		return([False, "Unable to read from stdin pipe"])

	with open(privKeyFile, "rb") as privKeyFileHandle:

		try:
			private_key = serialization.load_pem_private_key(privKeyFileHandle.read(),
		                                                    password = None,
			                                                 backend = default_backend())
		except Exception as e:
			return([False, f"Sign Load PEM Private Key error: [{e}]"])

		except:
			return([False, "Sign Load PEM Private Key generic error"])

	try:
		signature = private_key.sign(message,
		                             padding.PSS(mgf = padding.MGF1(hashes.SHA256()),
		                                         salt_length = padding.PSS.MAX_LENGTH),
		                             hashes.SHA256())

	except Exception as e:
		return([False, f"Sign error: [{e}]"])

	except:
		return([False, "Sign generic error"])

	#[print(x.decode('ascii')) for x in signature.splitlines()]
	print(signature)

	return([True, "Ok"])
	
# ------------------------------------------------------------------

def checkSign(pubKeyFile : str = '') -> [bool, str]:

	print(f"6) Check sign:\n\tcat signedMsg.text | {exec} CHECKSIGN publicKey.pem\n\tReturn: 'Ok' or 'NOk' to stdout (and 0 and 1 to shell)")

	ret, signedMessage = readBinFromStdinPipe()
	if ret == False:
		return([False, "Unable to read from stdin pipe"])

	with open(pubKeyFile, "rb") as pubKeyFileHandle:

		try:
			public_key = serialization.load_pem_public_key(pubKeyFileHandle.read(),
			                                               backend = default_backend())

		except Exception as e:
			return([False, f"Check Sign load pem public Key error: [{e}]"])

		except:
			return([False, "Check Sign Load PEM Public Key generic error"])

	try:
		public_key.verify(#signature, TODO
		                  signedMessage,
		                  padding.PSS(mgf = padding.MGF1(hashes.SHA256()),
		                              salt_length = padding.PSS.MAX_LENGTH),
		                  hashes.SHA256())

	except InvalidSignature as e:
		print(f"Signature does not match: [{e}]")
		return([True, f"Signature does not match: [{e}]"])

	except Exception as e:
		return([False, f"Check Signature Verify error: [{e}]"])

	except:
		return([False, "Check Signature Verify generic error"])

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
			ret, msgRet = decrypt(argv[2])
			if ret == False:
				print(f'Error: {msgRet}')
				exit(-1)
		else:
			print(f'Syntax error ENC. Usage:\ncat msgOut.text.rsa | {exec} DEC privateKey.pem > plainMsg.text\n')
			exit(-1)

	elif argv[1] == 'SIGN':
		if len(argv) == 3:
			ret, msgRet = sign(argv[2])
			if ret == False:
				print(f'Error: {msgRet}')
				exit(-1)
		else:
			print(f'Syntax error ENC. Usage:\ncat msg.text | {exec} SIGN privateKey.pem > singedMsg.text\n\t(or publicKey.pem)\n')
			exit(-1)

	elif argv[1] == 'CHECKSIGN':
		if len(argv) == 3:
			ret, msgRet = checkSign(argv[2])
			if ret == False:
				print(f'Error: {msgRet}')
				exit(-1)
		else:
			print(f"Syntax error ENC. Usage:\ncat signedMsg.text | {exec} CHECKSIGN publicKey.pem\n\tReturn: 'Ok' or 'NOk' to stdout (and 0 and 1 to shell)")
			exit(-1)

	else:
		printHelp(argv[0])
		exit(-1)

	exit(0)
