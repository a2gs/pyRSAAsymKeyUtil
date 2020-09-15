#!/usr/bin/env bash

# Andre Augusto Giannotti Scota (https://sites.google.com/view/a2gs/)

# Script exit if a command fails:
#set -e

# Script exit if a referenced variable is not declared:
#set -u

# If one command in a pipeline fails, its exit code will be returned as the result of the whole pipeline:
#set -o pipefail

# Activate tracing:
#set -x

testDate=`date '+%Y%m%d-%H%M%S'`

keySize=512
privKeyFile="$testDate"_privateKey.pem
publicKeyFile="$testDate"_publicKey.pem
signedPlainTextFile="$testDate"_signedPlainText.text
signedDecryptedPlainTextFile="$testDate"_signedDecryptedPlainText.text
encryptedAndSignedFile="$testDate"_signedEncryptedText.rsa

messageText='Gott weiß, ich will kein Engel sein'

./pyRSA.py GENKEY "$keySize" > "$privKeyFile"
if [ "$?" -ne 0 ];
then
	echo "Error GENKEY..."
	exit 1
fi

echo "Private key ($keySize bytes):"
cat "$privKeyFile"

echo '-----------------------------------------'

cat "$privKeyFile" | ./pyRSA.py GETPUB > "$publicKeyFile"
if [ "$?" -ne 0 ];
then
	echo "Error GETPUB..."
	exit 1
fi

echo "Public key:"
cat "$publicKeyFile"

echo '-----------------------------------------'
echo "$messageText" | ./pyRSA.py SIGN "$privKeyFile" > "$signedPlainTextFile"

if [ "$?" -ne 0 ];
then
	echo "Error SIGN..."
	exit 1
fi

echo "Signed message:"
cat "$signedPlainTextFile"

echo '-----------------------------------------'
cat "$signedPlainTextFile" | ./pyRSA.py ENC "$publicKeyFile" > "$encryptedAndSignedFile"

if [ "$?" -ne 0 ];
then
	echo "Error ENC..."
	exit 1
fi

echo "Encrypted message:"
cat "$encryptedAndSignedFile"

echo '-----------------------------------------'
cat "$encryptedAndSignedFile" | ./pyRSA.py DEC "$privKeyFile" > "$signedDecryptedPlainTextFile"

if [ "$?" -ne 0 ];
then
	echo "Error DEC..."
	exit 1
fi

echo "Decrypted message:"
cat "$signedDecryptedPlainTextFile"

echo '-----------------------------------------'
cat "$signedDecryptedPlainTextFile" | ./pyRSA.py CHECKSIGN "$publicKeyFile"

if [ "$?" -ne 0 ];
then
	echo "Truested text!"
else
	echo "SIGNATURE DOES NOT MATCH!"
fi

rm -rf "$privKeyFile $publicKeyFile $signedPlainTextFile $signedDecryptedPlainTextFile $encryptedAndSignedFile"
