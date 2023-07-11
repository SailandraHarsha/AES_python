#pip install pycryptodome
#https://asecuritysite.com/encryption/aes_gcm

from Crypto.Cipher import AES
import hashlib
import sys
import binascii
import random
import string


def Generate_Password(length):
    return ''.join(random.choices(string.ascii_letters + string.digits,k=length))

OrgFilePath = input("Enter File path: ")
f = open(OrgFilePath, 'rb')
plaintext = f.read()
f.close()

if not isinstance(plaintext, bytes):
    plaintext = plaintext.encode('utf-8')

password = "Sailandra@123"
#password = Generate_Password(8)


def encrypt(plaintext,key, mode):
  encobj = AES.new(key, AES.MODE_GCM)
  ciphertext,authTag=encobj.encrypt_and_digest(plaintext)
  return(ciphertext,authTag,encobj.nonce)

def decrypt(ciphertext,key, mode):
  (ciphertext,  authTag, nonce) = ciphertext
  encobj = AES.new(key,  mode, nonce)
  return(encobj.decrypt_and_verify(ciphertext, authTag))

key = hashlib.sha256(password.encode()).digest()

print("GCM Mode: Stream cipher and authenticated")
print("\nMessage:\t",plaintext)
print("Key:\t\t",password)


ciphertext = encrypt(plaintext,key,AES.MODE_GCM)

print("Cipher:\t\t",binascii.hexlify(ciphertext[0]))
print("Auth Msg:\t",binascii.hexlify(ciphertext[1]))
print("Nonce:\t\t",binascii.hexlify(ciphertext[2]))


res= decrypt(ciphertext,key,AES.MODE_GCM)


print ("\n\nDecrypted:\t",res.decode())
