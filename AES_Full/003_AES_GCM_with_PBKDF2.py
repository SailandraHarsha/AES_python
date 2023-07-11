
from Crypto.Cipher import AES
import hashlib
import sys
import binascii
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import random
import string


def Generate_Password(length):
    return ''.join(random.choices(string.ascii_letters + string.digits,k=length))

plaintext = input("Enter Text:")
password = Generate_Password(8)

def encrypt(plaintext,key, mode):
  encobj = AES.new(key, AES.MODE_GCM)
  ciphertext,authTag=encobj.encrypt_and_digest(plaintext)
  return(ciphertext,authTag,encobj.nonce)

def decrypt(ciphertext,key, mode):
  (ciphertext,  authTag, nonce) = ciphertext
  encobj = AES.new(key,  mode, nonce)
  return(encobj.decrypt_and_verify(ciphertext, authTag))

key = hashlib.sha256(password.encode()).digest()

salt = get_random_bytes(32)
key = PBKDF2(password, salt, 32, count=1000000, hmac_hash_module=SHA256)

print("GCM Mode: Stream cipher and authenticated")
print("\nMessage:\t",plaintext)
print("Password:\t\t",password)


ciphertext = encrypt(plaintext.encode(),key,AES.MODE_GCM)

print("Salt:\t\t",binascii.hexlify(salt))
print("Cipher:\t\t",binascii.hexlify(ciphertext[0]))
print("Auth Msg:\t",binascii.hexlify(ciphertext[1]))
print("Nonce:\t\t",binascii.hexlify(ciphertext[2]))


res= decrypt(ciphertext,key,AES.MODE_GCM)


print ("\n\nDecrypted:\t",res.decode())


