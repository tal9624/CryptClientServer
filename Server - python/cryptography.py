import os
from Crypto.Util.Padding import pad ## לעדכן את המרצה עלהבג
from Crypto.Cipher import AES ## לעדכן את המרצה על הבג
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA1
from Crypto.Random import get_random_bytes ## לעדכן את המרצה על הבג


def create_AESKey():
   AESKey = os.urandom(16)
   return AESKey

def encrypt_aes_with_rsa(aes_key,public_key):
    rsa_public_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key, hashAlgo=SHA1)
    encrypted_data = cipher_rsa.encrypt(aes_key)
    return encrypted_data

### end 4b

## 4c
def encrypt_file_with_public_key(AESKey,public_key):
    cipher = AES.new(AESKey, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(public_key, AES.block_size))
    return encrypted_data

def decrypt_file_with_public_key(AESKey,cipher_text):
    iv = bytearray(16)
    for b in iv: b = 0
    decrypt_cipher = AES.new(AESKey, AES.MODE_CBC, iv)
    decrypted_data = unpad(decrypt_cipher.decrypt(cipher_text), AES.block_size)
    return decrypted_data