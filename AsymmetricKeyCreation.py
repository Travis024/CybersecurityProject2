"""

I'm only uploading this since I'm not sure if it will be required or not.
This is the code that created our RSA keys
"""

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify

private_key = RSA.generate(2048) #generate a private key
public_key = private_key.publickey() #get corresponding public key

print(type(private_key), type(public_key))
private_str = private_key.exportKey().decode() #change type to string
public_str = public_key.exportKey().decode()

print(type(private_str), type(public_str))

with open('Server/private_key.pem', 'w') as pr: #write keys to file as strings
    pr.write(private_str)
with open('Client/public_key.pem', 'w') as pu:
    pu.write(public_str)
