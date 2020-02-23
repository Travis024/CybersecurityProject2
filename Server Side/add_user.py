"""
    add_user.py - Stores a new username along with salt/password
    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    The solution contains the same number of lines (plus imports)
"""
import hashlib
import os
import binascii

user = input("Enter a username: ")
password = input("Enter a password: ")

salt = os.urandom(32) #pulls from /dev/urandom, 32 bytes in size
string_salt = str(binascii.hexlify(salt))[2:-1] #turns the bytes into a string for storing in passfile.txt. DO NOT want to store as bytes

hashed_password = hashlib.pbkdf2_hmac('sha256', #the hash digest algorithm for HMAC
                                      password.encode('utf-8'), #convert the password to bytes
                                      salt, #The salt generated above in bytes
                                      100000 #Number of iterations - makes the hash algorithm slower
)

string_hashed_password = str(binascii.hexlify(hashed_password))[2:-1] #again, turns the bytes into a string for storing in passfile.txt

try:
    reading = open("passfile.txt", 'r')
    for line in reading.read().split('\n'):
        if line.split('\t')[0] == user:
            print("User already exists!")
            exit(1)
    reading.close()
except FileNotFoundError:
    pass

with open("passfile.txt", 'a+') as writer:
    writer.write("{0}\t{1}\t{2}\n".format(user, string_salt, string_hashed_password)) #make sure to store the string versions, NOT byte versions
    print("User successfully added!")
