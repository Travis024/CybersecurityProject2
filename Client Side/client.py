"""
    client.py - Connect to an SSL server
    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 117
        (Feel free to use more or less, this
        is provided as a sanity check)
    Put your team members' names:
    Travis Torline
    Alici Edwards
    Clint Eisenzimmer
"""

import socket
import os
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from binascii import hexlify

host = "localhost"
port = 10001


# A helper function that you may find useful for AES encryption
# Is this the best way to pad a message?!?!
def pad_message(message):
    return message + " "*((16-len(message))%16)



def generate_key():
    AES_key = os.urandom(16) #generate 16 byte key
    return AES_key


# Takes an AES session key and encrypts it using the appropriate
# key and return the value
def encrypt_handshake(session_key):
    public_str = open('public_key.pem', 'r').read() #read public key from file (already generated)
    public_key = RSA.importKey(public_str) #change key from string to RSAobj type
    cipher = PKCS1_OAEP.new(key=public_key) #create the cipher we will pass our text through
    cipher_text = cipher.encrypt(session_key) #encrypt the AES key
    return cipher_text
    """this code was successful in my tests so far."""


# Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
    cipher = AES.new(session_key)  #create the cipher we will pass our text through
    message = pad_message(message) #pad the message so that it's 16 bytes
    cipher_text = cipher.encrypt(message) #encrypt the message
    return cipher_text


# Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    cipher = AES.new(session_key)
    plain_text = cipher.decrypt(message)
    return plain_text


# Sends a message over TCP
def send_message(sock, message):
    sock.sendall(message)


# Receive a message from TCP
def receive_message(sock):
    data = sock.recv(1024)
    return data


def main():
    user = input("What's your username? ")
    password = input("What's your password? ")

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    try:
        # Message that we need to send
        message = user + ' ' + password

        # Generate random AES key
        key = generate_key()

        # Encrypt the session key using server's public key
        encrypted_key = encrypt_handshake(key)

        # Initiate handshake
        send_message(sock, encrypted_key)

        # Listen for okay from server (why is this necessary?)
        if receive_message(sock).decode() != "okay":
            print("Couldn't connect to server")
            exit(0)

        encrypted_message=encrypt_message(message, key) #encrypt the username and password
        send_message(sock, encrypted_message) #send encrypted message to the server

        received = decrypt_message(receive_message(sock), key) #check to see if authentication was successful
        print(received.decode('utf-8')) #The recieved message is in bytes, so decode it into a string
        
        #EXTRA CREDIT
        if (received.decode('utf-8') == "User Successfully authenticated!"): #if we entered the correct password and username
            type = input("Are you trying to (r)ead or w(rite): ") #try to read/write to a file
            s = "write"
            if (type == 'r'):
                s = "read"
            doc = input("Which file would you like to "+ s+" from?")
            new_message = encrypt_message(doc+' '+type, key) #encrypt file name and if we want to read/write and send
            send_message(sock, new_message)
            receive_again = decrypt_message(receive_message(sock), key) #print server response
            print(receive_again.decode('utf-8'))
    finally:
        print('closing socket')
        sock.close()


if __name__ in "__main__":
    main()
