"""
    server.py - host an SSL server that checks passwords
    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 140
        (Feel free to use more or less, this
        is provided as a sanity check)
    Put your team members' names:
    Travis Torline
    Alici Edwards
    Clint Eisenzimmer
"""

import socket
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import hashlib
import binascii

host = "localhost"
port = 10001

clearance = -1
types = []


# A helper function. It may come in handy when performing symmetric encryption
def pad_message(message):
    return message + " " * ((16 - len(message)) % 16)


# Write a function that decrypts a message using the server's private key
def decrypt_key(session_key):
    private_str = open('private_key.pem', 'r').read()
    private_key = RSA.importKey(private_str)
    cipher = PKCS1_OAEP.new(key=private_key)
    plain_text = cipher.decrypt(session_key)
    return plain_text


# Write a function that decrypts a message using the session key
def decrypt_message(client_message, session_key):
    cipher = AES.new(session_key) #create cipher we're passing our message through
    plain_text = cipher.decrypt(client_message) #decrypt message
    return plain_text


# Encrypt a message using the session key
def encrypt_message(message, session_key): #same as client side
    cipher = AES.new(session_key)
    message = pad_message(message)
    cipher_text = cipher.encrypt(message)
    return cipher_text


# Receive 1024 bytes from the client
def receive_message(connection):
    return connection.recv(1024)


# Sends message to client
def send_message(connection, data):
    if not data:
        print("Can't send empty string")
        return
    if type(data) != bytes:
        data = data.encode()
    connection.sendall(data)


# A function that reads in the password file, salts and hashes the password, and
# checks the stored hash of the password to see if they are equal. It returns
# True if they are and False if they aren't. The delimiters are newlines and tabs
def verify_hash(user, password):

    print(user.decode('utf-8') + " " + password.decode('utf-8')) #as shown in the writeup, the server prints the attempted connection

    try:
        reader = open("passfile.txt", 'r')
        for line in reader.read().split('\n'):
            line = line.split("\t")

            if line[0].encode('utf-8') == user: #The username is a string, but encrypted messages are binary. Use the encode method to change str -> binary for checking to make sure the username is correct
                salt = binascii.unhexlify(line[1]) #Turn the hex string from passfile.txt into bytes for hashing
                hashed_password = hashlib.pbkdf2_hmac('sha256', #he hash digest algorithm for HMAC
                                                      password, #the password from the encrypted message
                                                      salt, #The salt from above
                                                      100000 #Number of iterations - makes the hash algorithm slower
                )

                string_hashed_password = str(binascii.hexlify(hashed_password))[2:-1] #Passfile.txt has a hex string stored, so turn the hash we just generated into a hex string before checking
                if (string_hashed_password == line[2]): #get user clearance level and document classes for Extra credit
                    clearance = line[3]
                    for i in range(4, len(line)):
                        types.append(line[i])
                return string_hashed_password == line[2] #Checks to make sure that this user is stored in Passfile.txt
        reader.close()
    except FileNotFoundError:
        return False
    return False


def main():
    # Set up network connection listener
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    print('starting up on {} port {}'.format(*server_address))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)
    sock.listen(1)

    try:
        while True:
            # Wait for a connection
            print('waiting for a connection')
            connection, client_address = sock.accept()
            try:
                print('connection from', client_address)

                # Receive encrypted key from client
                encrypted_key = receive_message(connection)

                # Send okay back to client
                send_message(connection, "okay")

                # Decrypt key from client
                plaintext_key = decrypt_key(encrypted_key)

                # Receive encrypted message from client
                ciphertext_message = receive_message(connection)

                plaintext_message = decrypt_message(ciphertext_message, plaintext_key) #decrypt clients username and password
                bool = verify_hash(plaintext_message.split()[0], plaintext_message.split()[1]) #verify that the client entered the right pass

                plaintext_response = "Password or username incorrect"
                if (bool):
                    plaintext_response = "User Successfully authenticated!"
                ciphertext_response=encrypt_message(plaintext_response, plaintext_key)
                # Send encrypted response
                send_message(connection, ciphertext_response)#return whether the password was correct or not

                #EXTRA CREDIT
                tosend = 'File not found'
                if (bool):
                    message = receive_message(connection) #recieve doc info from user
                    fileInfo = decrypt_message(message, plaintext_key)
                    docName, service = fileInfo.split()
                    reader = open("files.txt", 'r')
                    level = -1
                    type = -1
                    for line in reader.read().split('\n'): #scan through list of files and permissions
                        if (len(line)>0):
                            indiv = line.split()
                            if indiv[0] == docName.decode('utf-8'): #if we find the file
                                level = indiv[2] #catch clearance level
                                type = indiv[1]# catch doc class
                                break
                    reader.close()
                    if (level != -1 and type !=-1): #if we did find the file
                        global types
                        global clearance
                        if service.decode('utf-8') == 'r': #if we want to read
                            if type in types and int(clearance) <= int(level): #check that file is lower than our clearance and that we have the doc type
                                tosend = "Permission Granted!"
                            else:
                                tosend = "Permission Denied"
                        if service.decode('utf-8') == 'w': #if we want to write
                            if int(clearance) >= int(level) and len(types) == 1 and types[0] == type: #check that file is above our clearancce and that we only have that doc type
                                tosend = "Permission Granted!"
                            else:
                                tosend = "Permission Denied"
                    ciphertext_tosend=encrypt_message(tosend, plaintext_key) #send permission granted, denied or file not found
                    # Send encrypted response
                    send_message(connection, ciphertext_tosend)
            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()


if __name__ in "__main__":
    main()
