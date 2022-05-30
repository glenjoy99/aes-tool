from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import sys, os, hashlib
from base64 import b64encode, b64decode
import tkinter as tk

'''
python3 encrypt.py -e plaintxt key 
python3 encrypt.py -d cipher key
'''


'''
encrypt: raw key -> encoded to bytes -> hashed to bytes -> base64 encoded

b64encode(): bytes -> bytes
.decode(utf-8): bytes -> utf-8 str
'''

def encrypt_msg(plaintext, password, outputbox):
    plaintext = plaintext.get()
    password = password.get()
    outputbox.delete(0, tk.END)
    message = plaintext.encode() # raw message encoded to bytes
    key = hashlib.sha256(password.encode()).digest() # key hashed to proper size
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message, 16)) # padding message to 128 bits and encrypting
    output = b64encode(ciphertext).decode('utf-8') # encoding ciphertext to utf-8 base64 string
    IV = b64encode(cipher.iv).decode('utf-8') # encoding IV to utf-8 base64 string
    outputbox.insert(tk.END, IV + " " + output)

def decrypt(encrypted, password, outputbox):
    encrypted = encrypted.get()
    password = password.get()
    outputbox.delete(0, tk.END)
    print("Inputted cipher " + encrypted)
    ciphertext = encrypted.split(" ")[1]
    iv = encrypted.split(" ")[0]
    IV = b64decode(iv.encode()) # decode base64 string IV
    raw_message = b64decode(ciphertext.encode())  # decode base64 string message
    key = hashlib.sha256(password.encode()).digest() # hash key to proper size
    cipher = AES.new(key, AES.MODE_CBC, IV) 
    output = cipher.decrypt(raw_message) # decrypt message
    outputbox.insert(tk.END, output)

def main():
    if (sys.argv[1] == "-e"):
        '''
        ra  w message -> encoded -> padded -> encrypted
        decrypt -> unpad -> decode -> raw message
        '''
        message = sys.argv[2].encode() # raw message encoded to bytes
        key = hashlib.sha256(sys.argv[3].encode()).digest() # key hashed to proper size
        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(message, 16)) # padding message to 128 bits and encrypting
        output = b64encode(ciphertext).decode('utf-8') # encoding ciphertext to utf-8 base64 string
        IV = b64encode(cipher.iv).decode('utf-8') # encoding IV to utf-8 base64 string
    elif (sys.argv[1] == "-d"):
        IV = b64decode(sys.argv[4].encode()) # decode base64 string IV
        raw_message = b64decode(sys.argv[2].encode())  # decode base64 string message
        key = hashlib.sha256(sys.argv[3].encode()).digest() # hash key to proper size
        cipher = AES.new(key, AES.MODE_CBC, IV) 
        output = cipher.decrypt(raw_message) # decrypt message
    print(sys.argv[2])
    print("-------------------------------")
    print("{} {}".format(IV, output))




if (__name__ == "__main__"):
    main()



# print(sys.argv[1])
# print(sys.argv[2])


