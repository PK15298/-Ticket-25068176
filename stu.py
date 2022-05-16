
import hashlib
from simplecrypt import encrypt, decrypt

value = input("Enter Any Text: ")
hex_string = ''
message = "Hello!"

def SHA256():
    result = hashlib.sha256(value.encode())
    print("\n", result.hexdigest())  
SHA256()
def MD5():
    #Mesage Direct 5
    result = hashlib.md5(value.encode())
    print("\n", result.hexdigest()) 
MD5()
def encryption():
    global hex_string
    ciphercode = encrypt('AIM', message)
    hex_string = ciphercode.hex()
    print("Encryption ", hex_string)

def decryption():
    global hex_string
    bytes_str = bytes.fromhex(hex_string)
    original = decrypt('AIM', bytes_str)
    final_message = original.decode("utf-8")
    print("Decryption ", final_message)
    

print(message)
encryption()
decryption()
