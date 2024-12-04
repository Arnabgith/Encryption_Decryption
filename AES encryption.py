from Crypto.Cipher import AES
from secrets import token_bytes

key = token_bytes(16)

def encrypt(msg):
     cipher = AES.new(key, AES.MODE_EAX)
     nonce = cipher.nonce
     ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
     return nonce, ciphertext, tag

def decrypt(ciphertext, nonce, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext.decode('ascii')
    except:
        return False

nonce, ciphertext, tag = encrypt(input('Enter a massage: '))
plaintext = decrypt(ciphertext, nonce, tag)

print(f'ciphertext: {ciphertext}')
if not  plaintext:
    print('Msg is corrupted')
else:
    print(f'plaintext: {plaintext}')
