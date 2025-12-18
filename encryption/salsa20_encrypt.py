from Crypto.Cipher import Salsa20

def salsa20_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    cipher = Salsa20.new(key=key) #makes random nonce lol
    ciphertext = cipher.encrypt(plaintext)
    return cipher.nonce, ciphertext #store it with ciphertext
