from Crypto.Cipher import AES
from base64 import b64decode, b64encode
import pkcs7

def ecb_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pkcs7.pkcs7_pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_message)
    return ciphertext

def ecb_decrypt(key, ciphertext):
    if len(ciphertext) % AES.block_size != 0:
        raise ValueError("Ciphertext is not a multiple of the block size")
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = cipher.decrypt(ciphertext)
    try:
        message = pkcs7.pkcs7_unpad(padded_message, AES.block_size)
    except ValueError:
        raise ValueError("Invalid padding")
    return message

def test_ecb_mode():
    key = b"CALIFORNIA LOVE!"
    with open("Lab2.TaskII.A.txt", "r") as f:
        ciphertext = b64decode(f.read().strip())
    plaintext = ecb_decrypt(key, ciphertext)
    print("Decrypted message:", plaintext.decode())

def main():
    test_ecb_mode()

if __name__ == "__main__":
    main()
