from Crypto.Cipher import AES
from base64 import b64decode, b64encode
import pkcs7
from PIL import Image
from io import BytesIO


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


def detect_ecb_mode(filename):
    with open(filename, "r") as f:
        ciphertexts = [bytes.fromhex(line.strip()) for line in f]
    block_size = AES.block_size 
    ecb_ciphertexts = []
    for i, ciphertext in enumerate(ciphertexts):
        blocks = [ciphertext[j:j+block_size] for j in range(54, len(ciphertext), block_size)]
        if len(blocks) != len(set(blocks)):
            ecb_ciphertexts.append((i, ciphertext))
    return ecb_ciphertexts


def create_cookie():
    block_size = AES.block_size
    # Create a user with a username such that the 'user=USERNAME&uid=UID&role=' part of the cookie is exactly 2 blocks long
    # 15
    username1 = "A" * (block_size - len("user=&uid=1&role="))
    cookie1 = bytes.fromhex("170f3e9656771270a4a71dc63e7323b07c5f1e6503fbd2a73e15461305f857c23b7de57cb6327ef2e1b7082bc0960629")
    # Create another user with a username such that the 'user=USERNAME&uid=UID&role=user' part of the cookie is exactly 2 blocks long
    # 11
    # username2 = "B" * (block_size - len("user=&uid=1&role=user"))
    # cookie2 = bytes.fromhex("26b27be2792db071651135cab6d73352ad8f39c7693d44cce9b7d210b9428b6abe6fd070b457bbcdce744af968947c60")
    # Replace the 'user' block in our first cookie with the 'admin' block from our second cookie
    # admin_cookie = cookie1[:2*BLOCK_SIZE] + cookie2[2*BLOCK_SIZE:4*BLOCK_SIZE] + cookie1[3*BLOCK_SIZE:]
    admin_cookie = cookie1[:2*block_size] + "admin".encode()
    print("Admin cookie:", b64encode(admin_cookie).decode())


def main():
    test_ecb_mode()

    ecb_ciphertexts = detect_ecb_mode("Lab2.TaskII.B.txt")
    for i, ciphertext in ecb_ciphertexts:
        print(f"Ciphertext {i} is likely encrypted in ECB mode.")
        # Write the raw bytes to a file
        with open(f"ecb_image_{i}.bmp", "wb") as f:
            f.write(ciphertext)
        # Open the image file with an image viewer
        img = Image.open(BytesIO(ciphertext))
        img.show()

    create_cookie()

# brute force open all ciphertext images
# def main():
#     with open("Lab2.TaskII.B.txt", "r") as f:
#         ciphertexts = [bytes.fromhex(line.strip()) for line in f]
#     for i, ciphertext in enumerate(ciphertexts):
#         # Write the raw bytes to a file
#         with open(f"image_{i}.bmp", "wb") as f:
#             f.write(ciphertext)
#         # Open the image file with an image viewer
#         img = Image.open(BytesIO(ciphertext))
#         img.show()


if __name__ == "__main__":
    main()
