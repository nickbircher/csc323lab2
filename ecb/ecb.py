from Crypto.Cipher import AES
from base64 import b64decode
from util import hex_to_bytes, bytes_to_hex
import pkcs7
from PIL import Image
from io import BytesIO
import requests


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
    # Read the ciphertexts from the file
    with open(filename, "r") as f:
        ciphertexts = [bytes.fromhex(line.strip()) for line in f]
    
    block_size = AES.block_size 
    
    ecb_ciphertexts = []
    for i, ciphertext in enumerate(ciphertexts):
        # Divide the ciphertext into blocks of size equal to the block size
        blocks = [ciphertext[j:j+block_size] for j in range(54, len(ciphertext), block_size)]
        
        # Check if there are any duplicate blocks
        if len(blocks) != len(set(blocks)):
            # If duplicate blocks are found, add the index and ciphertext to the list
            ecb_ciphertexts.append((i, ciphertext))
    
    return ecb_ciphertexts
    

def register_user(username: str, password: str) -> None:
    """
    Registers a user with the server
    """
    url = "http://localhost:8080/register"
    data = {"user": username, "password": password}
    with requests.Session() as session:
        response = session.post(url, data=data)
        return session.cookies.get("auth_token")
  
  
def login_user(username: str, password: str) -> str:
    """
    Logs in a user with the server and returns the cookie
    """
    url = "http://localhost:8080/"
    data = {"user": username, "password": password}
    with requests.Session() as session:
        response = session.post(url, data=data)
        return session.cookies.get("auth_token")
  
  
def login_home(cookie: str) -> str:
    """
    Logs in a user with the server using a cookie
    """
    url = "http://localhost:8080/home"
    with requests.Session() as session:
        response = session.get(url, cookies={"auth_token": cookie})
        return response.text


def create_ebc_cookie() -> str:
    """
    Creates a cookie using ECB mode of operation for a block cipher
    Cookies in the server follow the format user=USERNAME&uid=UID&role=ROLE
    where:
    * USERNAME is the registered username of the user
    * UID is arbitrary but unique across users
    * ROLE is always "user" for self-regular users, but can be "admin" for administrators
    Goal: create a valid cookie that gives administrator access
    """
    # each block is 16 bytes long (AES block size)
    # user=00000000000 admin0000000000B &uid=1&role=user
    username_block_1 = "0" * 11 # this will fill up the first block of the cookie, prepended with "user="
    username_block_2 = "admin" + chr(0) * 10 + chr(11) # this will fill up the second block of the cookie
    username_1 = username_block_1 + username_block_2 # 32 bytes long
    password = "password" # arbitrary password
    # user=00000000000 0000&uid=1&role=
    username_2 = "0" * 15 # this will fill up the entire first block of the cookie
    
    # create a cookie with the username and password
    register_user(username_1, password)
    register_user(username_2, password)

    encoded_cookie_1 = login_user(username_1, password)
    cookie_1: bytes = hex_to_bytes(encoded_cookie_1)
    
    encoded_cookie_2 = login_user(username_2, password)
    cookie_2: bytes = hex_to_bytes(encoded_cookie_2)
        
    # extract blocks from both generated cookies to form the admin cookie
    # user=00000000000 0000&uid=1&role= admin0000000000B
    result = cookie_2[:32] + cookie_1[16:32]
    admin_cookie = bytes_to_hex(result)
    print("Admin cookie: ", admin_cookie)
    return admin_cookie


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

    admin_cookie = create_ebc_cookie()
    print(login_home(admin_cookie))


if __name__ == "__main__":
    main()
