import base64

import requests

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

def calculate_bitmasks(original, target):
    bitmasks = []
    for i in range(len(original)):
        # Calculate the bitmask
        bitmask = ord(original[i]) ^ ord(target[i])
        bitmasks.append(bitmask)

    return bitmasks

def flip_bits(cookie):
    # Decode the cookie from hex
    decoded_cookie = bytes.fromhex(cookie)

    # Convert to a list of characters for easy modification
    cookie_chars = list(decoded_cookie)

    # Add a junk block to cookie_chars at the end of the first block
    cookie_chars = cookie_chars[:32] + cookie_chars[16:32] + cookie_chars[32:]

    masks = calculate_bitmasks("&role=user" + chr(0) * 5 + chr(6), "&role=admin" + chr(0) * 4 + chr(5))

    # Flip the necessary bits in the second block
    for i, mask in enumerate(masks):
        # Flip the bits by XORing with the bitmask
        cookie_chars[32 + i] ^= mask

    # Convert back to a string
    modified_cookie = bytes(cookie_chars)

    # Re-encode the cookie as hex
    encoded_cookie = modified_cookie.hex()

    return encoded_cookie

# IV00000000000000 user=12345&uid=1 user=12345&uid=1 &role=user000006
def main():
    register_user("12345", "password")
    cookie = login_user("12345", "password")

    # Flip the bits in the cookie
    flipped_cookie = flip_bits(cookie)

    print(login_home(flipped_cookie))

if __name__ == "__main__":
    main()