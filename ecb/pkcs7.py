
def pkcs7_pad(message, block_size):
    pad_length = block_size - (len(message) % block_size)
    padding = bytes([pad_length]) * pad_length
    return message + padding


def pkcs7_unpad(padded_message, block_size):
    pad_length = padded_message[-1]
    if pad_length > block_size or pad_length == 0:
        raise ValueError("Invalid padding")
    for i in range(1, pad_length + 1):
        if padded_message[-i] != pad_length:
            raise ValueError("Invalid padding")
    return padded_message[:-pad_length]


def test_pkcs7_padding():
    block_size = 16
    message = b"Hello world"
    padded_message = pkcs7_pad(message, block_size)
    assert len(padded_message) % block_size == 0
    unpadded_message = pkcs7_unpad(padded_message, block_size)
    assert message == unpadded_message

    # Test with a message that is a multiple of the block size
    message = b"Hello world" * 2
    padded_message = pkcs7_pad(message, block_size)
    assert len(padded_message) % block_size == 0
    unpadded_message = pkcs7_unpad(padded_message, block_size)
    assert message == unpadded_message

    # Test with invalid padding
    try:
        pkcs7_unpad(b"Invalid padding" + bytes([3, 2, 3]), block_size)
    except ValueError:
        pass
    else:
        assert False, "Expected a ValueError"


def main(): 
    test_pkcs7_padding()


if __name__ == "__main__":
    main()