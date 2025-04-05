import numpy as np
from PIL import Image

def encode_msg(msg, input="cover.png", output="cover_secret.png"):
    # Process message
    # b_msg = ''.join(["{:08b}".format(ord(x)) for x in msg ])
    # b_msg = [int(x) for x in b_msg]
    # b_msg_length = len(b_msg)
    b_msg = [format(byte, '08b') for byte in msg]
    b_msg = [int(bit) for byte in b_msg for bit in byte]
    b_msg_length = len(b_msg)

    # Open image
    with Image.open(input) as img:
        width, height = img.size
        data = np.array(img)
        
    # Modify last bit
    data = np.reshape(data, width*height*3)
    data[:b_msg_length] = data[:b_msg_length] & 0 | b_msg
    data = np.reshape(data, (height, width, 3))

    # Save encoded image
    new_img = Image.fromarray(data)
    new_img.save(output)

def decode_msg(length = 8, input="cover.png", byte = True):
    # Open encoded image
    with Image.open(input) as img:
        width, height = img.size
        data = np.array(img)
        
    # Extract last bit and combine into byte
    data = np.reshape(data, width*height*3)
    data = data & 1 
    data = np.packbits(data)

    # Read and convert to string
    if not byte:
        res = ""
        for x in data:
            l = chr(x)
            if len(res) >= length:
                break
            res += l
        return res

    return bytes(data[:length])