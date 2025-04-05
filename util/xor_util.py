def xor_mask(data, key):
    # Encode data and key to byte
    data = data.encode('utf-8')    
    key = key.encode('utf-8')

    # Extend key if not equal to data
    if len(key) < len(data):
        key = (key * (len(data) // len(key) + 1))[:len(data)]

    # Perform XOR masking
    masked_data = bytes([d ^ k for d, k in zip(data, key)])
    
    return masked_data


def xor_unmask(masked_data, key):
    # Encode key to byte
    key = key.encode('utf-8')

    # Extend key if not equal to data
    if len(key) < len(masked_data):
        key = (key * (len(masked_data) // len(key) + 1))[:len(masked_data)]
    
    # Perform XOR unmasking (which is the same as masking)
    original_data = bytes([m ^ k for m, k in zip(masked_data, key)])
    
    # Attempt to decode
    try:
        return original_data.decode('utf-8')
    except UnicodeDecodeError:
        return original_data