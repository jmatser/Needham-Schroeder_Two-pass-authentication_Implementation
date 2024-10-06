import json
from base64 import b64encode, b64decode
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes


def encrypt_chacha(data, key, hash, type_alg=None):
    """
    Encrypt data using the ChaCha20 cipher.

    Args:
    data (bytes): The plaintext data to encrypt.
    key (bytes): The secret key used for encryption.
    hash (bytes): The hash of the data, for integrity.
    type_alg (str, optional): Specifies the type of protocol (for indicating if it is part of key establishment, authetication or data reception).

    Returns:
    str: A JSON string containing the nonce, ciphertext, and hash, and optionally the protocol type.
    """
    # Generate a random nonce
    nonce_bytes = get_random_bytes(8)
    # Create a new ChaCha20 cipher object with the given key and nonce
    cipher = ChaCha20.new(key=key, nonce=nonce_bytes)
    # Encrypt the data
    ciphertext = cipher.encrypt(data)
    # Encode the nonce, ciphertext, and hash to base64 for JSON serialization
    nonce = b64encode(nonce_bytes).decode('utf-8')
    ct = b64encode(ciphertext).decode('utf-8')
    hs = b64encode(hash).decode('utf-8')
    # Create a JSON object with the relevant data
    if type_alg == None:
        result = json.dumps({'nonce':nonce, 'ciphertext':ct, 'hash':hs})
    else:
        result = json.dumps({'nonce':nonce, 'ciphertext':ct, 'hash':hs, 'Type':type_alg})
    return result

def decrypt_chacha(json_input, key):
    """
    Decrypt data using the ChaCha20 cipher.

    Args:
    json_input (str): The JSON string containing the encrypted data.
    key (bytes): The secret key used for decryption.

    Returns:
    tuple: The plaintext data and the retrieved hash, or -1 in case of an error.
    """
    try:
        # Parse the JSON input and extract the base64-encoded fields
        b64 = json.loads(json_input)
        nonce = b64decode(b64['nonce'])
        ciphertext = b64decode(b64['ciphertext'])
        # Create a new ChaCha20 cipher object for decryption
        cipher = ChaCha20.new(key=key, nonce=nonce)
        # Decode the hash
        retrieved_hash = b64decode(b64['hash'])
        # Decrypt the ciphertext
        plaintext = cipher.decrypt(ciphertext)

        return plaintext, retrieved_hash
    except (ValueError, KeyError):
        # Handle exceptions caused by incorrect keys or data format
        print("Incorrect decryption")
        return -1

if __name__ == "__main__":
    # Define the secret key and plaintext data
    key = b"BailaViniJr123456789123456789012" # 32 bytes key
    data = b'Por esos campos de Espana'

    # Encrypt and then decrypt the data
    enc = encrypt_chacha(data, key)
    dec = decrypt_chacha(enc, key)
    print(dec)
