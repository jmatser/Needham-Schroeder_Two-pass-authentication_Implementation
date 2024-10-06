import ascon
from base64 import b64encode, b64decode
import json
from Crypto.Random import get_random_bytes


def encrypt_ascon(data, key, hash, type_alg=None):
    """
    Encrypt data using the Ascon authenticated encryption algorithm.

    Args:
    data (bytes): The plaintext data to encrypt.
    key (bytes): The secret key used for encryption.
    hash (bytes): The hash of the data, used for additional data integrity.
    type_alg (str, optional): Specifies the type of protocol (for indicating if it is part of key establishment, authetication or data reception).

    Returns:
    str: A JSON string containing the nonce, ciphertext, and hash, and optionally the protocol type.
    """
    # Generate a random nonce
    nonce_bytes = get_random_bytes(16)
    # Encrypt the data using the Ascon encryption function
    ciphertext = ascon.encrypt(key, nonce_bytes, "", data)
    # Encode the nonce, ciphertext, and hash into base64 for JSON serialization
    nonce = b64encode(nonce_bytes).decode('utf-8')
    ct = b64encode(ciphertext).decode('utf-8')
    hs = b64encode(hash).decode('utf-8')
    # Create a JSON object with the relevant data
    if type_alg == None:
        result = json.dumps({'nonce': nonce, 'ciphertext': ct, 'hash': hs})
    else:
        result = json.dumps({'nonce': nonce, 'ciphertext': ct, 'hash': hs, 'Type': type_alg})
    return result


def decrypt_ascon(json_input, key):
    """
    Decrypt data using the Ascon authenticated decryption algorithm.

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
        # Decode the hash
        retrieved_hash = b64decode(b64['hash'])
        # Decrypt the ciphertext using the Ascon decryption function
        plaintext = ascon.decrypt(key, nonce, "", ciphertext)
        return plaintext, retrieved_hash
    except:
        # Handle exceptions caused by incorrect keys or data format
        print("Incorrect decryption")
        return -1

if __name__ == "__main__":
    # Define the secret key and plaintext data
    key = b'BailaViniJr12345'  # 16 bytes key
    data = b'Por esos campos de Espana'

    # Encrypt and then decrypt the data
    enc = encrypt_ascon(data, key)
    dec = decrypt_ascon(enc, key)
    print(dec)
