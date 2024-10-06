from enc_ascon import encrypt_ascon, decrypt_ascon
from enc_chacha import encrypt_chacha, decrypt_chacha
import ascon
from Crypto.Hash import SHA256

def encrypt(enc, hash_alg, data, key, type_alg=None):
    """
    Encrypt data with specified encryption and hashing algorithms.

    Args:
    enc (str): Type of encryption ('chacha' or 'ascon').
    hash_alg (str): Hashing algorithm ('ascon' or 'sha256').
    data (bytes): Data to be encrypted.
    key (bytes): Encryption key.
    type_alg (str, optional): Additional algorithm type specifier.

    Returns:
    str or int: Encrypted data in JSON format, or -1 if an error occurs.
    """
    hash = hash_data(hash_alg, data)
    if enc == 'chacha':
        return encrypt_chacha(data, key, hash, type_alg)
    elif enc == 'ascon':
        return encrypt_ascon(data, key, hash, type_alg)
    else:
        print("Wrong encryption algorithm")
        return -1
    
def decrypt(enc, hash_alg, data, key):
    """
    Decrypt data and verify integrity using specified encryption and hashing algorithms.

    Args:
    enc (str): Type of encryption used ('chacha' or 'ascon').
    hash_alg (str): Hashing algorithm used ('ascon' or 'sha256').
    data (str): Encrypted data in JSON format.
    key (bytes): Decryption key.

    Returns:
    bytes or int: Decrypted data if hash verification is successful, -1 otherwise.
    """
    if enc == 'chacha':
        data_decrypted, retrieved_hash = decrypt_chacha(data, key)
    elif enc == 'ascon':
        data_decrypted, retrieved_hash = decrypt_ascon(data, key)
    else:
        print("Wrong encryption algorithm")
        return -1
    
    if check_hash(hash_alg, data_decrypted, retrieved_hash):
        return data_decrypted
    else:
        return -1
    
def hash_data(hash_alg, data):
    """
    Hash data using specified algorithm.

    Args:
    hash_alg (str): Hashing algorithm ('ascon' or 'sha256').
    data (bytes): Data to hash.

    Returns:
    bytes or int: Hashed data, or -1 if a wrong hashing algorithm is used.
    """
    if hash_alg == 'ascon':
        hash = ascon.hash(data)
    elif hash_alg == 'sha256':
        hash_object = SHA256.new(data=data)
        hash = hash_object.digest()
    else:
        print("Wrong hashing algorithm")
        return -1
    return hash

def check_hash(hash_alg, data, retrieved_hash):
    """
    Verify if the calculated hash matches the retrieved hash.

    Args:
    hash_alg (str): Hashing algorithm used.
    data (bytes): Original data.
    retrieved_hash (bytes): Hash retrieved from the decryption process.

    Returns:
    bool: True if hashes match, False otherwise.
    """
    calculated_hash = hash_data(hash_alg, data)
    if calculated_hash == retrieved_hash:
        return True
    else:
        return False
