"""
Usage:
    A.py <encryption_algorithm> <hash_algorithm> <log_level> <file_to_send>

This script initiates the Needham–Schroeder protocol as A for establishing the key with B through the key server.
Later on, two-pass mutual authentication based on ISO/IEC 9798-2 is performed.
Finally, an encrypted text file is obtained and sent to B.
It uses the specified algorithms for encryption and hashing, with a configurable logging level.

Arguments:
    encryption_algorithm (str): The encryption algorithm to use. Can be either 'ascon' or 'chacha'.
    hash_algorithm (str):       The hashing algorithm to use for generating and comparing hashes. Can be either 'ascon' or 'sha256'.
    log_level (int):            An integer from 0 to 4, where 0 represents basic logging and 4 represents the most detailed logging available.
    file_to_send (str):         File with the data for sending to B

Examples:
    Launch the script using Ascon for both encryption and hashing with medium logging and a file in the parent folder:
        $ python3 A.py ascon ascon 2 ../data_to_send.txt

    Launch the script using ChaCha for encryption, SHA-256 for hashing, minimal logging and a file in the same folder of the script:
        $ python3 A.py chacha sha256 0 ./data_to_send.txt

"""

import json
import os
import pickle
import socket
import sys
from base64 import b64encode, b64decode
import time
sys.path.append('../encryption')
from enc import encrypt, decrypt
from Crypto.Random import get_random_bytes
sys.path.append('../utils')
from utils import receive_bytes, send_data_len
import logging

KEY_SERVER_CHACHA = b"PresharedKeyWithA123456789012345"  # 32 bytes
KEY_SERVER_ASCON = b"PresharedKeyA123"  # 16 bytes

# ----------------------------------------- LOGGER SET UP ------------------------------------------------
# Configures a custom logger for various debug levels to capture operational logs.

logger = logging.getLogger('my_custom_logger')
console_handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

def log_basic(message):
    """Logs basic operational messages at CRITICAL level.
    
    Parameters:
    - message (str): The message to be logged.
    """
    logger.critical(f'BASIC: {message}')

def log_protocols(message):
    """Logs protocol-specific messages at ERROR level.
    
    Parameters:
    - message (str): The message detailing protocol operations.
    """
    logger.error(f'PROTOCOLS: {message}')

def log_encryption(message):
    """Logs encryption operation details at WARNING level.
    
    Parameters:
    - message (str): The message detailing encryption operations.
    """
    logger.warning(f'ENCRYPTION: {message}')

def log_encryption_data(message):
    """Logs data that is about to be encrypted at INFO level.
    
    Parameters:
    - message (str): The message describing the data being encrypted.
    """
    logger.info(f'ENCRYPTION_DATA: {message}')

def log_encrypted_data(message):
    """Logs details of the encrypted data at DEBUG level.
    
    Parameters:
    - message (str): The message detailing the encrypted data.
    """
    logger.debug(f'ENCRYPTED_DATA: {message}')


#---------------------------------------------------- A ------------------------------------------------

key_B = None
IDa = 'A'
IDb = 'B'


def key_establishment(IDa, IDb):
    """Performs key establishment using Needham–Schroeder protocol with a key server.
    Parameters:
    - IDa (str): Identifier for party A.
    - IDb (str): Identifier for party B.
    Returns:
    - bytes or None: Returns the new key if successful, None otherwise.
    """
    log_basic("Started key establishment Needham–Schroeder")

    #Selecting the corresponding preshared key
    if encryption == 'chacha':
        key_server = KEY_SERVER_CHACHA
    elif encryption == 'ascon':
        key_server = KEY_SERVER_ASCON
    else:
        log_basic("Wrong encryption algorithm")
        return None
    
    #Generating step 1 JSON 
    Na = int.from_bytes(get_random_bytes(32), byteorder='big')
    dict_to_send = {"IDa": IDa, "IDb": IDb, "Na": Na}
    json_to_send = json.dumps(dict_to_send)
    log_protocols("Step 1 key establishment, sending data to key server")
    log_protocols(json_to_send)

    #Step 1: Sending the JSON to the key server
    key_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 8080)
    key_server_socket.connect(server_address)
    send_data_len(key_server_socket, json_to_send)

    #Step 2: Receiving the encrypted JSON of step 2 from the key server
    response = receive_bytes(key_server_socket)
    key_server_socket.close()

    #Decrypting the received JSON
    response_encrypted = response.decode('utf-8')
    log_protocols("Received JSON data encrypted (Step 2 Key Establishment)")
    log_protocols(response_encrypted)
    response_decrypted = decrypt(encryption, hash_alg, response_encrypted, key_server)
    response_decrypted_json = json.loads(response_decrypted.decode('utf-8'))
    log_encryption_data("Finished decryption: " + response_decrypted.decode('utf-8'))

    #Verify freshness by chekcing that the Nonce set is the same one that was previously sent
    if response_decrypted_json['Na'] != Na:
        log_protocols("Error, different Na")
        return None

    #Extracting the encrypted bytes for B received in step 2 (after the first decryption)
    json_to_B = response_decrypted_json['Data_to_B']

    #Step 3: Sending those bytes to B
    B_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    B_address = ('localhost', 8081)
    B_socket.connect(B_address)
    log_protocols("Step 3 key_establishment, sending data to " + IDb)
    log_protocols(str(json_to_B))
    send_data_len(B_socket, json_to_B)

    #Step 4: Receiving the encrypted JSON from B
    B_response = receive_bytes(B_socket)
    log_protocols("Received JSON data encrypted (Step 4 Key Establishment)")

    try:
        #Decrypting the received JSON with the new shared key between A and B
        B_response_encrypted = B_response.decode('utf-8')
        log_protocols(B_response_encrypted)
        B_response_decrypted = decrypt(encryption, hash_alg, B_response_encrypted, b64decode(response_decrypted_json['Kab']))
        B_response_decrypted_json = json.loads(B_response_decrypted.decode('utf-8'))
        log_encryption_data("Finished decryption: " + B_response_decrypted.decode('utf-8'))

        #Verify the received information (check that the received information is just a nonce from B) to be ensure that B received correctly the key
        if len(B_response_decrypted_json) == 1 and 'NonceB' in B_response_decrypted_json:
            log_protocols("B has the key, storing key")
            new_key = b64decode(response_decrypted_json['Kab'])

            #Generate a new JSON with the received nonce minus 1
            final_response = generate_response_B_step_5(B_response_decrypted_json, new_key)

            #Step 5: Sending the nonce minus 1 back to B
            log_protocols("Step 5 key establishment, sending data to " + IDb)
            send_data_len(B_socket, final_response)
            B_socket.close()
            return new_key
        else:
            return None
        
    except Exception as e:
        log_protocols(f"Error, B does not have the key: {str(e)}")
        return None

def authentication(key_B):
    """Performs two-pass mutual authentication based on ISO/IEC 9798-2.
    Parameters:
    - key_B (bytes): Key to use for authentication (key established between A and B).
    Returns:
    - bool: True if authentication succeeds, False otherwise.
    """

    #Start the authentication protocol by connecting to B
    log_basic("Started Two-pass mutual authentication protocol ISO/IEC 9798-2")
    B_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    B_address = ('localhost', 8081)
    B_socket.connect(B_address)

    #Generate the JSON for step 1 with the timestamp and the ID of B 
    auth_pass_json = generate_authentication_pass(IDb, key_B)

    #Step 1: Sending the generated JSON to B
    log_protocols("Step 1 authentication, sending data to " + IDb)
    send_data_len(B_socket, auth_pass_json)

    #Step 2: Receive the encrypted JSON from B with its authentication information
    B_response = receive_bytes(B_socket)
    log_protocols("Received JSON data encrypted (Step 2 Authentication)")

    try:
        #Decrypt the JSON with the established key between A and B
        B_response_encrypted = B_response.decode('utf-8')
        log_protocols(B_response_encrypted)
        B_response_decrypted = decrypt(encryption, hash_alg, B_response_encrypted, key_B)
        B_response_decrypted_json = json.loads(B_response_decrypted.decode('utf-8'))
        log_encryption_data("Finished decryption: " + B_response_decrypted.decode('utf-8'))

        #Verify the received message is the desired one
        if len(B_response_decrypted_json) == 2 and 'timestamp' in B_response_decrypted_json and 'IDa' in B_response_decrypted_json:

            #Verify the freshness of the message by checking if the Id is correct and the timestamp was generated a maximum of 5 seconds before
            actual_timestamp = int(time.time())
            timestamp_B = B_response_decrypted_json["timestamp"]
            if B_response_decrypted_json["IDa"] == IDa and timestamp_B <= actual_timestamp and timestamp_B >= (actual_timestamp - 5):
                log_protocols("Correct authentication")
                return True
            else:
                log_protocols("Incorrect authentication")
                return False
        else:
            log_protocols("Error in authentication")
            return False
    except Exception as e:
        log_protocols(f"Authentication error: {str(e)}")
        return False

def generate_response_B_step_5(B_response, key):
    """Generates the response for step 5 of the key establishment.
    Parameters:
    - B_response (dict): Decrypted response from B containing a nonce.
    - key (bytes): Shared secret key.
    Returns:
    - str: Encrypted response to be sent back to B.
    """

    response = {
        "NonceB": B_response['NonceB'] - 1
        }
    log_encryption("Encrypting with " + encryption +  " key length " + str(len(key)) + " and hashing with " + hash_alg + ":")
    response_bytes = json.dumps(response).encode('utf-8')
    response_encrypted = encrypt(encryption, hash_alg, response_bytes, key)
    log_encrypted_data("Finished encryption: " + response_encrypted)
    return response_encrypted

def generate_authentication_pass(IDb, key):
    """Generates authentication data to be sent to the other party.
    Parameters:
    - IDb (str): Identifier for party B.
    - key (bytes): Shared secret key.
    Returns:
    - str: Encrypted authentication data.
    """

    response = {
        "timestamp": int(time.time()), 
        "IDb": IDb
        }

    response_bytes = json.dumps(response).encode('utf-8')
    response_encrypted = encrypt(encryption, hash_alg, response_bytes, key, 2)
    log_encrypted_data("Finished encryption: " + response_encrypted)
    return response_encrypted

def send_data(data, key):
    """Encrypts and sends data securely to the connected device.
    Parameters:
    - data (bytes): Data to encrypt and send.
    - key (bytes): Key for encryption.
    Returns:
    - int: Status, 0 if sent successfully, -1 otherwise.
    """
    log_encryption("Encrypting with " + encryption +  " key length " + str(len(key)) + " and hashing with " + hash_alg + ":")
    encrypted = encrypt(encryption, hash_alg, data, key, 3)
    log_encrypted_data("Finished encryption")
    if encrypted != -1:
        #Connecting to B
        B_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        B_address = ('localhost', 8081)
        B_socket.connect(B_address)
        log_basic("Sending encrypted content to B")
        send_data_len(B_socket, encrypted)
        return 0
    else:
        return -1


def main():
    #Obtaining arguments from the terminal
    global encryption
    encryption = sys.argv[1]
    global hash_alg
    hash_alg = sys.argv[2]
    log = int(sys.argv[3])
    file_name = sys.argv[4]

    #Setting log level
    if log == 0:
        logger.setLevel(logging.CRITICAL)
        console_handler.setLevel(logging.CRITICAL)
    elif log == 1:
        logger.setLevel(logging.ERROR)
        console_handler.setLevel(logging.ERROR)
    elif log == 2:
        logger.setLevel(logging.WARNING)
        console_handler.setLevel(logging.WARNING)
    elif log == 3:
        logger.setLevel(logging.INFO)
        console_handler.setLevel(logging.INFO)
    elif log == 4:
        logger.setLevel(logging.DEBUG)
        console_handler.setLevel(logging.DEBUG)

    authenticate = {'Auth': False, 'timestamp': None}

    #Start key establishment protocol
    key_B = key_establishment("A", "B")
    log_basic("OBTAINED KEY: " + str(key_B))


    #Authenticate and verify that the authentication was performed correctly
    if authentication(key_B):
        authenticate = {'Auth': True, 'timestamp': int(time.time())}
        #Obtaining the content bytes for sending to B
        with open(file_name, 'rb') as file:
            content = file.read()
        log_basic("Read file")
        try:
            send_data(content, key_B)
        except:
            log_basic("Error in sending data")
    else:
        log_basic("Error in authentication, not sending data")


if __name__ == "__main__":
    main()
