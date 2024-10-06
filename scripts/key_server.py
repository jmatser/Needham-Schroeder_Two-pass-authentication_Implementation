"""
Usage:
    key_server.py <encryption_algorithm> <hash_algorithm> <log_level>

This script initiates the key server for the Needham–Schroeder protocol that uses the specified algorithms for encryption and hashing, with a configurable logging level.

Arguments:
    encryption_algorithm (str): The encryption algorithm to use. Can be either 'ascon' or 'chacha'.
    hash_algorithm (str):       The hashing algorithm to use for generating and comparing hashes. Can be either 'ascon' or 'sha256'.
    log_level (int):            An integer from 0 to 4, where 0 represents basic logging and 4 represents the most detailed logging available.

Examples:
    Launch the server using Ascon for both encryption and hashing with medium logging:
        $ python3 key_server.py ascon ascon 2

    Launch the server using ChaCha for encryption, SHA-256 for hashing, and minimal logging:
        $ python3 key_server.py chacha sha256 0

"""

import json
import socket
from base64 import b64encode, b64decode
import secrets
import sys
sys.path.append('../encryption')
from enc import encrypt
sys.path.append('../utils')
from utils import receive_bytes, send_data_len
import logging

# ------------------------- LOGGER SETUP -------------------------------------
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

# ------------------------- KEY SERVER ----------------------------------------

# Preshared keys for the two types of encryption algorithms used in communication.
preshared_keys_chacha = {
    "A": b"PresharedKeyWithA123456789012345",
    "B": b"PresharedKeyWithB012345678901234"
}

preshared_keys_ascon = {
    "A": b"PresharedKeyA123",
    "B": b"PresharedKeyB012"
}

def A_contact_server():
    """Starts a server to handle key distribution and encrypted communication.
    
    The server runs indefinitely, accepting connections and handling data received from A to generate the step two of the Needham–Schroeder key establishment protocol.
    """

    #Starting server at localhost:8080 and listen
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 8080)
    sock.bind(server_address)
    sock.listen(1)
    log_basic('Key server started')
    

    while True:
        #Accepting connection and retrieving data received
        client_socket, client_address = sock.accept()
        data = receive_bytes(client_socket).decode('utf-8')

        if data:
            json_data = json.loads(data)
            log_protocols("Received JSON data (Step 1 Key establishment):")
            log_protocols(json.dumps(json_data, indent=4))

        #With the data received in step 1 generate the JSON for step 2
        data_to_send = generate_response_step_2(json_data)
        if data_to_send != -1:
            log_protocols("Step 2 key establishment, sending data to " + json_data['IDa'])
            #Sending the step 2 JSON back to A
            send_data_len(client_socket, data_to_send)
        else:
            return -1

        client_socket.close()

    sock.close()

def generate_response_step_2(json_data):
    """Generates a response based on the received JSON data, encrypting it as per requested encryption method.
    JSON information corresponding to the step 2 of the Needham–Schroeder protocol
    
    Parameters:
    - json_data (dict): Parsed JSON data received from the client.
    
    Returns:
    - bytes: Encrypted response to be sent to the client.
    - int: Returns -1 in case of an error.
    """

    #Selecting the corresponding encryption algorithm and generating a new one for A and B
    if encryption == 'chacha':
        key_a = preshared_keys_chacha[json_data["IDa"]]
        key_b = preshared_keys_chacha[json_data["IDb"]]
        Kab = secrets.token_bytes(32)
    elif encryption == 'ascon':
        key_a = preshared_keys_ascon[json_data["IDa"]]
        key_b = preshared_keys_ascon[json_data["IDb"]]
        Kab = secrets.token_bytes(16)
    else:
        log_encryption("Wrong encryption algorithm")
        return -1



    #Generating the JSON encrypted with the Kbs key
    data_to_B = {
        "Kab": b64encode(Kab).decode('utf-8'),
        "IDa": json_data['IDa']
    }
    data_to_B_bytes = json.dumps(data_to_B).encode('utf-8')
    log_encryption(f"Encrypting with {encryption} key length {len(key_b)} and hashing with {hash_alg}:")
    log_encryption_data(data_to_B)
    data_to_B_encrypted = encrypt(encryption, hash_alg, data_to_B_bytes, key_b, 1)
    log_encrypted_data(f"Finished encryption: {data_to_B_encrypted}")



    #Generating the full JSON sent to A in Step 2, including the previous encrypted JSON
    response = {
        "Na": json_data['Na'],
        "IDb": json_data['IDb'],
        "Kab": b64encode(Kab).decode('utf-8'),
        "Data_to_B": data_to_B_encrypted
    }
    response_bytes = json.dumps(response).encode('utf-8')
    log_encryption(f"Encrypting with {encryption} key length {len(key_a)} and hashing with {hash_alg}:")
    log_encryption_data(response)
    response_encrypted = encrypt(encryption, hash_alg, response_bytes, key_a, 1)
    log_encrypted_data(f"Finished encryption: {response_encrypted}")

    return response_encrypted


def main():
    #Obtaining arguments from the terminal
    global encryption
    encryption = sys.argv[1]
    global hash_alg
    hash_alg = sys.argv[2]
    log = int(sys.argv[3])

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

    #Starting the server
    A_contact_server()


if __name__ == "__main__":
    main()
