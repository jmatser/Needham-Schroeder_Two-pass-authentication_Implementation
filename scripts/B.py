"""
Usage:
    B.py <encryption_algorithm> <hash_algorithm> <log_level>

This script initiates a server for continuing the process of the Needham–Schroeder protocol as B for establishing the key with A.
Later on, two-pass mutual authentication based on ISO/IEC 9798-2 is performed.
Finally, the encrypted content is received from A which will be printed in the terminal after decryption.
It uses the specified algorithms for encryption and hashing, with a configurable logging level.

Arguments:
    encryption_algorithm (str): The encryption algorithm to use. Can be either 'ascon' or 'chacha'.
    hash_algorithm (str):       The hashing algorithm to use for generating and comparing hashes. Can be either 'ascon' or 'sha256'.
    log_level (int):            An integer from 0 to 4, where 0 represents basic logging and 4 represents the most detailed logging available.

Examples:
    Launch the server using Ascon for both encryption and hashing with medium logging:
        $ python3 B.py ascon ascon 2

    Launch the server using ChaCha for encryption, SHA-256 for hashing, and minimal logging:
        $ python3 B.py chacha sha256 0

"""

import json
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

KEY_SERVER_CHACHA = b"PresharedKeyWithB012345678901234" #32 bytes
KEY_SERVER_ASCON = b"PresharedKeyB012" #16 bytes
IDa = 'A'
IDb = 'B'


#----------------------------------------- LOGGER SET UP ------------------------------------------------
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



#----------------------------------------- B ------------------------------------------------


def A_contact_server():
    """
    Function to handle the connection and authentication of B.
    It sets up a server, listens for connections, and handles data exchange based on the encryption type.
    
    Parameters:
        None, but uses global variables such as KEY_SERVER_CHACHA and KEY_SERVER_ASCON.
        
    Returns:
        None, but establishes a socket server and handles client communications.
    """


    #Selecting the corresponding preshared key
    if encryption == 'chacha':
        key_server = KEY_SERVER_CHACHA
    elif encryption == 'ascon':
        key_server = KEY_SERVER_ASCON
    else:
        log_basic("Wrong encryption algorithm")
        return -1
    
    #Dicts to store the established keys (managed to be able to handle more than one A in future implementations) and the different authentications
    established_keys = {}
    authentication = {}


    #Starting server at localhost:8081 and listen
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 8081)
    sock.bind(server_address)
    sock.listen(1)
    log_basic('B server started')


    while True:
        #Accepting connection and retrieving data received
        client_socket, client_address = sock.accept()

        #Decoding the data and loading it back as a JSON
        data_original = receive_bytes(client_socket).decode('utf-8')
        data = json.loads(data_original)

        if data:
            #Check the attribute Type is found in the JSON as it is necessary to determine what protocol is being realized
            if 'Type' in data:

                #Type == 1: New shared key
                if data['Type'] == 1:

                    #Step 3: Receiving the JSON generated in the key server and then sent to B through A
                    log_protocols("Received JSON data (Step 3 Key Establishment)")
                    log_protocols(data_original)

                    #Decrypting the JSON to obtain
                    log_encryption("Decrypting with " + encryption +  " key length " + str(len(key_server)) + " and hashing with " + hash_alg + ":")
                    response_decrypted = decrypt(encryption, hash_alg, data_original, key_server)
                    log_encryption_data("Finished decryption: " + response_decrypted.decode('utf-8'))
                    response_decrypted_json = json.loads(response_decrypted.decode('utf-8'))
                    
                    #Verify the IDa received is the ID of A
                    if response_decrypted_json['IDa'] == IDa:
                        #Decode the new key bytes
                        new_key = b64decode(response_decrypted_json['Kab'])
                        #Generate the JSON for sending in step 4 to A
                        data_to_send, nonceB = generate_response(new_key)

                        #Step 4: Sending the prevously generated JSON with a nonce value to A
                        log_protocols("Step 4 key establishment, sending data to " + response_decrypted_json['IDa'])
                        send_data_len(client_socket, data_to_send)

                        #Step 5: Receiving from A the encrypted JSON with the Nonce minus 1
                        data_final = receive_bytes(client_socket).decode('utf-8')
                        log_protocols("Received JSON data (Step 5 Key Establishment)")
                        log_protocols(data_final)
                        if data_final:
                            try:
                                #Decrypt the received JSON
                                log_encryption("Decrypting with " + encryption +  " key length " + str(len(new_key)) + " and hashing with " + hash_alg + ":")
                                final_response_decrypted = decrypt(encryption, hash_alg, data_final, new_key)
                                final_response_decrypted_json = json.loads(final_response_decrypted.decode('utf-8'))
                                log_encryption_data("Finished decryption: " + final_response_decrypted.decode('utf-8'))

                                #Verify that the received data is just a Nonce
                                if len(final_response_decrypted_json) == 1 and 'NonceB' in final_response_decrypted_json:
                                    #Verify that the received value is correct (NonceB - 1)
                                    if final_response_decrypted_json['NonceB'] == (nonceB - 1):
                                        #The correct calculation means that A also has the key and is alive
                                        #Storing the key as the protocol has finished succesfully
                                        log_basic("A has the key and is still alive")
                                        established_keys[response_decrypted_json['IDa']] = new_key

                                        #Setting IDa as non-autheticated
                                        authentication[IDa] = {}
                                        authentication[IDa]['Auth'] =  False
                                        authentication[IDa]['timestamp'] = None
                                        

                                    else:
                                        log_basic("Wrong operation on NonceB")
                                else:
                                    log_basic("Error with final step Key Authentication")
                            except:
                                log_basic("Error verifying A")
                        else:
                            log_basic("Error with the Identity of the A")

                #Type == 2: Authentication
                elif data['Type'] == 2:
                    #Receiving the encrypted JSON corresponding to the step 1
                    log_protocols("Received JSON data (Step 1 Authentication)")
                    log_protocols(data_original)

                    #Decrypting the received JSON
                    log_encryption("Decrypting with " + encryption +  " key length " + str(len(established_keys[IDa])) + " and hashing with " + hash_alg + ":")
                    auth_pass_decrypted = decrypt(encryption, hash_alg, data_original, established_keys[IDa])
                    log_encryption_data("Finished decryption: " + auth_pass_decrypted.decode('utf-8'))
                    auth_pass_decrypted_json = json.loads(auth_pass_decrypted.decode('utf-8'))

                    #Verify that the decrypted data is for requesting authentication
                    if len(auth_pass_decrypted_json) == 2 and 'timestamp' in auth_pass_decrypted_json and 'IDb' in auth_pass_decrypted_json:
                        log_protocols("A requested authentication")

                        #Verify the freshness of the message by checking if the Id is correct and the timestamp was generated a maximum of 5 seconds before
                        actual_timestamp = int(time.time())
                        timestamp_A = auth_pass_decrypted_json["timestamp"]
                        if auth_pass_decrypted_json["IDb"] == IDb and timestamp_A <= actual_timestamp and timestamp_A >= (actual_timestamp - 5):
                            log_protocols("Correct authentication")

                            #Setting the authentication to True and the timestamp when it was authenticated
                            authentication[IDa]['Auth'] = True
                            authentication[IDa]['timestamp'] = int(time.time())

                            #Generate the JSON for step 1 with the timestamp and the ID of A 
                            auth_sec_pass = generate_authentication_pass(established_keys[IDa])

                            #Step 2: Sending the generated JSON to A
                            log_protocols("Step 2 Authentication, sending data to A")
                            send_data_len(client_socket, auth_sec_pass)
                            '''length_header = f"{len(auth_sec_pass):<10}"
                            client_socket.sendall(length_header.encode('utf-8') + auth_sec_pass.encode('utf-8'))'''

                        else:
                            log_protocols("Incorrect authentication")
                            authentication[IDa]['Auth'] =  False
                            authentication[IDa]['timestamp'] = None

                #Type == 3: Data reception
                elif data['Type'] == 3:
                    #To be able to receive the data, A has to be authenticated a maximum of 10 seconds before
                    #Verify the authentication
                    actual_time = int(time.time())
                    if authentication[IDa]['Auth'] == True and authentication[IDa]['timestamp'] <= actual_time and authentication[IDa]['timestamp'] >= (actual_timestamp - 10):
                        log_basic("Receiving data after correct authetication")

                        #Decrypt the received data
                        log_encryption("Decrypting with " + encryption +  " key length " + str(len(established_keys[IDa])) + " and hashing with " + hash_alg + ":")
                        data_decrypted = decrypt(encryption, hash_alg, data_original, established_keys[IDa])

                        #Return the decrypted bytes to the original string
                        content_received = data_decrypted.decode('utf-8')

                        log_basic("Decoding and printing the received data")

                        #Print the received data
                        print(content_received)

                    else:
                        log_basic("Received data before correct authentication")

                #Wrong type
                else:
                    log_basic("Wrong type set")


            #No type
            else:
                log_basic("No type set")


        # Close the client connection
        client_socket.close()

    sock.close()


def generate_response(key):
    """
    Generate a response for a key establishment step with a new nonce.
    
    Parameters:
        key (bytes): The encryption key to use for securing the response.
        
    Returns:
        tuple: Encrypted response bytes and the nonce used in the response.
    """
     
    Nb = int.from_bytes(get_random_bytes(32), byteorder='big')
    response = {
        "NonceB": Nb
    }

    log_encryption("Encrypting with " + encryption +  " key length " + str(len(key)) + " and hashing with " + hash_alg + ":")
    log_encryption_data(response)

    response_bytes = json.dumps(response).encode('utf-8')
    response_encrypted = encrypt(encryption, hash_alg, response_bytes, key)
    log_encrypted_data("Finished encryption: " + response_encrypted)

    return response_encrypted, response['NonceB']


def generate_authentication_pass(key):
    """
    Generate a response for authentication with a timestamp.
    
    Parameters:
        key (bytes): The encryption key to use for securing the response.
        
    Returns:
        bytes: The encrypted authentication pass.
    """
    
    response = {
        "timestamp": int(time.time()),
        "IDa": IDa
    }

    log_encryption("Encrypting with " + encryption +  " key length " + str(len(key)) + " and hashing with " + hash_alg + ":")
    log_encryption_data(response)
    response_bytes = json.dumps(response).encode('utf-8')
    response_encrypted = encrypt(encryption, hash_alg, response_bytes, key, 2)
    log_encrypted_data("Finished encryption: " + response_encrypted)

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