def receive_bytes(socket):
    """
    Receives a message from a socket with a predefined 10-byte length header.

    Args:
    socket (socket.socket): The socket from which to receive data.

    Returns:
    bytes or None: The received message as a bytes object or None if no data is received.
    """
    # Read the 10-byte length header
    length_str = socket.recv(10).decode()
    if not length_str:
        return None  # Handle the case where no data is received

    # Convert length to int and remove any padding
    message_length = int(length_str.strip())
    full_message = b''
    while len(full_message) < message_length:
        # Receive data in chunks of 1024 bytes
        chunk = socket.recv(1024)
        if not chunk:
            break  # Break from loop if no more data is received
        full_message += chunk

    return full_message

def parse_boolean(string):
    """
    Converts a string to a boolean.

    Args:
    string (str): The string to convert.

    Returns:
    bool: The boolean value of the string.

    Raises:
    ValueError: If the string does not represent a boolean.
    """
    if string.lower() == 'false':
        return False
    elif string.lower() == 'true':
        return True
    else:
        raise ValueError("String not valid")

def send_data_len(client_socket, data):
    """
    Sends data preceded by a 10-byte length header over a socket.

    Args:
    client_socket (socket.socket): The socket to send data through.
    data (str): The data to send.

    """
    # Format the length header to be 10 bytes, left-aligned
    length_header = f"{len(data):<10}"
    # Send the length header followed by the actual data
    client_socket.sendall(length_header.encode('utf-8') + data.encode('utf-8'))
