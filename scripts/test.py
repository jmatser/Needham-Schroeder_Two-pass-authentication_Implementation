import ascon
import time
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import pandas as pd
import matplotlib.pyplot as plt

def calculate_ascon(data, nonce_bytes, key):
    """
    Measure the time taken to encrypt and decrypt data using the Ascon algorithm.

    Args:
    data (bytes): Data to encrypt and decrypt.
    nonce_bytes (bytes): Random bytes used as nonce for encryption.
    key (bytes): Key used for encryption.

    Returns:
    tuple: Execution time for encryption and decryption in milliseconds.
    """
    start_time = time.time()
    ciphertext = ascon.encrypt(key, nonce_bytes, "", data)
    end_time = time.time()
    ex_time_enc = (end_time - start_time) * 1000

    start_time = time.time()
    plaintext = ascon.decrypt(key, nonce_bytes, "", ciphertext)
    end_time = time.time()
    ex_time_dec = (end_time - start_time) * 1000

    return ex_time_enc, ex_time_dec

def calculate_chacha(data, nonce_bytes, key):
    """
    Measure the time taken to encrypt and decrypt data using the ChaCha20 algorithm.

    Args:
    data (bytes): Data to encrypt and decrypt.
    nonce_bytes (bytes): Random bytes used as nonce for encryption.
    key (bytes): Key used for encryption.

    Returns:
    tuple: Execution time for encryption and decryption in milliseconds.
    """
    start_time = time.time()
    cipher = ChaCha20.new(key=key, nonce=nonce_bytes)
    ciphertext = cipher.encrypt(data)
    end_time = time.time()
    ex_time_enc = (end_time - start_time) * 1000

    start_time = time.time()
    cipher_dec = ChaCha20.new(key=key, nonce=nonce_bytes)
    plaintext = cipher_dec.decrypt(ciphertext)
    end_time = time.time()
    ex_time_dec = (end_time - start_time) * 1000

    return ex_time_enc, ex_time_dec

def main(n_tests):
    """
    Main function to test and plot encryption and decryption times of Ascon and ChaCha20.

    Args:
    n_tests (int): Number of tests to run, determines the maximum data size.
    """
    # Initialize nonces and keys for both algorithms
    nonce_ascon = get_random_bytes(16)
    nonce_chacha = get_random_bytes(8)
    key_ascon = get_random_bytes(16)
    key_chacha = get_random_bytes(32)

    # Generate data sizes for testing
    sequence = [16 * (2 ** i) for i in range(n_tests)]
    ascon_times_enc = {"Algorithm": "Ascon"}
    ascon_times_dec = {"Algorithm": "Ascon"}
    chacha_times_enc = {"Algorithm": "Chacha"}
    chacha_times_dec = {"Algorithm": "Chacha"}

    # Run tests for each data size
    for n in sequence:
        data_to_encrypt = get_random_bytes(n)
        ascon_times_enc[n], ascon_times_dec[n] = calculate_ascon(data_to_encrypt, nonce_ascon, key_ascon)
        chacha_times_enc[n], chacha_times_dec[n] = calculate_chacha(data_to_encrypt, nonce_chacha, key_chacha)

    # Organize data into DataFrames
    final_df_enc = pd.DataFrame([ascon_times_enc, chacha_times_enc])
    final_df_enc.set_index('Algorithm', inplace=True)
    final_df_dec = pd.DataFrame([ascon_times_dec, chacha_times_dec])
    final_df_dec.set_index('Algorithm', inplace=True)

    # Create plots
    fig, axes = plt.subplots(nrows=1, ncols=2, figsize=(20, 6))
    final_df_enc.T.plot(marker='o', ax=axes[0])
    axes[0].set_title('Time vs. Bytes Used for Encryption Algorithms')
    axes[0].set_xlabel('Bytes Used')
    axes[0].set_ylabel('Time (milliseconds)')
    axes[0].grid(True)
    axes[0].legend(title='Algorithm')

    final_df_dec.T.plot(marker='o', ax=axes[1])
    axes[1].set_title('Time vs. Bytes Used for Decryption Algorithms')
    axes[1].set_xlabel('Bytes Used')
    axes[1].set_ylabel('Time (milliseconds)')
    axes[1].grid(True)
    axes[1].legend(title='Algorithm')

    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    main(8)
