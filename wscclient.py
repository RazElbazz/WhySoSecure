# imports
import socket
import time
# cryptography imports
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# DEFINITIONS
HOST = "127.0.0.1"
PORT = 65432

def generate_private_key(size: int = 2 ** 13):
    """
    This function generates a new private RSA key
    with given private key size in bits. Returns
    the private key and the duration of the generation in miliseconds.

    Parameters:
        size (int): private key size in bits (default: 2^13)

    Returns:
        private_key (RSAPrivateKey): the generated private key
        duration_in_miliseconds (int): how long the generation took (in miliseconds)
    """
    start = time.time() * 1000

    private_key = rsa.generate_private_key(
            public_exponent = 65537,
            key_size = size, # 2048 is 2 ^ 11
        )
    
    end = time.time() * 1000

    duration_in_miliseconds = int(end - start)

    return private_key, duration_in_miliseconds


def connect_to_server():
    # create tcp client socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # connect to server
        s.connect((HOST, PORT))


        s.sendall(b"H")
        print(f"Sent: '{b'H'}'")
        data = s.recv(1024)
        print(f"Received: '{data}'")



if __name__ == "__main__":
    try:
        connect_to_server()
    except Exception as e:
        print("Error occured:")
        print(e)
