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


def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))



        server_socket.listen()
        client_socket, client_address = server_socket.accept()
        with client_socket:
            print(f"Connected by {client_address}")
            while True:
                data = client_socket.recv(1)
                if not data:
                    break
                client_socket.sendall(data)


if __name__ == "__main__":
    try:
        run_server()
    except Exception as e:
        print("Error occured:")
        print(e)
