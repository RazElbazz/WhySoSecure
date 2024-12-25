# imports
import socket
import time
# cryptography imports
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# DEFINITIONS
HOST = "127.0.0.1"
PORT = 65432

# PROTOCOL CODES
ERROR = 400
ACKNOWLEDGE = 200
UPDATE = 201
JOIN = 100


class Packet:
    def __init__(self, code: int, data: bytes):
        self.code = code
        self.data = data
    
    def get_as_bytes(self):
        return (
            self.code.to_bytes(length=2, byteorder="big") + # code (2 byte)
            len(self.data).to_bytes(length=5, byteorder="big") + # length (5 bytes)
            self.data # data
            )
    


def receive_packet(sock: socket.socket) -> Packet:
    code = int.from_bytes(sock.recv(2), byteorder="big")
    length = int.from_bytes(sock.recv(5), byteorder="big")

    # if no data, craft with empty data
    if length == 0:
        return Packet(code=code, data=b'')

    # recv data of size length
    data = sock.recv(length)

    # craft and return packet
    return Packet(code=code, data=data)


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

    # gen key based on input
    private_key = rsa.generate_private_key(
            public_exponent = 65537,
            key_size = size, # 2048 is 2 ^ 11
        )
    
    end = time.time() * 1000

    # calculate duration
    duration_in_miliseconds = int(end - start)

    return private_key, duration_in_miliseconds


def connect_to_server():
    # create tcp client socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # connect to server
        server_socket.connect((HOST, PORT))

        # send join request
        join_packet = Packet(code=JOIN, data=b'')
        server_socket.sendall(join_packet.get_as_bytes())
        print(f"Sent join request to {HOST}:{PORT}")

        server_packet = receive_packet(sock=server_socket)

        # check if server acknowledged the join packet
        if server_packet.code != ACKNOWLEDGE:
            print("Not acknowledged by server")
            return
        
        # if server acknowledged, begin conversation
        print("Server acknowledged join, waiting for pub-key")



if __name__ == "__main__":
    #try:
    connect_to_server()
    #except Exception as e:
    #    print("Error occured:")
    #    print(e)
