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
CODE_ERROR = 400
CODE_PUB_KEY = 300
CODE_ACKNOWLEDGE = 200
CODE_UPDATE = 201
CODE_JOIN = 100
CODE_LOGIN = 101


class Packet:
    def __init__(self, code: int, data: bytes):
        self.code = code
        if isinstance(data,  bytes):
            self.data = data
        elif isinstance(data, str):
            self.data = data.encode()

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
        join_packet = Packet(code=CODE_JOIN, data=b'')
        server_socket.send(join_packet.get_as_bytes())
        print(f"Sent join request to {HOST}:{PORT}")

        server_packet = receive_packet(sock=server_socket)

        # check if server didn't acknowledge
        if server_packet.code != CODE_ACKNOWLEDGE:
            print("Not acknowledged by server")
            return
        
        # if server acknowledged, begin conversation
        print("Server acknowledged join, waiting for pub-key")

        # disable socket timeout
        server_socket.settimeout(None)

        server_packet = receive_packet(sock=server_socket)
        if server_packet.code != CODE_PUB_KEY:
            print("Error occured: received server packet which is not pub_key:")
            print(server_packet.get_as_bytes())
            return
        
        public_key = server_packet.data

        print(f"Received public key: '{public_key}'")

        password = input("100 seconds left to enter password: ")

        packet_to_send = Packet(code=CODE_LOGIN, data=password.strip())
        server_socket.send(packet_to_send.get_as_bytes())

        server_packet = receive_packet(sock=server_socket)

        if server_packet.code == CODE_ERROR:
            print(f"Error occured: Server returned error: `{server_packet.data}`")
            return
        
        if server_packet.code != CODE_ACKNOWLEDGE:
            print("Error occured: received server packet which is not error or acknowledge:")
            print(server_packet.get_as_bytes())
            return
        
        print("Correct password! We're in.")



if __name__ == "__main__":
    try:
        connect_to_server()
    except Exception as e:
        print("Error occured:")
        print(e)
