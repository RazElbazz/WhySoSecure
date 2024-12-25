# imports
import socket
import threading
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


def accept_client(client_socket: socket.socket, client_address: socket.AddressInfo):
    try:
        print(f"Client connected from {client_address}")
        with client_socket:

            # for join packet only timeout of 3 seconds
            client_socket.settimeout(3)

            # receive packet
            client_packet = receive_packet(sock=client_socket)
            
            # if packet was not join packet
            if client_packet.code != JOIN:
                client_socket.sendall(code=ERROR, data=b'Code was not join.')
                return

            # if packet was join packet
            acknowledge_join_packet = Packet(code=ACKNOWLEDGE, data=b'')
            client_socket.sendall(acknowledge_join_packet.get_as_bytes())


            client_socket.settimeout(None)

            while True:
                # receive packet
                client_packet = receive_packet(sock=client_socket)
                client_socket.send(Packet(code=UPDATE, data=client_packet.data).get_as_bytes())
    # handle client disconnect
    except socket.error as e:
        print(f"Client disconnected from {client_address} ({e.errno})")
    

    except Exception as e:
        print(f"Client disconnected from {client_address} ({e})")

def run_server():
    # create a tcp server socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # bind
        server_socket.bind((HOST, PORT))
        print(f"Server binded on {HOST}:{PORT}")

        # listen
        server_socket.listen()
        print(f"Server listening on {HOST}:{PORT}")

        while True:
        # accept clients
            client_socket, client_address = server_socket.accept()

            accept_client_thread = threading.Thread(
                target= accept_client,
                args= (client_socket, client_address)
            )

            accept_client_thread.start()


if __name__ == "__main__":
    try:
        run_server()
    except Exception as e:
        print("Error occured:")
        print(e)
