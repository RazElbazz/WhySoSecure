# imports
import sys
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


def public_key_from_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
    # get public key
    public_key = private_key.public_key()

    # return in correct encoding
    return public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
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


def accept_client(client_socket: socket.socket, client_address: socket.AddressInfo, password: str):
    try:
        print(f"Client connected from {client_address}")
        with client_socket:

            # for join packet only timeout of 3 seconds
            client_socket.settimeout(3)

            # receive packet
            client_packet = receive_packet(sock=client_socket)
            
            # if packet was not join packet
            if client_packet.code != CODE_JOIN:
                client_socket.send(code=CODE_ERROR, data=b'Code was not join.')
                return

            # if packet was join packet send acknowledge packet and generate key
            packet_to_send = Packet(code=CODE_ACKNOWLEDGE, data=b'')
            client_socket.send(packet_to_send.get_as_bytes())

            # generate private key
            client_socket.settimeout(None)
            private_key,  gen_duration = generate_private_key()
            public_key = public_key_from_private_key(private_key=private_key)

            # send public key to user
            packet_to_send = Packet(code=CODE_PUB_KEY, data=public_key)
            client_socket.send(packet_to_send.get_as_bytes())

            client_socket.settimeout(100)

            # wait for login packet
            client_packet = receive_packet(sock=client_socket)

            # if not login packet
            if client_packet.code != CODE_LOGIN:
                packet_to_send = Packet(code=CODE_ERROR, data=b'Code was not login.')
                client_socket.send(packet_to_send.get_as_bytes())
                return
            
            # if login packet, but bad password
            if client_packet.data != password:
                packet_to_send = Packet(code=CODE_ERROR, data=b'Bad password.')
                client_socket.send(packet_to_send.get_as_bytes())
                return
            
            # correct password
            packet_to_send = Packet(code=CODE_ACKNOWLEDGE, data=b'')
            client_socket.send(packet_to_send.get_as_bytes())





    # handle client disconnect
    except socket.error as e:
        print(f"Client disconnected from {client_address} ({e.errno})")
    
    # handle exceptions
    except Exception as e:
        print(f"Client disconnected from {client_address} ({e})")

def run_server(password: str):
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
                args= (client_socket, client_address, password)
            )

            accept_client_thread.start()


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <password>")
        exit(1)

    password = sys.argv[1].strip()

    try:
        run_server(password=password)
    except Exception as e:
        print("Error occured:")
        print(e)
