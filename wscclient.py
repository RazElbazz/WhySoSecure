# imports
import socket
import time
import threading
# cryptography imports
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# DEFINITIONS
HOST = "127.0.0.1"
PORT = 65432

# PROTOCOL CODES
CODE_ERROR = 400
CODE_ACKNOWLEDGE = 200
CODE_PUB_KEY = 201
CODE_UPDATE = 202
CODE_MESSAGE_ACKNOWLEDGE = 203
CODE_JOIN = 100
CODE_LOGIN = 101
CODE_LOGIN_USERNAME = 102
CODE_MESSAGE = 103


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


def client_listener(server_socket):
    while True:
        server_packet = receive_packet(sock=server_socket)
        if server_packet.code == CODE_UPDATE:
            message = server_packet.data.decode()
            print(message)
        elif server_packet.code == CODE_MESSAGE_ACKNOWLEDGE:
            print("->Server acknowledged your message.")
        else:
            print("Error occured: received server packet which is not update or message acknowledge:")
            print(server_packet.get_as_bytes())
            return


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
        print("Server acknowledged join, waiting for public key. (this is going to take a while)")

        # disable socket timeout
        server_socket.settimeout(None)

        server_packet = receive_packet(sock=server_socket)
        if server_packet.code != CODE_PUB_KEY:
            print("Error occured: received server packet which is not pub_key:")
            print(server_packet.get_as_bytes())
            return
        
        public_key = server_packet.data

        print(f"->Public key received.")

        password = input("password: ")

        packet_to_send = Packet(code=CODE_LOGIN, data=password)
        server_socket.send(packet_to_send.get_as_bytes())

        server_packet = receive_packet(sock=server_socket)

        if server_packet.code == CODE_ERROR:
            print(f"Error occured: Server returned error: `{server_packet.data}`")
            return
        
        if server_packet.code != CODE_ACKNOWLEDGE:
            print("Error occured: received server packet which is not error or acknowledge:")
            print(server_packet.get_as_bytes())
            return
        
        # password is correct, take username
        print("->Password accepted.")

        name = input("name to join with: ")

        packet_to_send = Packet(code=CODE_LOGIN_USERNAME, data=name)
        server_socket.send(packet_to_send.get_as_bytes())

        server_packet = receive_packet(sock=server_socket)

        if server_packet.code == CODE_ERROR:
            print(f"Error occured: Server returned error: `{server_packet.data}`")
            return
        
        if server_packet.code != CODE_ACKNOWLEDGE:
            print("Error occured: received server packet which is not error or acknowledge:")
            print(server_packet.get_as_bytes())
            return
        
        print("->Server acknowledged, you are now in the chat.")

        # joined room

        # start client listener
        client_listener_thread = threading.Thread(target=client_listener, args=(server_socket,))
        client_listener_thread.start()
        

        # read input from user to chat
        while True:
            message = input()
            packet_to_send = Packet(code=CODE_MESSAGE, data=message)
            server_socket.send(packet_to_send.get_as_bytes())



if __name__ == "__main__":
    try:
        connect_to_server()
    except Exception as e:
        print("Error occured:")
        print(e)
