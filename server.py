# imports
import socket
import time
# cryptography imports
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_private_key(size: int = 2 ** 13):
    """
    This function generates a new private RSA key
    with given private key size in bits.

    size : int
        private key size in bits (default 2^13)
    """
    start = time.time() * 1000

    private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size= size, # 2048 is 2 ^ 11
        )
    end = time.time() * 1000

    duration_in_miliseconds = int(end - start)

    return private_key, duration_in_miliseconds
