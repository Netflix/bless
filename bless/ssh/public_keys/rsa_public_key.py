"""
.. module: bless.ssh.public_keys.rsa_public_key
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
import base64
import hashlib

from bless.ssh.public_keys.ssh_public_key import SSHPublicKey, SSHPublicKeyType
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers


def check_small_primes(n):
    """
    Returns True if n is divisible by a number in SMALL_PRIMES.
    Based on the MPL licensed
    https://github.com/letsencrypt/boulder/blob/58e27c0964a62772e7864e8a12e565ef8a975035/core/good_key.go
    """
    small_primes = [
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
        53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107,
        109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
        173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
        233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
        293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359,
        367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431,
        433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491,
        499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571,
        577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641,
        643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709,
        719, 727, 733, 739, 743, 751
    ]
    for prime in small_primes:
        if (n % prime == 0):
            return True
    return False


class RSAPublicKey(SSHPublicKey):
    def __init__(self, ssh_public_key):
        """
        Extracts the useful RSA Public Key information from an SSH Public Key file.
        :param ssh_public_key: SSH Public Key file contents. (i.e. 'ssh-rsa AAAAB3NzaC1yc2E..').
        """
        super(RSAPublicKey, self).__init__()

        self.type = SSHPublicKeyType.RSA

        split_ssh_public_key = ssh_public_key.split(' ')
        split_key_len = len(split_ssh_public_key)

        # is there a key comment at the end?
        if split_key_len > 2:
            self.key_comment = ' '.join(split_ssh_public_key[2:])
        else:
            self.key_comment = ''

        public_key = serialization.load_ssh_public_key(ssh_public_key.encode('ascii'), default_backend())
        ca_pub_numbers = public_key.public_numbers()
        if not isinstance(ca_pub_numbers, RSAPublicNumbers):
            raise TypeError("Public Key is not the correct type or format")

        self.key_size = public_key.key_size
        self.e = ca_pub_numbers.e
        self.n = ca_pub_numbers.n

        key_bytes = base64.b64decode(split_ssh_public_key[1])
        fingerprint = hashlib.md5(key_bytes).hexdigest()

        self.fingerprint = 'RSA ' + ':'.join(
            fingerprint[i:i + 2] for i in range(0, len(fingerprint), 2))

    def validate_for_signing(self):
        """
        Raises an error if the public key looks weak
        """
        if (self.key_size < 2048
                or self.e < 65537
                or self.n % 2 == 0
                or check_small_primes(self.n)):
            raise ValueError("Unsafe RSA public key")
