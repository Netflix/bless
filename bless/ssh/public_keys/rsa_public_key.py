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

        public_key = serialization.load_ssh_public_key(ssh_public_key, default_backend())
        ca_pub_numbers = public_key.public_numbers()
        if not isinstance(ca_pub_numbers, RSAPublicNumbers):
            raise TypeError("Public Key is not the correct type or format")

        self.e = ca_pub_numbers.e
        self.n = ca_pub_numbers.n

        key_bytes = base64.b64decode(split_ssh_public_key[1])
        fingerprint = hashlib.md5(key_bytes).hexdigest()

        self.fingerprint = 'RSA ' + ':'.join(
            fingerprint[i:i + 2] for i in range(0, len(fingerprint), 2))
