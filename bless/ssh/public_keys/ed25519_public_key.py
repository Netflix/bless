"""
.. module: bless.ssh.public_keys.ed25519_public_key
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
import base64
import hashlib

from bless.ssh.public_keys.ssh_public_key import SSHPublicKey, SSHPublicKeyType
from cryptography.hazmat.primitives.serialization import ssh


class ED25519PublicKey(SSHPublicKey):
    def __init__(self, ssh_public_key):
        """
        Extracts the useful ED25519 Public Key information from an SSH Public Key file.
        :param ssh_public_key: SSH Public Key file contents. (i.e. 'ssh-ed25519 AAAAB3NzaC1yc2E..').
        """
        super(ED25519PublicKey, self).__init__()

        self.type = SSHPublicKeyType.ED25519

        split_ssh_public_key = ssh_public_key.split(' ')
        split_key_len = len(split_ssh_public_key)

        # is there a key comment at the end?
        if split_key_len > 2:
            self.key_comment = ' '.join(split_ssh_public_key[2:])
        else:
            self.key_comment = ''

        # hazmat does not support ed25519 so we have out own loader based on serialization.load_ssh_public_key

        if split_key_len < 2:
            raise ValueError(
                'Key is not in the proper format or contains extra data.')

        key_type = split_ssh_public_key[0]
        key_body = split_ssh_public_key[1]

        if key_type != SSHPublicKeyType.ED25519:
            raise TypeError("Public Key is not the correct type or format")

        try:
            decoded_data = base64.b64decode(key_body)
        except TypeError:
            raise ValueError('Key is not in the proper format.')

        inner_key_type, rest = ssh._get_sshstr(decoded_data)

        if inner_key_type != key_type.encode("utf-8"):
            raise ValueError(
                'Key header and key body contain different key type values.'
            )

        # ed25519 public key is a single string https://tools.ietf.org/html/rfc8032#section-5.1.5
        self.a, rest = ssh._get_sshstr(rest)

        key_bytes = base64.b64decode(split_ssh_public_key[1])
        fingerprint = hashlib.md5(key_bytes).hexdigest()

        self.fingerprint = 'ED25519 ' + ':'.join(
            fingerprint[i:i + 2] for i in range(0, len(fingerprint), 2))
