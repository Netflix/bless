"""
.. module: bless.ssh.public_keys.ssh_public_key_factory
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from bless.ssh.public_keys.rsa_public_key import RSAPublicKey
from bless.ssh.public_keys.ssh_public_key import SSHPublicKeyType


def get_ssh_public_key(ssh_public_key):
    """
    Returns the proper SSHPublicKey instance based off of the SSH Public Key file.
    :param ssh_public_key: SSH Public Key file contents. (i.e. 'ssh-XXX AAAA....').
    :return: An SSHPublicKey instance.
    """
    if ssh_public_key.startswith(SSHPublicKeyType.RSA):
        rsa_public_key = RSAPublicKey(ssh_public_key)
        rsa_public_key.validate_for_signing()
        return rsa_public_key
    else:
        raise TypeError("Unsupported Public Key Type")
