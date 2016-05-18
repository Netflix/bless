"""
.. module: bless.ssh.public_keys.ssh_public_key
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""


class SSHPublicKeyType(object):
    RSA = 'ssh-rsa'
    ED25519 = 'ssh-ed25519'
    # todo support more key types


# todo real abstract classes
class SSHPublicKey(object):
    """
    Extracts the useful Public Key information from an SSH Public Key file.
    :param ssh_public_key: SSH Public Key file contents. (i.e. 'ssh-XXX AAAA....').
    """
    def __init__(self):
        self.type = None
        self.key_comment = None
        self.fingerprint = None
