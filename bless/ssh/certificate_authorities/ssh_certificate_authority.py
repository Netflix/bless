"""
.. module: bless.ssh.certificate_authorities.ssh_certificate_authority
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from bless.ssh.protocol.ssh_protocol import pack_ssh_string


class SSHCertificateAuthorityPrivateKeyType(object):
    RSA = '-----BEGIN RSA PRIVATE KEY-----\n'
    # todo support other CA Private Key Types


class SSHCertificateAuthority(object):
    def __init__(self):
        self.public_key_type = None

    # todo real abstract classes
    def sign(self, body):
        """
        Sign the certificate body with the CA private key.  Signatures are computed and
        encoded per RFC4253 section 6.6
        :param body: All other fields of the SSH Certificate, from the initial string to the
        signature key.
        :return: SSH Signature.
        """
        raise NotImplementedError("Child classes should override this")

    # todo real abstract classes
    def get_signature_key(self):
        """
        Get the SSH Public Key associated with this CA.
        Packed per RFC4253 section 6.6
        :return: SSH Certificate formatted Public Key.
        """
        raise NotImplementedError("Child classes should override this")

    def _serialize_signature(self, signature):
        # pack signature block
        sig_inner = pack_ssh_string(self.public_key_type)
        sig_inner += pack_ssh_string(signature)

        return pack_ssh_string(sig_inner)
