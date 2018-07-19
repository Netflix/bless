"""
.. module: bless.ssh.certificate_authorities.rsa_certificate_authority
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from bless.ssh.certificate_authorities.ssh_certificate_authority import \
    SSHCertificateAuthority
from bless.ssh.protocol.ssh_protocol import pack_ssh_mpint, pack_ssh_string
from bless.ssh.public_keys.ssh_public_key import SSHPublicKeyType
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key


class RSACertificateAuthority(SSHCertificateAuthority):
    def __init__(self, pem_private_key, private_key_password=None):
        """
        RSA Certificate Authority used to sign certificates.
        :param pem_private_key: PEM formatted RSA Private Key.  It should be encrypted with a
        password, but that is not required.
        :param private_key_password: Password to decrypt the PEM RSA Private Key, if it is
        encrypted.  Which it should be.
        """
        super(SSHCertificateAuthority, self).__init__()
        self.public_key_type = SSHPublicKeyType.RSA

        self.private_key = load_pem_private_key(pem_private_key,
                                                private_key_password,
                                                default_backend())

        ca_pub_numbers = self.private_key.public_key().public_numbers()

        self.e = ca_pub_numbers.e
        self.n = ca_pub_numbers.n

    def get_signature_key(self):
        """
        Get the SSH Public Key associated with this CA.
        Packed per RFC4253 section 6.6.
        :return: SSH Public Key.
        """
        key = pack_ssh_string(self.public_key_type)
        key += pack_ssh_mpint(self.e)
        key += pack_ssh_mpint(self.n)
        return key

    def sign(self, body):
        """
        Sign the certificate body with the RSA private key.  Signatures are computed and
        encoded per RFC4253 section 6.6
        :param body: All other fields of the SSH Certificate, from the initial string to the
        signature key.
        :return: SSH RSA Signature.
        """
        signature = self.private_key.sign(body, padding.PKCS1v15(), hashes.SHA1())

        return self._serialize_signature(signature)
