"""
.. module: bless.ssh.certificates.rsa_certificate_builder
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from bless.ssh.certificates.ssh_certificate_builder import \
    SSHCertificateBuilder, SSHCertifiedKeyType
from bless.ssh.protocol.ssh_protocol import pack_ssh_mpint


class RSACertificateBuilder(SSHCertificateBuilder):
    def __init__(self, ca, cert_type, ssh_public_key_rsa):
        """
        Produces an SSH certificate for RSA public keys.
        :param ca: The SSHCertificateAuthority that will sign the certificate.  The
        SSHCertificateAuthority type does not need to be the same type as the
        SSHCertificateBuilder.
        :param cert_type: The SSHCertificateType.  Is this a User or Host certificate?  Some of
        the SSH Certificate fields do not apply or have a slightly different meaning depending on
        the certificate type.
        See http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys
        :param ssh_public_key_rsa: The RSAPublicKey to issue a certificate for.
        """
        super(RSACertificateBuilder, self).__init__(ca, cert_type)
        self.cert_key_type = SSHCertifiedKeyType.RSA
        self.ssh_public_key = ssh_public_key_rsa
        self.public_key_comment = ssh_public_key_rsa.key_comment
        self.e = ssh_public_key_rsa.e
        self.n = ssh_public_key_rsa.n

    def _serialize_ssh_public_key(self):
        """
        Serialize the Public Key into the RSA exponent and public modulus stored as SSH mpints.
        http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys
        :return: The bytes that belong in the SSH Certificate between the nonce and the
        certificate serial number.
        """
        public_key = pack_ssh_mpint(self.e)
        public_key += pack_ssh_mpint(self.n)
        return public_key
