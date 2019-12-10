"""
.. module: bless.ssh.certificates.ed25519_certificate_builder
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from bless.ssh.certificates.ssh_certificate_builder import \
    SSHCertificateBuilder, SSHCertifiedKeyType
from bless.ssh.protocol.ssh_protocol import pack_ssh_string


class ED25519CertificateBuilder(SSHCertificateBuilder):
    def __init__(self, ca, cert_type, ssh_public_key_ed25519):
        """
        Produces an SSH certificate for ED25519 public keys.
        :param ca: The SSHCertificateAuthority that will sign the certificate.  The
        SSHCertificateAuthority type does not need to be the same type as the
        SSHCertificateBuilder.
        :param cert_type: The SSHCertificateType.  Is this a User or Host certificate?  Some of
        the SSH Certificate fields do not apply or have a slightly different meaning depending on
        the certificate type.
        See http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys
        :param ssh_public_key_ed25519: The ED25519PublicKey to issue a certificate for.
        """
        super(ED25519CertificateBuilder, self).__init__(ca, cert_type)
        self.cert_key_type = SSHCertifiedKeyType.ED25519
        self.ssh_public_key = ssh_public_key_ed25519
        self.public_key_comment = ssh_public_key_ed25519.key_comment
        self.a = ssh_public_key_ed25519.a

    def _serialize_ssh_public_key(self):
        """
        Serialize the Public Key into a string. This is not specified in
        http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys
        but https://tools.ietf.org/id/draft-ietf-curdle-ssh-ed25519-02.html
        :return: The bytes that belong in the SSH Certificate between the nonce and the
        certificate serial number.
        """
        public_key = pack_ssh_string(self.a)
        return public_key
