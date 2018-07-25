"""
.. module: bless.ssh.certificates.ssh_certificate_builder_factory
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from bless.ssh.certificates.rsa_certificate_builder \
    import RSACertificateBuilder
from bless.ssh.certificates.ed25519_certificate_builder \
    import ED25519CertificateBuilder
from bless.ssh.public_keys.ssh_public_key import SSHPublicKeyType
from bless.ssh.public_keys.ssh_public_key_factory import get_ssh_public_key


def get_ssh_certificate_builder(ca, cert_type, public_key_to_sign):
    """
    Returns the proper SSHCertificateBuilder instance for the type of public key to be signed.
    :param ca: The SSHCertificateAuthority that will sign the certificate.  The
    SSHCertificateAuthority type does not need to be the same type as the SSHCertificateBuilder.
    :param cert_type: The SSHCertificateType.  Is this a User or Host certificate?
    :param public_key_to_sign: The SSHPublicKey to issue a certificate for.
    :return: An SSHCertificateBuilder instance.
    """
    # Determine the type of public key we have, to decide the right cert type
    ssh_public_key = get_ssh_public_key(public_key_to_sign)

    if ssh_public_key.type is SSHPublicKeyType.RSA:
        return RSACertificateBuilder(ca, cert_type, ssh_public_key)
    elif ssh_public_key.type is SSHPublicKeyType.ED25519:
        return ED25519CertificateBuilder(ca, cert_type, ssh_public_key)
    else:
        raise TypeError("Unsupported Public Key Type")
