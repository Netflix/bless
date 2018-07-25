"""
.. module: bless.ssh.certificate_authorities.ssh_certificate_authority_factory
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from bless.ssh.certificate_authorities.rsa_certificate_authority import \
    RSACertificateAuthority
from bless.ssh.certificate_authorities.ssh_certificate_authority import \
    SSHCertificateAuthorityPrivateKeyType


def get_ssh_certificate_authority(private_key, password=None):
    """
    Returns the proper SSHCertificateAuthority instance based off the private_key type.
    :param private_key: ASCII bytes of an SSH compatible Private Key (e.g., PEM or SSH Protocol 2 Private Key).
    It should be encrypted with a password, but that is not required.
    :param password: ASCII bytes of the Password to decrypt the Private Key, if it is encrypted.  Which it should be.
    :return: An SSHCertificateAuthority instance.
    """
    if private_key.decode('ascii').startswith(SSHCertificateAuthorityPrivateKeyType.RSA):
        return RSACertificateAuthority(private_key, password)
    else:
        raise TypeError("Unsupported CA Private Key Type")
