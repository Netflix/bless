import pytest

from bless.ssh.certificate_authorities.ssh_certificate_authority_factory import \
    get_ssh_certificate_authority
from bless.ssh.certificates.rsa_certificate_builder import RSACertificateBuilder, \
    SSHCertifiedKeyType
from bless.ssh.certificates.ssh_certificate_builder import SSHCertificateType
from bless.ssh.certificates.ssh_certificate_builder_factory import get_ssh_certificate_builder
from tests.ssh.vectors import RSA_CA_PRIVATE_KEY, RSA_CA_PRIVATE_KEY_PASSWORD, \
    EXAMPLE_RSA_PUBLIC_KEY, EXAMPLE_ED25519_PUBLIC_KEY


def test_valid_rsa_request():
    ca = get_ssh_certificate_authority(RSA_CA_PRIVATE_KEY, RSA_CA_PRIVATE_KEY_PASSWORD)
    cert_builder = get_ssh_certificate_builder(ca, SSHCertificateType.USER, EXAMPLE_RSA_PUBLIC_KEY)
    cert = cert_builder.get_cert_file()
    assert isinstance(cert_builder, RSACertificateBuilder)
    assert cert.startswith(SSHCertifiedKeyType.RSA)


def test_invalid_ed25519_request():
    with pytest.raises(TypeError):
        ca = get_ssh_certificate_authority(RSA_CA_PRIVATE_KEY, RSA_CA_PRIVATE_KEY_PASSWORD)
        get_ssh_certificate_builder(ca, SSHCertificateType.USER, EXAMPLE_ED25519_PUBLIC_KEY)


def test_invalid_key_request():
    with pytest.raises(TypeError):
        ca = get_ssh_certificate_authority(RSA_CA_PRIVATE_KEY, RSA_CA_PRIVATE_KEY_PASSWORD)
        get_ssh_certificate_builder(ca, SSHCertificateType.USER, 'bogus')
