import pytest

from bless.ssh.certificate_authorities.rsa_certificate_authority import RSACertificateAuthority
from bless.ssh.certificate_authorities.ssh_certificate_authority_factory import \
    get_ssh_certificate_authority
from bless.ssh.public_keys.ssh_public_key import SSHPublicKeyType
from tests.ssh.vectors import RSA_CA_PRIVATE_KEY, RSA_CA_PRIVATE_KEY_PASSWORD, \
    RSA_CA_SSH_PUBLIC_KEY, RSA_CA_PRIVATE_KEY_NOT_ENCRYPTED


def test_valid_key_valid_password():
    ca = get_ssh_certificate_authority(RSA_CA_PRIVATE_KEY, RSA_CA_PRIVATE_KEY_PASSWORD)
    assert isinstance(ca, RSACertificateAuthority)
    assert SSHPublicKeyType.RSA == ca.public_key_type
    assert 65537 == ca.e
    assert ca.get_signature_key() == RSA_CA_SSH_PUBLIC_KEY


def test_valid_key_not_encrypted():
    ca = get_ssh_certificate_authority(RSA_CA_PRIVATE_KEY_NOT_ENCRYPTED)
    assert SSHPublicKeyType.RSA == ca.public_key_type
    assert 65537 == ca.e


def test_valid_key_missing_password():
    with pytest.raises(TypeError):
        get_ssh_certificate_authority(RSA_CA_PRIVATE_KEY)


def test_valid_key_invalid_password():
    with pytest.raises(ValueError):
        get_ssh_certificate_authority(RSA_CA_PRIVATE_KEY, b'bogus')


def test_valid_key_not_encrypted_invalid_pass():
    with pytest.raises(TypeError):
        get_ssh_certificate_authority(RSA_CA_PRIVATE_KEY_NOT_ENCRYPTED, b'bogus')


def test_invalid_key():
    with pytest.raises(TypeError):
        get_ssh_certificate_authority(b'bogus')
