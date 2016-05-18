import pytest

from bless.ssh.public_keys.ssh_public_key_factory import get_ssh_public_key
from tests.ssh.vectors import EXAMPLE_RSA_PUBLIC_KEY, EXAMPLE_ED25519_PUBLIC_KEY, \
    EXAMPLE_ECDSA_PUBLIC_KEY, EXAMPLE_RSA_PUBLIC_KEY_N, EXAMPLE_RSA_PUBLIC_KEY_E


def test_valid_rsa():
    pub_key = get_ssh_public_key(EXAMPLE_RSA_PUBLIC_KEY)
    assert 'Test RSA User Key' == pub_key.key_comment
    assert EXAMPLE_RSA_PUBLIC_KEY_N == pub_key.n
    assert EXAMPLE_RSA_PUBLIC_KEY_E == pub_key.e
    assert 'RSA 57:3d:48:4c:65:90:30:8e:39:ba:d8:fa:d0:20:2e:6c' == pub_key.fingerprint


def test_unsupported_ed_25519():
    with pytest.raises(TypeError):
        get_ssh_public_key(EXAMPLE_ED25519_PUBLIC_KEY)


def test_invalid_key():
    with pytest.raises(TypeError):
        get_ssh_public_key(EXAMPLE_ECDSA_PUBLIC_KEY)
