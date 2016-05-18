import pytest

from bless.ssh.public_keys.rsa_public_key import RSAPublicKey
from tests.ssh.vectors import EXAMPLE_RSA_PUBLIC_KEY, \
    EXAMPLE_RSA_PUBLIC_KEY_NO_DESCRIPTION, EXAMPLE_ECDSA_PUBLIC_KEY, EXAMPLE_RSA_PUBLIC_KEY_N, \
    EXAMPLE_RSA_PUBLIC_KEY_E


def test_valid_key():
    pub_key = RSAPublicKey(EXAMPLE_RSA_PUBLIC_KEY)
    assert 'Test RSA User Key' == pub_key.key_comment
    assert EXAMPLE_RSA_PUBLIC_KEY_N == pub_key.n
    assert EXAMPLE_RSA_PUBLIC_KEY_E == pub_key.e
    assert 'RSA 57:3d:48:4c:65:90:30:8e:39:ba:d8:fa:d0:20:2e:6c' == pub_key.fingerprint


def test_valid_key_no_description():
    pub_key = RSAPublicKey(EXAMPLE_RSA_PUBLIC_KEY_NO_DESCRIPTION)
    assert '' == pub_key.key_comment
    assert EXAMPLE_RSA_PUBLIC_KEY_N == pub_key.n
    assert EXAMPLE_RSA_PUBLIC_KEY_E == pub_key.e
    assert 'RSA 57:3d:48:4c:65:90:30:8e:39:ba:d8:fa:d0:20:2e:6c' == pub_key.fingerprint


def test_invalid_keys():
    with pytest.raises(TypeError):
        RSAPublicKey(EXAMPLE_ECDSA_PUBLIC_KEY)

    with pytest.raises(ValueError):
        RSAPublicKey('bogus')
