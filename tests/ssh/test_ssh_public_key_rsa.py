import pytest

from bless.ssh.public_keys.rsa_public_key import RSAPublicKey
from tests.ssh.vectors import EXAMPLE_RSA_PUBLIC_KEY, \
    EXAMPLE_RSA_PUBLIC_KEY_NO_DESCRIPTION, EXAMPLE_ECDSA_PUBLIC_KEY, EXAMPLE_RSA_PUBLIC_KEY_N, \
    EXAMPLE_RSA_PUBLIC_KEY_E, EXAMPLE_RSA_PUBLIC_KEY_2048, EXAMPLE_RSA_PUBLIC_KEY_1024, \
    EXAMPLE_RSA_PUBLIC_KEY_SMALLPRIME, EXAMPLE_RSA_PUBLIC_KEY_E3, EXAMPLE_RSA_PUBLIC_KEY_N_NO_DESCRIPTION


def test_valid_key():
    pub_key = RSAPublicKey(EXAMPLE_RSA_PUBLIC_KEY)
    assert './user_ca' == pub_key.key_comment
    assert EXAMPLE_RSA_PUBLIC_KEY_N == pub_key.n
    assert EXAMPLE_RSA_PUBLIC_KEY_E == pub_key.e
    assert 'RSA 09:26:ae:1a:a1:27:7c:42:c3:00:cc:1e:82:0b:1f:2f' == pub_key.fingerprint


def test_valid_key_no_description():
    pub_key = RSAPublicKey(EXAMPLE_RSA_PUBLIC_KEY_NO_DESCRIPTION)
    assert '' == pub_key.key_comment
    assert EXAMPLE_RSA_PUBLIC_KEY_N_NO_DESCRIPTION == pub_key.n
    assert EXAMPLE_RSA_PUBLIC_KEY_E == pub_key.e
    assert 'RSA 57:3d:48:4c:65:90:30:8e:39:ba:d8:fa:d0:20:2e:6c' == pub_key.fingerprint


def test_invalid_keys():
    with pytest.raises(TypeError):
        RSAPublicKey(EXAMPLE_ECDSA_PUBLIC_KEY)

    with pytest.raises(ValueError):
        RSAPublicKey('bogus')


def test_validation_for_signing():
    pub_key = RSAPublicKey(EXAMPLE_RSA_PUBLIC_KEY_1024)
    with pytest.raises(ValueError):
        pub_key.validate_for_signing()

    pub_key_sp = RSAPublicKey(EXAMPLE_RSA_PUBLIC_KEY_SMALLPRIME)
    with pytest.raises(ValueError):
        pub_key_sp.validate_for_signing()

    pub_key_e3 = RSAPublicKey(EXAMPLE_RSA_PUBLIC_KEY_E3)
    with pytest.raises(ValueError):
        pub_key_e3.validate_for_signing()

    pub_key_valid = RSAPublicKey(EXAMPLE_RSA_PUBLIC_KEY_2048)
    try:
        pub_key_valid.validate_for_signing()
    except ValueError:
        pytest.fail("Valid key failed to validate")
