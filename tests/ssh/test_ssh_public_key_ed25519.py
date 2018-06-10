import pytest

from bless.ssh.public_keys.ed25519_public_key import ED25519PublicKey
from tests.ssh.vectors import EXAMPLE_ED25519_PUBLIC_KEY, EXAMPLE_ED25519_PUBLIC_KEY_A, \
    EXAMPLE_ECDSA_PUBLIC_KEY, \
    EXAMPLE_ED25519_PUBLIC_KEY_NO_DESCRIPTION


def test_valid_key():
    pub_key = ED25519PublicKey(EXAMPLE_ED25519_PUBLIC_KEY)
    assert 'Test ED25519 User Key' == pub_key.key_comment
    assert EXAMPLE_ED25519_PUBLIC_KEY_A == pub_key.a
    assert 'ED25519 fb:80:ca:21:7d:c8:9d:38:35:c0:f6:ba:fb:6d:82:e8' == pub_key.fingerprint


def test_valid_key_no_description():
    pub_key = ED25519PublicKey(EXAMPLE_ED25519_PUBLIC_KEY_NO_DESCRIPTION)
    assert '' == pub_key.key_comment
    assert EXAMPLE_ED25519_PUBLIC_KEY_A == pub_key.a
    assert 'ED25519 fb:80:ca:21:7d:c8:9d:38:35:c0:f6:ba:fb:6d:82:e8' == pub_key.fingerprint


def test_invalid_keys():
    with pytest.raises(TypeError):
        ED25519PublicKey(EXAMPLE_ECDSA_PUBLIC_KEY)

    with pytest.raises(ValueError):
        ED25519PublicKey('bogus')

