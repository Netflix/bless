import pytest

from bless.ssh.public_keys.ssh_public_key_factory import get_ssh_public_key
from tests.ssh.vectors import EXAMPLE_RSA_PUBLIC_KEY, EXAMPLE_ED25519_PUBLIC_KEY, \
    EXAMPLE_ECDSA_PUBLIC_KEY, EXAMPLE_RSA_PUBLIC_KEY_N, EXAMPLE_RSA_PUBLIC_KEY_E, \
    EXAMPLE_ED25519_PUBLIC_KEY_A

def test_valid_rsa():
    pub_key = get_ssh_public_key(EXAMPLE_RSA_PUBLIC_KEY)
    assert './user_ca' == pub_key.key_comment
    assert EXAMPLE_RSA_PUBLIC_KEY_N == pub_key.n
    assert EXAMPLE_RSA_PUBLIC_KEY_E == pub_key.e
    assert 'RSA 09:26:ae:1a:a1:27:7c:42:c3:00:cc:1e:82:0b:1f:2f'== pub_key.fingerprint


def test_valid_ed25519():
    pub_key = get_ssh_public_key(EXAMPLE_ED25519_PUBLIC_KEY)
    assert 'Test ED25519 User Key' == pub_key.key_comment
    assert EXAMPLE_ED25519_PUBLIC_KEY_A == pub_key.a
    assert 'ED25519 fb:80:ca:21:7d:c8:9d:38:35:c0:f6:ba:fb:6d:82:e8' == pub_key.fingerprint


def test_invalid_key():
    with pytest.raises(TypeError):
        get_ssh_public_key(EXAMPLE_ECDSA_PUBLIC_KEY)

