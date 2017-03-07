import base64

import pytest
from cryptography.hazmat.primitives.serialization import _ssh_read_next_string

from bless.ssh.certificate_authorities.rsa_certificate_authority import RSACertificateAuthority
from bless.ssh.certificates.rsa_certificate_builder import RSACertificateBuilder
from bless.ssh.certificates.ssh_certificate_builder import SSHCertificateType
from bless.ssh.public_keys.rsa_public_key import RSAPublicKey
from tests.ssh.vectors import RSA_CA_PRIVATE_KEY, RSA_CA_PRIVATE_KEY_PASSWORD, \
    EXAMPLE_RSA_PUBLIC_KEY, EXAMPLE_RSA_PUBLIC_KEY_NO_DESCRIPTION, RSA_USER_CERT_MINIMAL, \
    RSA_USER_CERT_DEFAULTS, RSA_USER_CERT_DEFAULTS_NO_PUBLIC_KEY_COMMENT, \
    RSA_USER_CERT_MANY_PRINCIPALS, RSA_HOST_CERT_MANY_PRINCIPALS, \
    RSA_USER_CERT_FORCE_COMMAND_AND_SOURCE_ADDRESS, \
    RSA_USER_CERT_FORCE_COMMAND_AND_SOURCE_ADDRESS_KEY_ID, RSA_HOST_CERT_MANY_PRINCIPALS_KEY_ID, \
    RSA_USER_CERT_MANY_PRINCIPALS_KEY_ID, RSA_USER_CERT_DEFAULTS_NO_PUBLIC_KEY_COMMENT_KEY_ID, \
    RSA_USER_CERT_DEFAULTS_KEY_ID, SSH_CERT_DEFAULT_EXTENSIONS, SSH_CERT_CUSTOM_EXTENSIONS

USER1 = 'user1'


def get_basic_public_key(public_key):
    return RSAPublicKey(public_key)


def get_basic_rsa_ca():
    return RSACertificateAuthority(RSA_CA_PRIVATE_KEY, RSA_CA_PRIVATE_KEY_PASSWORD)


def get_basic_cert_builder_rsa(cert_type=SSHCertificateType.USER,
                               public_key=EXAMPLE_RSA_PUBLIC_KEY):
    ca = get_basic_rsa_ca()
    pub_key = get_basic_public_key(public_key)
    return RSACertificateBuilder(ca, cert_type, pub_key)


def extract_nonce_from_cert(cert_file):
    cert = cert_file.split(' ')[1]
    cert_type, cert_remainder = _ssh_read_next_string(base64.b64decode(cert))
    nonce, cert_remainder = _ssh_read_next_string(cert_remainder)
    return nonce


def test_valid_principals():
    USER2 = 'second_user'

    cert = get_basic_cert_builder_rsa()

    # No principals by default
    assert list() == cert.valid_principals

    # Two principals
    cert.add_valid_principal(USER1)
    cert.add_valid_principal(USER2)
    assert [USER1, USER2] == cert.valid_principals

    # Adding a null principal should throw a ValueError
    with pytest.raises(ValueError):
        cert.add_valid_principal('')

    # Adding same principal twice should not change the list, and throw a ValueError
    with pytest.raises(ValueError):
        cert.add_valid_principal(USER1)
    assert [USER1, USER2] == cert.valid_principals


def test_serialize_no_principals():
    cert = get_basic_cert_builder_rsa()

    assert list() == cert.valid_principals
    assert '' == cert._serialize_valid_principals()


def test_serialize_one_principal():
    expected = base64.b64decode('AAAABXVzZXIx')

    cert = get_basic_cert_builder_rsa()
    cert.add_valid_principal(USER1)

    assert expected == cert._serialize_valid_principals()


def test_serialize_multiple_principals():
    users = 'user1,user2,other_user1,other_user2'
    expected = base64.b64decode('AAAABXVzZXIxAAAABXVzZXIyAAAAC290aGVyX3VzZXIxAAAAC290aGVyX3VzZXIy')

    cert = get_basic_cert_builder_rsa()
    for user in users.split(','):
        cert.add_valid_principal(user)

    assert expected == cert._serialize_valid_principals()


def test_no_extensions():
    cert_builder = get_basic_cert_builder_rsa()
    assert cert_builder.extensions is None

    cert_builder.clear_extensions()
    assert '' == cert_builder._serialize_extensions()


def test_bogus_cert_validity_range():
    cert_builder = get_basic_cert_builder_rsa()
    with pytest.raises(ValueError):
        cert_builder.set_valid_after(100)
        cert_builder.set_valid_after(99)
        cert_builder._validate_cert_properties()


def test_bogus_critical_options():
    cert_builder = get_basic_cert_builder_rsa()
    with pytest.raises(ValueError):
        cert_builder.set_critical_option_force_command('')

    with pytest.raises(ValueError):
        cert_builder.set_critical_option_source_addresses('')


def test_rsa_user_cert_minimal():
    cert_builder = get_basic_cert_builder_rsa()
    cert_builder.set_nonce(nonce=extract_nonce_from_cert(RSA_USER_CERT_MINIMAL))
    cert_builder.clear_extensions()
    cert = cert_builder.get_cert_file()
    assert RSA_USER_CERT_MINIMAL == cert


def test_default_extensions():
    cert_builder = get_basic_cert_builder_rsa()
    cert_builder.set_extensions_to_default()
    assert SSH_CERT_DEFAULT_EXTENSIONS == cert_builder._serialize_extensions()


def test_add_extensions():
    extensions = {'permit-port-forwarding',
                  'permit-pty', 'permit-user-rc'}

    cert_builder = get_basic_cert_builder_rsa()

    for extension in extensions:
        cert_builder.add_extension(extension)

    print base64.b64encode(cert_builder._serialize_extensions())
    assert SSH_CERT_CUSTOM_EXTENSIONS == cert_builder._serialize_extensions()


def test_rsa_user_cert_defaults():
    cert_builder = get_basic_cert_builder_rsa()
    cert_builder.set_nonce(nonce=extract_nonce_from_cert(RSA_USER_CERT_DEFAULTS))
    cert_builder.set_key_id(RSA_USER_CERT_DEFAULTS_KEY_ID)

    cert = cert_builder.get_cert_file()
    assert RSA_USER_CERT_DEFAULTS == cert


def test_rsa_user_cert_duplicate_signs():
    cert_builder = get_basic_cert_builder_rsa()
    cert_builder.set_nonce(nonce=extract_nonce_from_cert(RSA_USER_CERT_DEFAULTS))
    cert_builder.set_key_id(RSA_USER_CERT_DEFAULTS_KEY_ID)
    cert_builder._sign_cert()

    cert = cert_builder.get_cert_file()
    assert RSA_USER_CERT_DEFAULTS == cert


def test_rsa_user_cert_defaults_no_public_key_comment():
    cert_builder = get_basic_cert_builder_rsa(public_key=EXAMPLE_RSA_PUBLIC_KEY_NO_DESCRIPTION)
    cert_builder.set_nonce(
        nonce=extract_nonce_from_cert(RSA_USER_CERT_DEFAULTS_NO_PUBLIC_KEY_COMMENT))
    cert_builder.set_key_id(RSA_USER_CERT_DEFAULTS_NO_PUBLIC_KEY_COMMENT_KEY_ID)

    cert = cert_builder.get_cert_file()
    assert RSA_USER_CERT_DEFAULTS_NO_PUBLIC_KEY_COMMENT == cert


def test_rsa_user_cert_many_principals():
    cert_builder = get_basic_cert_builder_rsa()
    cert_builder.set_nonce(nonce=extract_nonce_from_cert(RSA_USER_CERT_MANY_PRINCIPALS))
    cert_builder.set_key_id(RSA_USER_CERT_MANY_PRINCIPALS_KEY_ID)

    principals = 'user1,user2,other_user1,other_user2'
    for principal in principals.split(','):
        cert_builder.add_valid_principal(principal)

    cert = cert_builder.get_cert_file()
    assert RSA_USER_CERT_MANY_PRINCIPALS == cert


def test_rsa_host_cert_many_principals():
    cert_builder = get_basic_cert_builder_rsa(cert_type=SSHCertificateType.HOST)
    cert_builder.set_nonce(nonce=extract_nonce_from_cert(RSA_HOST_CERT_MANY_PRINCIPALS))
    cert_builder.set_key_id(RSA_HOST_CERT_MANY_PRINCIPALS_KEY_ID)

    principals = 'host.example.com,192.168.1.1,host2.example.com'
    for principal in principals.split(','):
        cert_builder.add_valid_principal(principal)

    cert = cert_builder.get_cert_file()
    assert RSA_HOST_CERT_MANY_PRINCIPALS == cert


def test_rsa_user_cert_critical_opt_source_address():
    cert_builder = get_basic_cert_builder_rsa()
    cert_builder.set_nonce(
        nonce=extract_nonce_from_cert(RSA_USER_CERT_FORCE_COMMAND_AND_SOURCE_ADDRESS))
    cert_builder.set_key_id(RSA_USER_CERT_FORCE_COMMAND_AND_SOURCE_ADDRESS_KEY_ID)
    cert_builder.set_critical_option_force_command('/bin/ls')
    cert_builder.set_critical_option_source_addresses('192.168.1.0/24')

    cert = cert_builder.get_cert_file()

    assert RSA_USER_CERT_FORCE_COMMAND_AND_SOURCE_ADDRESS == cert


def test_nonce():
    cert_builder = get_basic_cert_builder_rsa()
    cert_builder.set_nonce()

    cert_builder2 = get_basic_cert_builder_rsa()
    cert_builder2.set_nonce()

    assert cert_builder.nonce != cert_builder2.nonce
