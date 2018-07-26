import base64
import os
import zlib
import pytest

from bless.config.bless_config import BlessConfig, \
    BLESS_OPTIONS_SECTION, \
    CERTIFICATE_VALIDITY_BEFORE_SEC_OPTION, \
    CERTIFICATE_VALIDITY_AFTER_SEC_OPTION, \
    ENTROPY_MINIMUM_BITS_OPTION, \
    RANDOM_SEED_BYTES_OPTION, \
    CERTIFICATE_VALIDITY_SEC_DEFAULT, \
    ENTROPY_MINIMUM_BITS_DEFAULT, \
    RANDOM_SEED_BYTES_DEFAULT, \
    LOGGING_LEVEL_DEFAULT, \
    LOGGING_LEVEL_OPTION, \
    BLESS_CA_SECTION, \
    CA_PRIVATE_KEY_FILE_OPTION, \
    KMSAUTH_SECTION, \
    KMSAUTH_USEKMSAUTH_OPTION, \
    KMSAUTH_KEY_ID_OPTION, \
    KMSAUTH_SERVICE_ID_OPTION, \
    CERTIFICATE_EXTENSIONS_OPTION, \
    USERNAME_VALIDATION_OPTION, \
    USERNAME_VALIDATION_DEFAULT, \
    REMOTE_USERNAMES_VALIDATION_OPTION, \
    CA_PRIVATE_KEY_COMPRESSION_OPTION, \
    CA_PRIVATE_KEY_COMPRESSION_OPTION_DEFAULT


def test_empty_config():
    with pytest.raises(ValueError):
        BlessConfig('us-west-2', config_file='')


def test_config_no_password():
    with pytest.raises(ValueError) as e:
        BlessConfig('bogus-region',
                    config_file=os.path.join(os.path.dirname(__file__), 'full.cfg'))
    assert 'No Region Specific And No Default Password Provided.' == str(e.value)

    config = BlessConfig('bogus-region',
                         config_file=os.path.join(os.path.dirname(__file__), 'full-with-default.cfg'))
    assert '<INSERT_DEFAULT_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>' == config.getpassword()

def test_wrong_compression_env_key(monkeypatch):
    extra_environment_variables = {
        'bless_ca_default_password': '<INSERT_DEFAULT_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>',
        'bless_ca_ca_private_key_compression': 'lzh',
        'bless_ca_ca_private_key': str(base64.b64encode(b'<INSERT_YOUR_ENCRYPTED_PEM_FILE_CONTENT>'), encoding='ascii')
    }

    for k, v in extra_environment_variables.items():
        monkeypatch.setenv(k, v)

    # Create an empty config, everything is set in the environment
    config = BlessConfig('us-east-1', config_file='')

    with pytest.raises(ValueError) as e:
        config.getprivatekey()

    assert "Compression lzh is not supported." == str(e.value)

def test_none_compression_env_key(monkeypatch):
    extra_environment_variables = {
        'bless_ca_default_password': '<INSERT_DEFAULT_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>',
        'bless_ca_ca_private_key_compression': 'none',
        'bless_ca_ca_private_key': str(base64.b64encode(b'<INSERT_YOUR_ENCRYPTED_PEM_FILE_CONTENT>'), encoding='ascii')
    }

    for k, v in extra_environment_variables.items():
        monkeypatch.setenv(k, v)

    # Create an empty config, everything is set in the environment
    config = BlessConfig('us-east-1', config_file='')

    assert b'<INSERT_YOUR_ENCRYPTED_PEM_FILE_CONTENT>' == config.getprivatekey()

def test_zlib_positive_compression(monkeypatch):
    extra_environment_variables = {
        'bless_ca_default_password': '<INSERT_DEFAULT_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>',
        'bless_ca_ca_private_key_compression': 'zlib',
        'bless_ca_ca_private_key': str(base64.b64encode(zlib.compress(b'<INSERT_YOUR_ENCRYPTED_PEM_FILE_CONTENT>')), encoding='ascii')
    }

    for k, v in extra_environment_variables.items():
        monkeypatch.setenv(k, v)

    # Create an empty config, everything is set in the environment
    config = BlessConfig('us-east-1', config_file='')

    assert b'<INSERT_YOUR_ENCRYPTED_PEM_FILE_CONTENT>' == config.getprivatekey()

def test_zlib_compression_env_with_uncompressed_key(monkeypatch):
    extra_environment_variables = {
        'bless_ca_default_password': '<INSERT_DEFAULT_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>',
        'bless_ca_ca_private_key_compression': 'zlib',
        'bless_ca_ca_private_key': base64.b64encode(b'<INSERT_YOUR_ENCRYPTED_PEM_FILE_CONTENT>'),
    }

    for k, v in extra_environment_variables.items():
        monkeypatch.setenv(k, v)

    # Create an empty config, everything is set in the environment
    config = BlessConfig('us-east-1', config_file='')

    with pytest.raises(zlib.error) as e:
        config.getprivatekey()

def test_config_environment_override(monkeypatch):
    extra_environment_variables = {
        'bless_options_certificate_validity_after_seconds': '1',
        'bless_options_certificate_validity_before_seconds': '1',
        'bless_options_entropy_minimum_bits': '2',
        'bless_options_random_seed_bytes': '3',
        'bless_options_logging_level': 'DEBUG',
        'bless_options_certificate_extensions': 'permit-X11-forwarding',
        'bless_options_username_validation': 'debian',
        'bless_options_remote_usernames_validation': 'useradd',

        'bless_ca_us_east_1_password': '<INSERT_US-EAST-1_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>',
        'bless_ca_default_password': '<INSERT_DEFAULT_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>',
        'bless_ca_ca_private_key_file': '<INSERT_YOUR_ENCRYPTED_PEM_FILE_NAME>',
        'bless_ca_ca_private_key': str(base64.b64encode(b'<INSERT_YOUR_ENCRYPTED_PEM_FILE_CONTENT>'), encoding='ascii'),

        'kms_auth_use_kmsauth': 'True',
        'kms_auth_kmsauth_key_id': '<INSERT_ARN>',
        'kms_auth_kmsauth_serviceid': 'bless-test',
    }

    for k, v in extra_environment_variables.items():
        monkeypatch.setenv(k, v)

    # Create an empty config, everything is set in the environment
    config = BlessConfig('us-east-1', config_file='')

    assert 1 == config.getint(BLESS_OPTIONS_SECTION, CERTIFICATE_VALIDITY_AFTER_SEC_OPTION)
    assert 1 == config.getint(BLESS_OPTIONS_SECTION, CERTIFICATE_VALIDITY_BEFORE_SEC_OPTION)
    assert 2 == config.getint(BLESS_OPTIONS_SECTION, ENTROPY_MINIMUM_BITS_OPTION)
    assert 3 == config.getint(BLESS_OPTIONS_SECTION, RANDOM_SEED_BYTES_OPTION)
    assert 'DEBUG' == config.get(BLESS_OPTIONS_SECTION, LOGGING_LEVEL_OPTION)
    assert 'permit-X11-forwarding' == config.get(BLESS_OPTIONS_SECTION, CERTIFICATE_EXTENSIONS_OPTION)
    assert 'debian' == config.get(BLESS_OPTIONS_SECTION, USERNAME_VALIDATION_OPTION)
    assert 'useradd' == config.get(BLESS_OPTIONS_SECTION, REMOTE_USERNAMES_VALIDATION_OPTION)

    assert '<INSERT_US-EAST-1_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>' == config.getpassword()
    assert '<INSERT_YOUR_ENCRYPTED_PEM_FILE_NAME>' == config.get(BLESS_CA_SECTION, CA_PRIVATE_KEY_FILE_OPTION)
    assert b'<INSERT_YOUR_ENCRYPTED_PEM_FILE_CONTENT>' == config.getprivatekey()

    assert config.getboolean(KMSAUTH_SECTION, KMSAUTH_USEKMSAUTH_OPTION)
    assert '<INSERT_ARN>' == config.get(KMSAUTH_SECTION, KMSAUTH_KEY_ID_OPTION)
    assert 'bless-test' == config.get(KMSAUTH_SECTION, KMSAUTH_SERVICE_ID_OPTION)

    config.aws_region = 'invalid'
    assert '<INSERT_DEFAULT_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>' == config.getpassword()


@pytest.mark.parametrize(
    "config,region,expected_cert_valid,expected_entropy_min,expected_rand_seed,expected_log_level,"
    "expected_password,expected_username_validation,expected_key_compression", [
        ((os.path.join(os.path.dirname(__file__), 'minimal.cfg')), 'us-west-2',
         CERTIFICATE_VALIDITY_SEC_DEFAULT, ENTROPY_MINIMUM_BITS_DEFAULT, RANDOM_SEED_BYTES_DEFAULT,
         LOGGING_LEVEL_DEFAULT,
         '<INSERT_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>',
         USERNAME_VALIDATION_DEFAULT,
         CA_PRIVATE_KEY_COMPRESSION_OPTION_DEFAULT
         ),
        ((os.path.join(os.path.dirname(__file__), 'full-zlib.cfg')), 'us-west-2',
         1, 2, 3, 'DEBUG',
         '<INSERT_US-WEST-2_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>',
         'debian',
         'zlib'
         ),
        ((os.path.join(os.path.dirname(__file__), 'full.cfg')), 'us-east-1',
         1, 2, 3, 'DEBUG',
         '<INSERT_US-EAST-1_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>',
         'debian',
         'zlib'
         )
    ])
def test_configs(config, region, expected_cert_valid, expected_entropy_min, expected_rand_seed,
                 expected_log_level, expected_password, expected_username_validation, expected_key_compression):
    config = BlessConfig(region, config_file=config)
    assert expected_cert_valid == config.getint(BLESS_OPTIONS_SECTION,
                                                CERTIFICATE_VALIDITY_BEFORE_SEC_OPTION)
    assert expected_cert_valid == config.getint(BLESS_OPTIONS_SECTION,
                                                CERTIFICATE_VALIDITY_AFTER_SEC_OPTION)

    assert expected_entropy_min == config.getint(BLESS_OPTIONS_SECTION,
                                                 ENTROPY_MINIMUM_BITS_OPTION)
    assert expected_rand_seed == config.getint(BLESS_OPTIONS_SECTION,
                                               RANDOM_SEED_BYTES_OPTION)
    assert expected_log_level == config.get(BLESS_OPTIONS_SECTION, LOGGING_LEVEL_OPTION)
    assert expected_password == config.getpassword()
    assert expected_username_validation == config.get(BLESS_OPTIONS_SECTION,
                                                      USERNAME_VALIDATION_OPTION)
    assert expected_key_compression == config.get(BLESS_CA_SECTION,
                                                  CA_PRIVATE_KEY_COMPRESSION_OPTION)
