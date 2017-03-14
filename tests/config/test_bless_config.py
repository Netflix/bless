import os

import pytest

from bless.config.bless_config import BlessConfig, BLESS_OPTIONS_SECTION, \
    CERTIFICATE_VALIDITY_BEFORE_SEC_OPTION, CERTIFICATE_VALIDITY_AFTER_SEC_OPTION, \
    ENTROPY_MINIMUM_BITS_OPTION, RANDOM_SEED_BYTES_OPTION, \
    CERTIFICATE_VALIDITY_SEC_DEFAULT, ENTROPY_MINIMUM_BITS_DEFAULT, RANDOM_SEED_BYTES_DEFAULT, \
    LOGGING_LEVEL_DEFAULT, LOGGING_LEVEL_OPTION, USERNAME_VALIDATION_OPTION, USERNAME_VALIDATION_DEFAULT


def test_empty_config():
    with pytest.raises(ValueError):
        BlessConfig('us-west-2', config_file='')


def test_config_no_password():
    with pytest.raises(ValueError) as e:
        BlessConfig('bogus-region',
                    config_file=os.path.join(os.path.dirname(__file__), 'full.cfg'))
    assert 'No Region Specific Password Provided.' == e.value.message


@pytest.mark.parametrize(
    "config,region,expected_cert_valid,expected_entropy_min,expected_rand_seed,expected_log_level,"
    "expected_password,expected_username_validation", [
        ((os.path.join(os.path.dirname(__file__), 'minimal.cfg')), 'us-west-2',
         CERTIFICATE_VALIDITY_SEC_DEFAULT, ENTROPY_MINIMUM_BITS_DEFAULT, RANDOM_SEED_BYTES_DEFAULT,
         LOGGING_LEVEL_DEFAULT,
         '<INSERT_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>',
         USERNAME_VALIDATION_DEFAULT
        ),
        ((os.path.join(os.path.dirname(__file__), 'full.cfg')), 'us-west-2',
         1, 2, 3, 'DEBUG',
         '<INSERT_US-WEST-2_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>',
         'debian'
        ),
        ((os.path.join(os.path.dirname(__file__), 'full.cfg')), 'us-east-1',
         1, 2, 3, 'DEBUG',
         '<INSERT_US-EAST-1_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>',
         'debian'
        )
    ])
def test_configs(config, region, expected_cert_valid, expected_entropy_min, expected_rand_seed,
                 expected_log_level, expected_password, expected_username_validation):
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
