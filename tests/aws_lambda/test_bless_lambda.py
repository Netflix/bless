import os

import pytest

from bless.aws_lambda.bless_lambda import lambda_handler
from tests.ssh.vectors import EXAMPLE_RSA_PUBLIC_KEY, RSA_CA_PRIVATE_KEY_PASSWORD, \
    EXAMPLE_ED25519_PUBLIC_KEY


class Context(object):
    aws_request_id = 'bogus aws_request_id'
    invoked_function_arn = 'bogus invoked_function_arn'


VALID_TEST_REQUEST = {
    "remote_usernames": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1"
}

VALID_TEST_REQUEST_USERNAME_VALIDATION_EMAIL_REMOTE_USERNAMES_USERADD = {
    "remote_usernames": "user,anotheruser",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "someone@example.com",
    "bastion_user_ip": "127.0.0.1"
}

VALID_TEST_REQUEST_USERNAME_VALIDATION_DISABLED = {
    "remote_usernames": "'~:, \n\t@'",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "a33characterusernameyoumustbenuts",
    "bastion_user_ip": "127.0.0.1"
}

INVALID_TEST_REQUEST = {
    "remote_usernames": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "invalid_ip",
    "bastion_user": "user",
    "bastion_user_ip": "invalid_ip"
}

VALID_TEST_REQUEST_KMSAUTH = {
    "remote_usernames": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1",
    "kmsauth_token": "validkmsauthtoken",
}

INVALID_TEST_REQUEST_KEY_TYPE = {
    "remote_usernames": "user",
    "public_key_to_sign": EXAMPLE_ED25519_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1"
}

INVALID_TEST_REQUEST_EXTRA_FIELD = {
    "remote_usernames": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1",
    "bastion_ip": "127.0.0.1"  # Note this is now an invalid field.
}

INVALID_TEST_REQUEST_MISSING_FIELD = {
    "remote_usernames": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1"
}

VALID_TEST_REQUEST_MULTIPLE_PRINCIPALS = {
    "remote_usernames": "user1,user2",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1"
}

INVALID_TEST_REQUEST_MULTIPLE_PRINCIPALS = {
    "remote_usernames": ",user#",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1"
}

INVALID_TEST_REQUEST_USERNAME_INVALID = {
    "remote_usernames": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "~@.",
    "bastion_user_ip": "127.0.0.1"
}

INVALID_TEST_KMSAUTH_REQUEST_USERNAME_DOESNT_MATCH_REMOTE = {
    "remote_usernames": "userb",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "usera",
    "bastion_user_ip": "127.0.0.1",
    "kmsauth_token": "validkmsauthtoken"
}

INVALID_TEST_KMSAUTH_REQUEST_DIFFERENT_REMOTE_USER = {
    "remote_usernames": "root",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "usera",
    "bastion_user_ip": "127.0.0.1",
    "kmsauth_token": "validkmsauthtoken"
}

VALID_TEST_KMSAUTH_REQUEST_DIFFERENT_REMOTE_USER = {
    "remote_usernames": "alloweduser",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "usera",
    "bastion_user_ip": "127.0.0.1",
    "kmsauth_token": "validkmsauthtoken"
}

os.environ['AWS_REGION'] = 'us-west-2'


def test_basic_local_request():
    output = lambda_handler(VALID_TEST_REQUEST, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), 'bless-test.cfg'))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_basic_local_unused_kmsauth_request():
    output = lambda_handler(VALID_TEST_REQUEST_KMSAUTH, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), 'bless-test.cfg'))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_basic_local_missing_kmsauth_request():
    output = lambda_handler(VALID_TEST_REQUEST, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-kmsauth.cfg'))
    assert output['errorType'] == 'InputValidationError'


def test_basic_local_username_validation_disabled(monkeypatch):
    extra_environment_variables = {
        'bless_ca_default_password': '<INSERT_DEFAULT_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>',
        'bless_ca_ca_private_key_file': 'tests/aws_lambda/only-use-for-unit-tests.pem',
        'bless_options_username_validation': 'disabled',
        'bless_options_remote_usernames_validation': 'disabled',
    }

    for k, v in extra_environment_variables.items():
        monkeypatch.setenv(k, v)

    output = lambda_handler(VALID_TEST_REQUEST_USERNAME_VALIDATION_DISABLED, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), ''))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_basic_local_username_validation_email_remote_usernames_useradd(monkeypatch):
    extra_environment_variables = {
        'bless_ca_default_password': '<INSERT_DEFAULT_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>',
        'bless_ca_ca_private_key_file': 'tests/aws_lambda/only-use-for-unit-tests.pem',
        'bless_options_username_validation': 'email',
        'bless_options_remote_usernames_validation': 'useradd',
    }

    for k, v in extra_environment_variables.items():
        monkeypatch.setenv(k, v)

    output = lambda_handler(VALID_TEST_REQUEST_USERNAME_VALIDATION_EMAIL_REMOTE_USERNAMES_USERADD, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), ''))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_invalid_username_request():
    output = lambda_handler(INVALID_TEST_REQUEST_USERNAME_INVALID, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test.cfg'))
    assert output['errorType'] == 'InputValidationError'


def test_invalid_kmsauth_request():
    output = lambda_handler(VALID_TEST_REQUEST_KMSAUTH, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-kmsauth.cfg'))
    assert output['errorType'] == 'KMSAuthValidationError'


def test_invalid_request():
    output = lambda_handler(INVALID_TEST_REQUEST, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), 'bless-test.cfg'))
    assert output['errorType'] == 'InputValidationError'


def test_local_request_key_not_found():
    with pytest.raises(IOError):
        lambda_handler(VALID_TEST_REQUEST, context=Context,
                       ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                       entropy_check=False,
                       config_file=os.path.join(os.path.dirname(__file__), 'bless-test-broken.cfg'))


def test_local_request_config_not_found():
    with pytest.raises(ValueError):
        lambda_handler(VALID_TEST_REQUEST, context=Context,
                       ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                       entropy_check=False,
                       config_file=os.path.join(os.path.dirname(__file__), 'none'))


def test_local_request_invalid_pub_key():
    output = lambda_handler(INVALID_TEST_REQUEST_KEY_TYPE, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), 'bless-test.cfg'))
    assert output['errorType'] == 'InputValidationError'


def test_local_request_extra_field():
    output = lambda_handler(INVALID_TEST_REQUEST_EXTRA_FIELD, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), 'bless-test.cfg'))
    assert output['errorType'] == 'InputValidationError'


def test_local_request_missing_field():
    output = lambda_handler(INVALID_TEST_REQUEST_MISSING_FIELD, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), 'bless-test.cfg'))
    assert output['errorType'] == 'InputValidationError'


def test_local_request_with_test_user():
    output = lambda_handler(VALID_TEST_REQUEST, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), 'bless-test-with-test-user.cfg'))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_local_request_with_custom_certificate_extensions():
    output = lambda_handler(VALID_TEST_REQUEST, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-with-certificate-extensions.cfg'))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_local_request_with_empty_certificate_extensions():
    output = lambda_handler(VALID_TEST_REQUEST, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-with-certificate-extensions-empty.cfg'))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_local_request_with_multiple_principals():
    output = lambda_handler(VALID_TEST_REQUEST_MULTIPLE_PRINCIPALS, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test.cfg'))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_invalid_request_with_multiple_principals():
    output = lambda_handler(INVALID_TEST_REQUEST_MULTIPLE_PRINCIPALS, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test.cfg'))
    assert output['errorType'] == 'InputValidationError'


def test_invalid_request_with_mismatched_bastion_and_remote():
    '''
    Test default kmsauth behavior, that a bastion_user and remote_usernames must match
    :return: 
    '''
    output = lambda_handler(INVALID_TEST_KMSAUTH_REQUEST_USERNAME_DOESNT_MATCH_REMOTE, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-kmsauth.cfg'))
    assert output['errorType'] == 'KMSAuthValidationError'


def test_invalid_request_with_unallowed_remote():
    output = lambda_handler(INVALID_TEST_KMSAUTH_REQUEST_DIFFERENT_REMOTE_USER, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-kmsauth-different-remote.cfg'))
    assert output['errorType'] == 'KMSAuthValidationError'


def test_valid_request_with_allowed_remote(mocker):
    mocker.patch("kmsauth.KMSTokenValidator.decrypt_token")
    output = lambda_handler(VALID_TEST_KMSAUTH_REQUEST_DIFFERENT_REMOTE_USER, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-kmsauth-different-remote.cfg'))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')

def test_valid_request_with_allowed_remote_and_allowed_iam_group(mocker):
    mocker.patch("kmsauth.KMSTokenValidator.decrypt_token")
    clientmock = mocker.MagicMock()
    clientmock.list_groups_for_user.return_value = {"Groups":[{"GroupName":"ssh-alloweduser"}]}
    botomock = mocker.patch('boto3.client')
    botomock.return_value = clientmock
    output = lambda_handler(VALID_TEST_KMSAUTH_REQUEST_DIFFERENT_REMOTE_USER, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-kmsauth-iam-group-validation.cfg'))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_invalid_request_with_allowed_remote_and_not_allowed_iam_group(mocker):
    mocker.patch("kmsauth.KMSTokenValidator.decrypt_token")
    clientmock = mocker.MagicMock()
    clientmock.list_groups_for_user.return_value = {"Groups": [{"GroupName": "ssh-notalloweduser"}]}
    botomock = mocker.patch('boto3.client')
    botomock.return_value = clientmock
    output = lambda_handler(VALID_TEST_KMSAUTH_REQUEST_DIFFERENT_REMOTE_USER, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-kmsauth-iam-group-validation.cfg'))
    assert output['errorType'] == 'KMSAuthValidationError'