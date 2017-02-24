import os

import pytest

from bless.aws_lambda.bless_lambda import lambda_handler
from tests.ssh.vectors import EXAMPLE_RSA_PUBLIC_KEY, RSA_CA_PRIVATE_KEY_PASSWORD, \
    EXAMPLE_ED25519_PUBLIC_KEY


class Context(object):
    aws_request_id = 'bogus aws_request_id'
    invoked_function_arn = 'bogus invoked_function_arn'


VALID_TEST_REQUEST = {
    "remote_username": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1"
}

INVALID_TEST_REQUEST = {
    "remote_username": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "invalid_ip",
    "bastion_user": "user",
    "bastion_user_ip": "invalid_ip"
}

VALID_TEST_REQUEST_KMSAUTH = {
    "remote_username": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1",
    "kmsauth_token": "validkmsauthtoken",
}

INVALID_TEST_REQUEST_KEY_TYPE = {
    "remote_username": "user",
    "public_key_to_sign": EXAMPLE_ED25519_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1"
}

INVALID_TEST_REQUEST_EXTRA_FIELD = {
    "remote_username": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1",
    "bastion_ip": "127.0.0.1"  # Note this is now an invalid field.
}

INVALID_TEST_REQUEST_MISSING_FIELD = {
    "remote_username": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1"
}

os.environ['AWS_REGION'] = 'us-west-2'


def test_basic_local_request():
    cert = lambda_handler(VALID_TEST_REQUEST, context=Context,
                          ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                          entropy_check=False,
                          config_file=os.path.join(os.path.dirname(__file__), 'bless-test.cfg'))
    assert cert.startswith('ssh-rsa-cert-v01@openssh.com ')


def test_basic_local_unused_kmsauth_request():
    cert = lambda_handler(VALID_TEST_REQUEST_KMSAUTH, context=Context,
                          ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                          entropy_check=False,
                          config_file=os.path.join(os.path.dirname(__file__), 'bless-test.cfg'))
    assert cert.startswith('ssh-rsa-cert-v01@openssh.com ')


def test_basic_local_missing_kmsauth_request():
    with pytest.raises(ValueError):
        lambda_handler(VALID_TEST_REQUEST, context=Context,
                       ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                       entropy_check=False,
                       config_file=os.path.join(os.path.dirname(__file__),
                                                'bless-test-kmsauth.cfg'))


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
    with pytest.raises(ValueError):
        lambda_handler(VALID_TEST_REQUEST, context=Context,
                       ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                       entropy_check=False,
                       config_file=os.path.join(os.path.dirname(__file__), 'bless-test-with-test-user.cfg'))
