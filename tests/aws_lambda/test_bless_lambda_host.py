import os

from bless.aws_lambda.bless_lambda_host import lambda_handler_host
from tests.ssh.vectors import EXAMPLE_RSA_PUBLIC_KEY, RSA_CA_PRIVATE_KEY_PASSWORD


class Context(object):
    aws_request_id = 'bogus aws_request_id'
    invoked_function_arn = 'bogus invoked_function_arn'


VALID_TEST_REQUEST = {
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "hostnames": "thisthat.com",
}

VALID_TEST_REQUEST_MULTIPLE_HOSTS = {
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "hostnames": "thisthat.com,thatthis.com",
}

INVALID_TEST_REQUEST = {
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "hostname": "thisthat.com",  # Wrong key name
}

os.environ['AWS_REGION'] = 'us-west-2'


def test_basic_local_request():
    output = lambda_handler_host(VALID_TEST_REQUEST, context=Context,
                                 ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                                 entropy_check=False,
                                 config_file=os.path.join(os.path.dirname(__file__), 'bless-test.cfg'))
    print(output)
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_basic_local_request_with_multiple_hosts():
    output = lambda_handler_host(VALID_TEST_REQUEST_MULTIPLE_HOSTS, context=Context,
                                 ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                                 entropy_check=False,
                                 config_file=os.path.join(os.path.dirname(__file__), 'bless-test.cfg'))
    print(output)
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_invalid_request():
    output = lambda_handler_host(INVALID_TEST_REQUEST, context=Context,
                                 ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                                 entropy_check=False,
                                 config_file=os.path.join(os.path.dirname(__file__), 'bless-test.cfg'))
    assert output['errorType'] == 'InputValidationError'
