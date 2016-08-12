import os
import pytest

from bless.aws_lambda.bless_lambda import lambda_handler
from bless.ssh.certificates.ssh_certificate_builder import SSHCertificateType
from tests.ssh.vectors import EXAMPLE_RSA_PUBLIC_KEY, RSA_CA_PRIVATE_KEY_PASSWORD


class Context(object):
    aws_request_id = 'bogus aws_request_id'
    invoked_function_arn = 'bogus invoked_function_arn'


VALID_TEST_REQUEST = {
    "remote_hostnames": ["example.com", "example1.com"],
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
}

os.environ['AWS_REGION'] = 'us-west-2'


def test_basic_local_request():
    cert = lambda_handler(VALID_TEST_REQUEST, context=Context,
                          ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                          entropy_check=False,
                          config_file=os.path.join(os.path.dirname(__file__), 'bless-test-host.cfg'))
    assert cert.startswith('ssh-rsa-cert-v01@openssh.com ')
