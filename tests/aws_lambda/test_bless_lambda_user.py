import os
import zlib
import datetime
import pytest

from bless.aws_lambda.bless_lambda_user import lambda_handler_user
from bless.aws_lambda.bless_lambda import lambda_handler
from tests.ssh.vectors import EXAMPLE_RSA_PUBLIC_KEY, RSA_CA_PRIVATE_KEY_PASSWORD, \
    EXAMPLE_ED25519_PUBLIC_KEY, EXAMPLE_ECDSA_PUBLIC_KEY
from jose import jwt

class Context(object):
    aws_request_id = 'bogus aws_request_id'
    invoked_function_arn = 'bogus invoked_function_arn'

JWTAUTH_JWK_SIGN = {
  "kty": "RSA",
  "d": "rCI3nedHZQF6VJHiKHTJHis9heGhrg3m5Ohbz96-GlN_HH3AQFuNe9El2_DCEz0DFrRACyjYkXao3r-Cc3hyVnBluTvoq25odvKwyXc0rNVTDRt_nQsrVrgaZ5oYkWhp3yDWmY4GRfE2r4ZisrQ9b7-vKXjzepTBlJfPlc75dVR5RoS5WISqt5jPPl2jGlbCmWw1Qb4N1TwCWXHtK5ns6IfeewlMyn7rpm3CfYblQlMGOorB6QzID4cEd2ogagJQIICPXlmbZ6N8qXEPWpVBQ0Krum91RmFButf0rUt-ODPe-BTmYLsa4txk5IFaHOLjzVjmq6AgRVxWmsA_rbOhMQ",
  "e": "AQAB",
  "use": "sig",
  "kid": "key1",
  "alg": "RS256",
  "n": "7V4O45XkdzKedgfbg3U1X_UeGF00wQH6APcuRX_702h-3QZI4VmAbBFgDDAJgHa1wunKPUKmwfmzFodLX6Bd2UvgHtzhHDAnrHYSOpV0jci7zxUhPN84PBbNRKNG-yAGPvNk4YbCWHywz7BKmTVnG9q4KSdWaHpyhljxedMdkt2JqdTJcwaAEfqT_0A-gcBWxyCPwRJJRLColM9g6lZU7-17Y3UNHwBFC4lahfd009CXY7WMbKIJMG0LuBjsmCE4L__IlrFlevVFyA0ShDjDh07gKD-f5WJ6WdgcZOL7X3rf-DK6MRBUW4ItIpG7DVVWN0Vj6SNQT3x1kwq55mIZTw"
}

JWTAUTH_JWK_BAD_SIGN = {
  "kty": "RSA",
  "d": "bGRl4H_ZRz4UaXXHpBjsGvSmEazJ0YJjWt_DNG3SjsHrFZwLXU2CWLP1-JAVe9Y2VRIuTKSdOBDbEWiSpAsH7iAirxKGqmIBLaYOrK170zrzWcToSGcIZziBbwTZpIy9Z55loXrtFjkObUfoEw7erHNNJfM0-jg79W_Phe89mtqbAf6twzB76yS4hcIzQdkTT_0q0PNj0n4DC8uDZC70gzHDGjtGUQmjw1ZXHCGFZaFESQjbv9-2SlhS5foLeNtuKCkQMRAeRaJ5_fLnJs61yVKwRzOz4r73yfTPlsYfhFXN5M4P6C1GOaDZANzl3uFsU88aCydEuFXEdWcRHeSw2Q",
  "e": "AQAB",
  "use": "sig",
  "kid": "key1",
  "alg": "RS256",
  "n": "xPrwx5lWUhlPvH4qa791zUczNIPclGR3fnw6RHPtt8gExFfyChJ34lgHTRloEsRLTDyIfDgmTzGJHPBVYyxm8G7b3oC2KKbfczagb4Hfw0iIC1wXdp8PFiWy3L4qE6bh-3D0wwwqAQXyOx7ITa44oOYQzevYp637pzyCSZrInBDf9-TvyVjoO9erpbyHr7SnvIN8cccyqoQdpobG5N7vcSGWDXJrD1ZNKU624wAbe6ARUlOj7JdNxsFRO92IQSEZycTPo3aKhcQFqasQeRTNS_GChrcVvKfrBRt3KTWai9-hbtjlOetTfhtaGnbO2AxbMYgmis-_MSXTXs9VssqbVw"
}

VALID_TEST_REQUEST = {
    "remote_usernames": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1"
}

VALID_TEST_REQUEST_ED2551 = {
    "remote_usernames": "user",
    "public_key_to_sign": EXAMPLE_ED25519_PUBLIC_KEY,
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

VALID_TEST_REQUEST_JWTAUTH = {
    "remote_usernames": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1",
    "jwtauth_token": jwt.encode({
        "exp":datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        "iss":"https://issuer.example.com",
        "aud":"6c1d8893-9240-4f87-be95-1f21ef664ce0",
        "username": "user"
    }, JWTAUTH_JWK_SIGN, algorithm="RS256"),
}

INVALID_TEST_REQUEST_JWTAUTH = {
    "remote_usernames": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1",
    "jwtauth_token": "",
}

INVALID_TEST_REQUEST_KEY_TYPE = {
    "remote_usernames": "user",
    "public_key_to_sign": EXAMPLE_ECDSA_PUBLIC_KEY,
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

INVALID_TEST_REQUEST_BLACKLISTED_REMOTE_USERNAME = {
    "remote_usernames": "alloweduser,balrog",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1"
}

INVALID_TEST_JWTAUTH_REQUEST_USERNAME_DOESNT_MATCH_REMOTE = {
    "remote_usernames": "usera",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "userb",
    "bastion_user_ip": "127.0.0.1",
    "jwtauth_token": jwt.encode({
        "iss":"https://issuer.example.com",
        "aud":"6c1d8893-9240-4f87-be95-1f21ef664ce0",
        "username": "user"
    }, JWTAUTH_JWK_SIGN, algorithm="RS256"),
}

INVALID_TEST_JWTAUTH_REQUEST_EXPIRED_JWTAUTH_TOKEN = {
    "remote_usernames": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1",
    "jwtauth_token": jwt.encode({
        "exp":datetime.datetime.utcnow() - datetime.timedelta(hours=1),
        "iss":"https://issuer.example.com",
        "aud":"6c1d8893-9240-4f87-be95-1f21ef664ce0",
        "username": "user"
    }, JWTAUTH_JWK_SIGN, algorithm="RS256"),
}

INVALID_TEST_JWTAUTH_REQUEST_INCORRECT_ISSUER = {
    "remote_usernames": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1",
    "jwtauth_token": jwt.encode({
        "exp":datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        "iss":"https://bad.issuer",
        "aud":"6c1d8893-9240-4f87-be95-1f21ef664ce0",
        "username": "user"
    }, JWTAUTH_JWK_SIGN, algorithm="RS256"),
}

INVALID_TEST_JWTAUTH_REQUEST_INCORRECT_AUDIENCE = {
    "remote_usernames": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1",
    "jwtauth_token": jwt.encode({
        "exp":datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        "iss":"https://issuer.example.com",
        "aud":"bad.audience",
        "username": "user"
    }, JWTAUTH_JWK_SIGN, algorithm="RS256"),
}

INVALID_TEST_JWTAUTH_REQUEST_MISSING_USERNAME_CLAIM = {
    "remote_usernames": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1",
    "jwtauth_token": jwt.encode({
        "exp":datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        "iss":"https://issuer.example.com",
        "aud":"6c1d8893-9240-4f87-be95-1f21ef664ce0"
    }, JWTAUTH_JWK_SIGN, algorithm="RS256"),
}

INVALID_TEST_JWTAUTH_REQUEST_USERNAME_CLAIM_DOESNT_MATCH_REMOTE_USER = {
    "remote_usernames": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1",
    "jwtauth_token": jwt.encode({
        "exp":datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        "iss":"https://issuer.example.com",
        "aud":"6c1d8893-9240-4f87-be95-1f21ef664ce0",
        "username": "bad.user"
    }, JWTAUTH_JWK_SIGN, algorithm="RS256"),
}

INVALID_TEST_JWTAUTH_REQUEST_INCORRECT_SIGNATURE_ALGORITHM = {
    "remote_usernames": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1",
    "jwtauth_token": jwt.encode({
        "exp":datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        "iss":"https://issuer.example.com",
        "aud":"6c1d8893-9240-4f87-be95-1f21ef664ce0",
        "username": "user"
    }, JWTAUTH_JWK_SIGN, algorithm="RS512"),
}

INVALID_TEST_JWTAUTH_REQUEST_INCORRECT_SIGNATURE = {
    "remote_usernames": "user",
    "public_key_to_sign": EXAMPLE_RSA_PUBLIC_KEY,
    "command": "ssh user@server",
    "bastion_ips": "127.0.0.1",
    "bastion_user": "user",
    "bastion_user_ip": "127.0.0.1",
    "jwtauth_token": jwt.encode({
        "exp":datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        "iss":"https://issuer.example.com",
        "aud":"6c1d8893-9240-4f87-be95-1f21ef664ce0",
        "username": "user"
    }, JWTAUTH_JWK_BAD_SIGN, algorithm="RS256"),
}

def test_basic_local_request_with_wrapper():
    output = lambda_handler(VALID_TEST_REQUEST, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), 'bless-test.cfg'))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_basic_local_request():
    output = lambda_handler_user(VALID_TEST_REQUEST, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), 'bless-test.cfg'))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_basic_local_request_ed2551():
    output = lambda_handler_user(VALID_TEST_REQUEST_ED2551, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), 'bless-test.cfg'))
    assert output['certificate'].startswith('ssh-ed25519-cert-v01@openssh.com ')


def test_basic_local_unused_kmsauth_request():
    output = lambda_handler_user(VALID_TEST_REQUEST_KMSAUTH, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), 'bless-test.cfg'))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_basic_local_missing_kmsauth_request():
    output = lambda_handler_user(VALID_TEST_REQUEST, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-kmsauth.cfg'))
    assert output['errorType'] == 'InputValidationError'

def test_basic_local_unused_jwtauth_request():
    output = lambda_handler_user(VALID_TEST_REQUEST_JWTAUTH, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), 'bless-test.cfg'))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_basic_local_missing_jwtauth_request():
    output = lambda_handler_user(VALID_TEST_REQUEST, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-jwtauth.cfg'))
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

    output = lambda_handler_user(VALID_TEST_REQUEST_USERNAME_VALIDATION_DISABLED, context=Context,
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

    output = lambda_handler_user(VALID_TEST_REQUEST_USERNAME_VALIDATION_EMAIL_REMOTE_USERNAMES_USERADD, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), ''))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_basic_ca_private_key_file_bz2(monkeypatch):
    extra_environment_variables = {
        'bless_ca_default_password': '<INSERT_DEFAULT_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>',
        'bless_ca_ca_private_key_file': 'tests/aws_lambda/only-use-for-unit-tests.pem.bz2',
        'bless_ca_ca_private_key_compression': 'bz2',
        'bless_options_username_validation': 'email',
        'bless_options_remote_usernames_validation': 'useradd',
    }

    for k, v in extra_environment_variables.items():
        monkeypatch.setenv(k, v)

    output = lambda_handler_user(VALID_TEST_REQUEST_USERNAME_VALIDATION_EMAIL_REMOTE_USERNAMES_USERADD, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), ''))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_basic_ca_private_key_env_bz2(monkeypatch):
    extra_environment_variables = {
        'bless_ca_default_password': '<INSERT_DEFAULT_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>',
        'bless_ca_ca_private_key': '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',
        'bless_ca_ca_private_key_compression': 'bz2',
        'bless_options_username_validation': 'email',
        'bless_options_remote_usernames_validation': 'useradd',
    }

    for k, v in extra_environment_variables.items():
        monkeypatch.setenv(k, v)

    output = lambda_handler_user(VALID_TEST_REQUEST_USERNAME_VALIDATION_EMAIL_REMOTE_USERNAMES_USERADD, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), ''))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_basic_ca_private_key_file_zlib(monkeypatch):
    extra_environment_variables = {
        'bless_ca_default_password': '<INSERT_DEFAULT_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>',
        'bless_ca_ca_private_key_file': 'tests/aws_lambda/only-use-for-unit-tests.zlib',
        'bless_ca_ca_private_key_compression': 'zlib',
        'bless_options_username_validation': 'email',
        'bless_options_remote_usernames_validation': 'useradd',
    }

    for k, v in extra_environment_variables.items():
        monkeypatch.setenv(k, v)

    output = lambda_handler_user(VALID_TEST_REQUEST_USERNAME_VALIDATION_EMAIL_REMOTE_USERNAMES_USERADD, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), ''))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_basic_ca_private_key_env_zlib(monkeypatch):
    extra_environment_variables = {
        'bless_ca_default_password': '<INSERT_DEFAULT_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>',
        'bless_ca_ca_private_key': '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',
        'bless_ca_ca_private_key_compression': 'zlib',
        'bless_options_username_validation': 'email',
        'bless_options_remote_usernames_validation': 'useradd',
    }

    for k, v in extra_environment_variables.items():
        monkeypatch.setenv(k, v)

    output = lambda_handler_user(VALID_TEST_REQUEST_USERNAME_VALIDATION_EMAIL_REMOTE_USERNAMES_USERADD, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), ''))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_basic_ca_private_key_file_none_compression(monkeypatch):
    extra_environment_variables = {
        'bless_ca_default_password': '<INSERT_DEFAULT_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>',
        'bless_ca_ca_private_key_file': 'tests/aws_lambda/only-use-for-unit-tests.pem',
        'bless_ca_ca_private_key_compression': 'none',
        'bless_options_username_validation': 'email',
        'bless_options_remote_usernames_validation': 'useradd',
    }

    for k, v in extra_environment_variables.items():
        monkeypatch.setenv(k, v)

    output = lambda_handler_user(VALID_TEST_REQUEST_USERNAME_VALIDATION_EMAIL_REMOTE_USERNAMES_USERADD, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), ''))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_invalid_uncompressed_with_zlib(monkeypatch):
    extra_environment_variables = {
        'bless_ca_default_password': '<INSERT_DEFAULT_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>',
        'bless_ca_ca_private_key_file': 'tests/aws_lambda/only-use-for-unit-tests.pem',
        'bless_ca_ca_private_key_compression': 'zlib',
        'bless_options_username_validation': 'email',
        'bless_options_remote_usernames_validation': 'useradd',
    }

    for k, v in extra_environment_variables.items():
        monkeypatch.setenv(k, v)

    with pytest.raises(zlib.error):
        lambda_handler_user(VALID_TEST_REQUEST_USERNAME_VALIDATION_EMAIL_REMOTE_USERNAMES_USERADD, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), ''))


def test_invalid_uncompressed_with_bz2(monkeypatch):
    extra_environment_variables = {
        'bless_ca_default_password': '<INSERT_DEFAULT_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>',
        'bless_ca_ca_private_key_file': 'tests/aws_lambda/only-use-for-unit-tests.pem',
        'bless_ca_ca_private_key_compression': 'bz2',
        'bless_options_username_validation': 'email',
        'bless_options_remote_usernames_validation': 'useradd',
    }

    for k, v in extra_environment_variables.items():
        monkeypatch.setenv(k, v)

    with pytest.raises(OSError):
        lambda_handler_user(VALID_TEST_REQUEST_USERNAME_VALIDATION_EMAIL_REMOTE_USERNAMES_USERADD, context=Context,
                       ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                       entropy_check=False,
                       config_file=os.path.join(os.path.dirname(__file__), ''))


def test_invalid_username_request():
    output = lambda_handler_user(INVALID_TEST_REQUEST_USERNAME_INVALID, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test.cfg'))
    assert output['errorType'] == 'InputValidationError'


def test_invalid_kmsauth_request():
    output = lambda_handler_user(VALID_TEST_REQUEST_KMSAUTH, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-kmsauth.cfg'))
    assert output['errorType'] == 'KMSAuthValidationError'

def test_invalid_jwtauth_request():
    output = lambda_handler_user(INVALID_TEST_REQUEST_JWTAUTH, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-jwtauth.cfg'))
    assert output['errorType'] == 'InputValidationError'


def test_invalid_request():
    output = lambda_handler_user(INVALID_TEST_REQUEST, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), 'bless-test.cfg'))
    assert output['errorType'] == 'InputValidationError'


def test_local_request_key_not_found():
    with pytest.raises(IOError):
        lambda_handler_user(VALID_TEST_REQUEST, context=Context,
                       ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                       entropy_check=False,
                       config_file=os.path.join(os.path.dirname(__file__), 'bless-test-broken.cfg'))


def test_local_request_config_not_found():
    with pytest.raises(ValueError):
        lambda_handler_user(VALID_TEST_REQUEST, context=Context,
                       ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                       entropy_check=False,
                       config_file=os.path.join(os.path.dirname(__file__), 'none'))


def test_local_request_invalid_pub_key():
    output = lambda_handler_user(INVALID_TEST_REQUEST_KEY_TYPE, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), 'bless-test.cfg'))
    assert output['errorType'] == 'InputValidationError'


def test_local_request_extra_field():
    output = lambda_handler_user(INVALID_TEST_REQUEST_EXTRA_FIELD, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), 'bless-test.cfg'))
    assert output['errorType'] == 'InputValidationError'


def test_local_request_missing_field():
    output = lambda_handler_user(INVALID_TEST_REQUEST_MISSING_FIELD, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), 'bless-test.cfg'))
    assert output['errorType'] == 'InputValidationError'


def test_local_request_with_test_user():
    output = lambda_handler_user(VALID_TEST_REQUEST, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), 'bless-test-with-test-user.cfg'))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_local_request_with_custom_certificate_extensions():
    output = lambda_handler_user(VALID_TEST_REQUEST, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-with-certificate-extensions.cfg'))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_local_request_with_empty_certificate_extensions():
    output = lambda_handler_user(VALID_TEST_REQUEST, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-with-certificate-extensions-empty.cfg'))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_local_request_with_multiple_principals():
    output = lambda_handler_user(VALID_TEST_REQUEST_MULTIPLE_PRINCIPALS, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test.cfg'))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_invalid_request_with_multiple_principals():
    output = lambda_handler_user(INVALID_TEST_REQUEST_MULTIPLE_PRINCIPALS, context=Context,
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
    output = lambda_handler_user(INVALID_TEST_KMSAUTH_REQUEST_USERNAME_DOESNT_MATCH_REMOTE, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-kmsauth.cfg'))
    assert output['errorType'] == 'KMSAuthValidationError'


def test_invalid_request_with_unallowed_remote():
    output = lambda_handler_user(INVALID_TEST_KMSAUTH_REQUEST_DIFFERENT_REMOTE_USER, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-kmsauth-different-remote.cfg'))
    assert output['errorType'] == 'KMSAuthValidationError'


def test_valid_request_with_allowed_remote(mocker):
    mocker.patch("kmsauth.KMSTokenValidator.decrypt_token")
    output = lambda_handler_user(VALID_TEST_KMSAUTH_REQUEST_DIFFERENT_REMOTE_USER, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-kmsauth-different-remote.cfg'))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')


def test_valid_request_with_allowed_remote_and_allowed_iam_group(mocker):
    mocker.patch("kmsauth.KMSTokenValidator.decrypt_token")
    clientmock = mocker.MagicMock()
    clientmock.list_groups_for_user.return_value = {"Groups": [{"GroupName": "ssh-alloweduser"}]}
    botomock = mocker.patch('boto3.client')
    botomock.return_value = clientmock
    output = lambda_handler_user(VALID_TEST_KMSAUTH_REQUEST_DIFFERENT_REMOTE_USER, context=Context,
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
    output = lambda_handler_user(VALID_TEST_KMSAUTH_REQUEST_DIFFERENT_REMOTE_USER, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-kmsauth-iam-group-validation.cfg'))
    assert output['errorType'] == 'KMSAuthValidationError'


def test_basic_local_request_blacklisted(monkeypatch):
    extra_environment_variables = {
        'bless_options_remote_usernames_blacklist': 'root|balrog',
    }

    for k, v in extra_environment_variables.items():
        monkeypatch.setenv(k, v)

    output = lambda_handler_user(INVALID_TEST_REQUEST_BLACKLISTED_REMOTE_USERNAME, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__), 'bless-test.cfg'))
    assert output['errorType'] == 'InputValidationError'


def test_invalid_jwtauth_request_with_mismatched_bastion_and_remote():
    output = lambda_handler_user(INVALID_TEST_JWTAUTH_REQUEST_USERNAME_DOESNT_MATCH_REMOTE, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-jwtauth.cfg'))
    assert output['errorType'] == 'JWTAuthValidationError'

def test_valid_jwtauth_request():
    output = lambda_handler_user(VALID_TEST_REQUEST_JWTAUTH, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-jwtauth.cfg'))
    assert output['certificate'].startswith('ssh-rsa-cert-v01@openssh.com ')

def test_invalid_jwtauth_request_with_expired_jwtauth_token():
    output = lambda_handler_user(INVALID_TEST_JWTAUTH_REQUEST_EXPIRED_JWTAUTH_TOKEN, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-jwtauth.cfg'))
    assert output['errorType'] == 'JWTAuthValidationError'
    assert output['errorMessage'] == 'Signature has expired.'

def test_invalid_jwtauth_request_with_incorrect_issuer():
    output = lambda_handler_user(INVALID_TEST_JWTAUTH_REQUEST_INCORRECT_ISSUER, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-jwtauth.cfg'))
    assert output['errorType'] == 'JWTAuthValidationError'
    assert output['errorMessage'] == 'Invalid issuer'

def test_invalid_jwtauth_request_with_incorrect_audience():
    output = lambda_handler_user(INVALID_TEST_JWTAUTH_REQUEST_INCORRECT_AUDIENCE, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-jwtauth.cfg'))
    assert output['errorType'] == 'JWTAuthValidationError'
    assert output['errorMessage'] == 'Invalid audience'

def test_invalid_jwtauth_request_with_missing_username_claim():
    output = lambda_handler_user(INVALID_TEST_JWTAUTH_REQUEST_MISSING_USERNAME_CLAIM, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-jwtauth.cfg'))
    assert output['errorType'] == 'JWTAuthValidationError'
    assert output['errorMessage'] == 'missing username claim in jwt'

def test_invalid_jwtauth_request_with_username_claim_not_matching_remote_user():
    output = lambda_handler_user(INVALID_TEST_JWTAUTH_REQUEST_USERNAME_CLAIM_DOESNT_MATCH_REMOTE_USER, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-jwtauth.cfg'))
    assert output['errorType'] == 'JWTAuthValidationError'
    assert output['errorMessage'] == 'bastion_user must equal username claim in jwt'

def test_invalid_jwtauth_request_with_incorrect_signature_algorithm():
    output = lambda_handler_user(INVALID_TEST_JWTAUTH_REQUEST_INCORRECT_SIGNATURE_ALGORITHM, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-jwtauth.cfg'))
    assert output['errorType'] == 'JWTAuthValidationError'
    assert output['errorMessage'] == 'The specified alg value is not allowed'

def test_invalid_jwtauth_request_with_incorrect_signature():
    output = lambda_handler_user(INVALID_TEST_JWTAUTH_REQUEST_INCORRECT_SIGNATURE, context=Context,
                            ca_private_key_password=RSA_CA_PRIVATE_KEY_PASSWORD,
                            entropy_check=False,
                            config_file=os.path.join(os.path.dirname(__file__),
                                                     'bless-test-jwtauth.cfg'))
    assert output['errorType'] == 'JWTAuthValidationError'
    assert output['errorMessage'] == 'Signature verification failed.'