"""
.. module: bless.aws_lambda.bless_lambda
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
import base64
import logging
import os
import time

import boto3
from botocore.exceptions import ClientError
from kmsauth import KMSTokenValidator, TokenValidationError
from marshmallow.exceptions import ValidationError

from bless.config.bless_config import BlessConfig, \
    BLESS_OPTIONS_SECTION, \
    CERTIFICATE_VALIDITY_BEFORE_SEC_OPTION, \
    CERTIFICATE_VALIDITY_AFTER_SEC_OPTION, \
    ENTROPY_MINIMUM_BITS_OPTION, \
    RANDOM_SEED_BYTES_OPTION, \
    LOGGING_LEVEL_OPTION, \
    USERNAME_VALIDATION_OPTION, \
    KMSAUTH_SECTION, \
    KMSAUTH_USEKMSAUTH_OPTION, \
    KMSAUTH_REMOTE_USERNAMES_ALLOWED_OPTION, \
    KMSAUTH_SERVICE_ID_OPTION, \
    TEST_USER_OPTION, \
    CERTIFICATE_EXTENSIONS_OPTION, \
    REMOTE_USERNAMES_VALIDATION_OPTION
from bless.request.bless_request import BlessSchema
from bless.ssh.certificate_authorities.ssh_certificate_authority_factory import \
    get_ssh_certificate_authority
from bless.ssh.certificates.ssh_certificate_builder import SSHCertificateType
from bless.ssh.certificates.ssh_certificate_builder_factory import get_ssh_certificate_builder


def lambda_handler(event, context=None, ca_private_key_password=None,
                   entropy_check=True,
                   config_file=os.path.join(os.path.dirname(__file__), 'bless_deploy.cfg')):
    """
    This is the function that will be called when the lambda function starts.
    :param event: Dictionary of the json request.
    :param context: AWS LambdaContext Object
    http://docs.aws.amazon.com/lambda/latest/dg/python-context-object.html
    :param ca_private_key_password: For local testing, if the password is provided, skip the KMS
    decrypt.
    :param entropy_check: For local testing, if set to false, it will skip checking entropy and
    won't try to fetch additional random from KMS
    :param config_file: The config file to load the SSH CA private key from, and additional settings
    :return: the SSH Certificate that can be written to id_rsa-cert.pub or similar file.
    """
    # AWS Region determines configs related to KMS
    region = os.environ['AWS_REGION']

    # Load the deployment config values
    config = BlessConfig(region,
                         config_file=config_file)

    logging_level = config.get(BLESS_OPTIONS_SECTION, LOGGING_LEVEL_OPTION)
    numeric_level = getattr(logging, logging_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: {}'.format(logging_level))

    logger = logging.getLogger()
    logger.setLevel(numeric_level)

    certificate_validity_before_seconds = config.getint(BLESS_OPTIONS_SECTION,
                                                        CERTIFICATE_VALIDITY_BEFORE_SEC_OPTION)
    certificate_validity_after_seconds = config.getint(BLESS_OPTIONS_SECTION,
                                                       CERTIFICATE_VALIDITY_AFTER_SEC_OPTION)
    entropy_minimum_bits = config.getint(BLESS_OPTIONS_SECTION, ENTROPY_MINIMUM_BITS_OPTION)
    random_seed_bytes = config.getint(BLESS_OPTIONS_SECTION, RANDOM_SEED_BYTES_OPTION)
    ca_private_key = config.getprivatekey()
    password_ciphertext_b64 = config.getpassword()
    certificate_extensions = config.get(BLESS_OPTIONS_SECTION, CERTIFICATE_EXTENSIONS_OPTION)

    # Process cert request
    schema = BlessSchema(strict=True)
    schema.context[USERNAME_VALIDATION_OPTION] = config.get(BLESS_OPTIONS_SECTION, USERNAME_VALIDATION_OPTION)
    schema.context[REMOTE_USERNAMES_VALIDATION_OPTION] = config.get(BLESS_OPTIONS_SECTION,
                                                                    REMOTE_USERNAMES_VALIDATION_OPTION)

    try:
        request = schema.load(event).data
    except ValidationError as e:
        return error_response('InputValidationError', str(e))

    logger.info('Bless lambda invoked by [user: {0}, bastion_ips:{1}, public_key: {2}, kmsauth_token:{3}]'.format(
        request.bastion_user,
        request.bastion_user_ip,
        request.public_key_to_sign,
        request.kmsauth_token))

    # decrypt ca private key password
    if ca_private_key_password is None:
        kms_client = boto3.client('kms', region_name=region)
        try:
            ca_password = kms_client.decrypt(
                CiphertextBlob=base64.b64decode(password_ciphertext_b64))
            ca_private_key_password = ca_password['Plaintext']
        except ClientError as e:
            return error_response('ClientError', str(e))

    # if running as a Lambda, we can check the entropy pool and seed it with KMS if desired
    if entropy_check:
        with open('/proc/sys/kernel/random/entropy_avail', 'r') as f:
            entropy = int(f.read())
            logger.debug(entropy)
            if entropy < entropy_minimum_bits:
                logger.info(
                    'System entropy was {}, which is lower than the entropy_'
                    'minimum {}.  Using KMS to seed /dev/urandom'.format(
                        entropy, entropy_minimum_bits))
                response = kms_client.generate_random(
                    NumberOfBytes=random_seed_bytes)
                random_seed = response['Plaintext']
                with open('/dev/urandom', 'w') as urandom:
                    urandom.write(random_seed)

    # cert values determined only by lambda and its configs
    current_time = int(time.time())
    test_user = config.get(BLESS_OPTIONS_SECTION, TEST_USER_OPTION)
    if test_user and (request.bastion_user == test_user or request.remote_usernames == test_user):
        # This is a test call, the lambda will issue an invalid
        # certificate where valid_before < valid_after
        valid_before = current_time
        valid_after = current_time + 1
        bypass_time_validity_check = True
    else:
        valid_before = current_time + certificate_validity_after_seconds
        valid_after = current_time - certificate_validity_before_seconds
        bypass_time_validity_check = False

    # Authenticate the user with KMS, if key is setup
    if config.get(KMSAUTH_SECTION, KMSAUTH_USEKMSAUTH_OPTION):
        if request.kmsauth_token:
            # Allow bless to sign the cert for a different remote user than the name of the user who signed it
            if KMSAUTH_REMOTE_USERNAMES_ALLOWED_OPTION:
                allowed_users = KMSAUTH_REMOTE_USERNAMES_ALLOWED_OPTION.split(",")
                if allowed_users != '*' and request.remote_usernames not in allowed_users:
                    return error_response('KMSAuthValidationError',
                                          'invalid remote_usernames [{}]'.format(request.remote_usernames))
            elif request.remote_usernames != request.bastion_user:
                    return error_response('KMSAuthValidationError',
                                          'remote_usernames must be the same as bastion_user')
            try:
                validator = KMSTokenValidator(
                    None,
                    config.getkmsauthkeyids(),
                    config.get(KMSAUTH_SECTION, KMSAUTH_SERVICE_ID_OPTION),
                    region
                )
                # decrypt_token will raise a TokenValidationError if token doesn't match
                validator.decrypt_token(
                    "2/user/{}".format(request.bastion_user),
                    request.kmsauth_token
                )
            except TokenValidationError as e:
                return error_response('KMSAuthValidationError', str(e))
        else:
            return error_response('InputValidationError', 'Invalid request, missing kmsauth token')

    # Build the cert
    ca = get_ssh_certificate_authority(ca_private_key, ca_private_key_password)
    cert_builder = get_ssh_certificate_builder(ca, SSHCertificateType.USER,
                                               request.public_key_to_sign)
    for username in request.remote_usernames.split(','):
        cert_builder.add_valid_principal(username)

    cert_builder.set_valid_before(valid_before)
    cert_builder.set_valid_after(valid_after)

    if certificate_extensions:
        for e in certificate_extensions.split(','):
            if e:
                cert_builder.add_extension(e)
    else:
        cert_builder.clear_extensions()

    # cert_builder is needed to obtain the SSH public key's fingerprint
    key_id = 'request[{}] for[{}] from[{}] command[{}] ssh_key[{}]  ca[{}] valid_to[{}]'.format(
        context.aws_request_id, request.bastion_user, request.bastion_user_ip, request.command,
        cert_builder.ssh_public_key.fingerprint, context.invoked_function_arn,
        time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(valid_before)))
    cert_builder.set_critical_option_source_addresses(request.bastion_ips)
    cert_builder.set_key_id(key_id)
    cert = cert_builder.get_cert_file(bypass_time_validity_check)

    logger.info(
        'Issued a cert to bastion_ips[{}] for remote_usernames[{}] with key_id[{}] and '
        'valid_from[{}])'.format(
            request.bastion_ips, request.remote_usernames, key_id,
            time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(valid_after))))
    return success_response(cert)


def success_response(cert):
    return {
        'certificate': cert
    }


def error_response(error_type, error_message):
    return {
        'errorType': error_type,
        'errorMessage': error_message
    }
