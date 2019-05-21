"""
.. module: bless.aws_lambda.bless_lambda_user
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
import time

import boto3
from bless.aws_lambda.bless_lambda_common import success_response, error_response, set_logger, check_entropy, \
    setup_lambda_cache
from bless.config.bless_config import BLESS_OPTIONS_SECTION, \
    CERTIFICATE_VALIDITY_BEFORE_SEC_OPTION, \
    CERTIFICATE_VALIDITY_AFTER_SEC_OPTION, \
    USERNAME_VALIDATION_OPTION, \
    KMSAUTH_SECTION, \
    KMSAUTH_USEKMSAUTH_OPTION, \
    KMSAUTH_REMOTE_USERNAMES_ALLOWED_OPTION, \
    VALIDATE_REMOTE_USERNAMES_AGAINST_IAM_GROUPS_OPTION, \
    KMSAUTH_SERVICE_ID_OPTION, \
    TEST_USER_OPTION, \
    CERTIFICATE_EXTENSIONS_OPTION, \
    REMOTE_USERNAMES_VALIDATION_OPTION, \
    IAM_GROUP_NAME_VALIDATION_FORMAT_OPTION, \
    REMOTE_USERNAMES_BLACKLIST_OPTION
from bless.request.bless_request_user import BlessUserSchema
from bless.ssh.certificate_authorities.ssh_certificate_authority_factory import \
    get_ssh_certificate_authority
from bless.ssh.certificates.ssh_certificate_builder import SSHCertificateType
from bless.ssh.certificates.ssh_certificate_builder_factory import get_ssh_certificate_builder
from kmsauth import KMSTokenValidator, TokenValidationError
from marshmallow.exceptions import ValidationError


def lambda_handler_user(
        event, context=None, ca_private_key_password=None,
        entropy_check=True,
        config_file=None):
    """
    This is the function that will be called when the lambda function starts.
    :param event: Dictionary of the json request.
    :param context: AWS LambdaContext Object
    http://docs.aws.amazon.com/lambda/latest/dg/python-context-object.html
    :param ca_private_key_password: For local testing, if the password is provided, skip the KMS
    decrypt.
    :param entropy_check: For local testing, if set to false, it will skip checking entropy and
    won't try to fetch additional random from KMS.
    :param config_file: The config file to load the SSH CA private key from, and additional settings.
    :return: the SSH Certificate that can be written to id_rsa-cert.pub or similar file.
    """
    bless_cache = setup_lambda_cache(ca_private_key_password, config_file)

    # AWS Region determines configs related to KMS
    region = bless_cache.region

    # Load the deployment config values
    config = bless_cache.config

    logger = set_logger(config)

    certificate_validity_before_seconds = config.getint(BLESS_OPTIONS_SECTION,
                                                        CERTIFICATE_VALIDITY_BEFORE_SEC_OPTION)
    certificate_validity_after_seconds = config.getint(BLESS_OPTIONS_SECTION,
                                                       CERTIFICATE_VALIDITY_AFTER_SEC_OPTION)
    ca_private_key = config.getprivatekey()
    certificate_extensions = config.get(BLESS_OPTIONS_SECTION, CERTIFICATE_EXTENSIONS_OPTION)

    # Process cert request
    schema = BlessUserSchema(strict=True)
    schema.context[USERNAME_VALIDATION_OPTION] = config.get(BLESS_OPTIONS_SECTION, USERNAME_VALIDATION_OPTION)
    schema.context[REMOTE_USERNAMES_VALIDATION_OPTION] = config.get(BLESS_OPTIONS_SECTION,
                                                                    REMOTE_USERNAMES_VALIDATION_OPTION)
    schema.context[REMOTE_USERNAMES_BLACKLIST_OPTION] = config.get(BLESS_OPTIONS_SECTION,
                                                                   REMOTE_USERNAMES_BLACKLIST_OPTION)

    try:
        request = schema.load(event).data
    except ValidationError as e:
        return error_response('InputValidationError', str(e))

    logger.info('Bless lambda invoked by [user: {0}, bastion_ips:{1}, public_key: {2}, kmsauth_token:{3}]'.format(
        request.bastion_user,
        request.bastion_user_ip,
        request.public_key_to_sign,
        request.kmsauth_token))

    # Make sure we have the ca private key password
    if bless_cache.ca_private_key_password is None:
        return error_response('ClientError', bless_cache.ca_private_key_password_error)
    else:
        ca_private_key_password = bless_cache.ca_private_key_password

    # if running as a Lambda, we can check the entropy pool and seed it with KMS if desired
    if entropy_check:
        check_entropy(config, logger)

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
    if config.getboolean(KMSAUTH_SECTION, KMSAUTH_USEKMSAUTH_OPTION):
        if request.kmsauth_token:
            # Allow bless to sign the cert for a different remote user than the name of the user who signed it
            allowed_remotes = config.get(KMSAUTH_SECTION, KMSAUTH_REMOTE_USERNAMES_ALLOWED_OPTION)
            if allowed_remotes:
                allowed_users = allowed_remotes.split(',')
                requested_remotes = request.remote_usernames.split(',')
                if allowed_users != ['*'] and not all([u in allowed_users for u in requested_remotes]):
                    return error_response('KMSAuthValidationError',
                                          'unallowed remote_usernames [{}]'.format(request.remote_usernames))

                # Check if the user is in the required IAM groups
                if config.getboolean(KMSAUTH_SECTION, VALIDATE_REMOTE_USERNAMES_AGAINST_IAM_GROUPS_OPTION):
                    iam = boto3.client('iam')
                    user_groups = iam.list_groups_for_user(UserName=request.bastion_user)

                    group_name_template = config.get(KMSAUTH_SECTION, IAM_GROUP_NAME_VALIDATION_FORMAT_OPTION)
                    for requested_remote in requested_remotes:
                        required_group_name = group_name_template.format(requested_remote)

                        user_is_in_group = any(
                            group
                            for group in user_groups['Groups']
                            if group['GroupName'] == required_group_name
                        )

                        if not user_is_in_group:
                            return error_response('KMSAuthValidationError',
                                                  'user {} is not in the {} iam group'.format(request.bastion_user,
                                                                                              required_group_name))

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
