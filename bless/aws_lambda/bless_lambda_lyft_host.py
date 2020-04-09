"""
.. module: bless.aws_lambda.bless_lambda
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
import base64
import logging
import time

import boto3
import botocore
import os
import kmsauth
from bless.config.bless_config import BlessConfig, BLESS_OPTIONS_SECTION, \
    CERTIFICATE_VALIDITY_WINDOW_SEC_OPTION, ENTROPY_MINIMUM_BITS_OPTION, RANDOM_SEED_BYTES_OPTION, \
    BLESS_CA_SECTION, CA_PRIVATE_KEY_FILE_OPTION, LOGGING_LEVEL_OPTION, CERTIFICATE_TYPE_OPTION, \
    KMSAUTH_KEY_ID_OPTION, KMSAUTH_CONTEXT_OPTION, CROSS_ACCOUNT_ROLE_ARN_OPTION
from bless.request.bless_request import BlessUserSchema, BlessHostSchema
from bless.ssh.certificate_authorities.ssh_certificate_authority_factory import \
    get_ssh_certificate_authority
from bless.ssh.certificates.ssh_certificate_builder import SSHCertificateType
from bless.ssh.certificates.ssh_certificate_builder_factory import get_ssh_certificate_builder

logger = logging.getLogger()

REGIONS = {
    'iad': 'us-east-1',
    'sfo': 'us-west-1'
}


def get_role_name_from_request(request):
    if request.onebox_name:
        return 'onebox-production-iad'
    else:
        return '{}-{}-{}'.format(
            request.service_name,
            request.service_instance,
            request.service_region)


def get_role_name(instance_id, cross_account_role_arn, aws_region='us-east-1'):
    sts_client = boto3.client('sts')
    assumed_role_object = sts_client.assume_role(
        RoleArn=cross_account_role_arn,
        RoleSessionName='AssumedRoleSession'
    )
    credentials = assumed_role_object['Credentials']
    ec2_resource = boto3.resource(
        'ec2',
        region_name=aws_region,
        api_version='2016-11-15',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    instance = ec2_resource.Instance(instance_id)
    try:
        role = instance.iam_instance_profile['Arn'].split('/')[1]
    except botocore.exceptions.ClientError:
        logger.exception('Could not find instance {0}.'.format(instance_id))
        role = None
    except IndexError:
        logger.error(
            'Could not find the role associated with {0}.'.format(instance_id)
        )
        role = None
    except Exception:
        logger.exception(
            'Failed to lookup role for instance id {0}.'.format(instance_id)
        )
        role = None
    return role


def validate_instance_id(instance_id, request, cross_account_role_arn):
    aws_region = REGIONS.get(request.service_region, 'us-east-1')
    role = get_role_name(instance_id, cross_account_role_arn, aws_region)
    try:
        role_split = role.split('-')
        role_service_name = role_split[0]
        role_service_instance = role_split[1]
        role_service_region = role_split[2]
    except IndexError:
        logger.error(
            'Role is not a valid format {0}.'.format(role)
        )
        return False
    if (role_service_name in request.service_name and
            role_service_instance == request.service_instance and
            role_service_region == request.service_region):
        return True
    else:
        return False


def get_hostnames(service_name, service_instance, service_region, instance_id,
                  availability_zone, onebox_name, is_canary):
    cluster_name = '{0}-{1}-{2}'.format(
        service_name, service_instance, service_region)
    az_split = availability_zone.split('-')
    az_shortened = az_split[2][-1]  # last letter of 3rd block of az

    hostname_prefixes = []
    if instance_id:
        # strip 'i' in 'i-12345'
        instance_id_stripped = instance_id.split('-')[1]
        hostname_prefixes.append(instance_id)
        hostname_prefixes.append(instance_id_stripped)
    hostname_prefixes.append(cluster_name)
    hostname_prefixes.append(service_name)
    hostname_prefixes.append('{service_name}-{az_letter}'.format(
        service_name=service_name,
        az_letter=az_shortened))
    hostname_prefixes.append('{service_name}-{service_region}'.format(
        service_name=service_name,
        service_region=service_region))
    hostname_prefixes.append('{service_name}-{service_instance}'.format(
        service_name=service_name,
        service_instance=service_instance))
    if is_canary:
        hostname_prefixes.append('{service_name}-canary'.format(
            service_name=service_name))
        hostname_prefixes.append('{cluster_name}-canary'.format(
            cluster_name=cluster_name))
    if onebox_name:
        hostname_prefixes.append('{onebox_name}.onebox'.format(
            onebox_name=onebox_name))

    hostname_suffixes = ['.lyft.net', '.ln']
    if service_name == 'gateway':
        hostname_suffixes.append('lyft.com')
    hostnames = []
    for prefix in hostname_prefixes:
        for suffix in hostname_suffixes:
            hostnames.append('{prefix}{suffix}'.format(
                prefix=prefix, suffix=suffix))

    return hostnames


def get_certificate_type(certificate_type_option):
    if certificate_type_option == 'user':
        return 1
    elif certificate_type_option == 'host':
        return 2
    else:
        raise ValueError('Invalid certificate type option: {}'.format(certificate_type_option))


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
    :param certificate_type: Type of certificate to be generated
    :param config_file: The config file to load the SSH CA private key from, and additional settings
    :return: the SSH Certificate that can be written to id_rsa-cert.pub or similar file.
    """
    # AWS Region determines configs related to KMS
    region = os.environ['AWS_REGION']

    # Load the deployment config values
    config = BlessConfig(region,
                         config_file=config_file)

    certificate_type = get_certificate_type(config.get(BLESS_OPTIONS_SECTION, CERTIFICATE_TYPE_OPTION))
    logging_level = config.get(BLESS_OPTIONS_SECTION, LOGGING_LEVEL_OPTION)
    numeric_level = getattr(logging, logging_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: {}'.format(logging_level))

    logger.setLevel(numeric_level)

    certificate_validity_window_seconds = config.getint(BLESS_OPTIONS_SECTION,
                                                        CERTIFICATE_VALIDITY_WINDOW_SEC_OPTION)
    entropy_minimum_bits = config.getint(BLESS_OPTIONS_SECTION, ENTROPY_MINIMUM_BITS_OPTION)
    random_seed_bytes = config.getint(BLESS_OPTIONS_SECTION, RANDOM_SEED_BYTES_OPTION)
    cross_account_role_arn = config.get(BLESS_OPTIONS_SECTION, CROSS_ACCOUNT_ROLE_ARN_OPTION)
    ca_private_key_file = config.get(BLESS_CA_SECTION, CA_PRIVATE_KEY_FILE_OPTION)
    password_ciphertext_b64 = config.getpassword()
    kmsauth_key_id = config.get(BLESS_CA_SECTION, KMSAUTH_KEY_ID_OPTION)
    kmsauth_context = config.get(BLESS_CA_SECTION, KMSAUTH_CONTEXT_OPTION)

    # read the private key .pem
    with open(os.path.join(os.path.dirname(__file__), ca_private_key_file), 'r') as f:
        ca_private_key = f.read()

    # decrypt ca private key password
    if ca_private_key_password is None:
        kms_client = boto3.client('kms', region_name=region)
        ca_password = kms_client.decrypt(
            CiphertextBlob=base64.b64decode(password_ciphertext_b64))
        ca_private_key_password = ca_password['Plaintext']

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

    # Process cert request
    if certificate_type == SSHCertificateType.HOST:
        schema = BlessHostSchema(strict=True)
    else:
        schema = BlessUserSchema(strict=True)
    request = schema.load(event).data

    # cert values determined only by lambda and its configs
    current_time = int(time.time())
    valid_before = current_time + certificate_validity_window_seconds
    valid_after = current_time - certificate_validity_window_seconds

    # Authenticate the host with KMS, if key is setup
    if kmsauth_key_id:
        if request.kmsauth_token:
            validator = kmsauth.KMSTokenValidator(
                kmsauth_key_id,
                kmsauth_key_id,
                kmsauth_context,
                region
            )
            # decrypt_token will raise a TokenValidationError if token doesn't match
            role_name = get_role_name_from_request(request)
            validator.decrypt_token('2/service/{}'.format(role_name), request.kmsauth_token)
        else:
            raise ValueError('Invalid request, missing kmsauth token')

    # Build the cert
    ca = get_ssh_certificate_authority(ca_private_key, ca_private_key_password)
    cert_builder = get_ssh_certificate_builder(ca, certificate_type,
                                               request.public_key_to_sign)
    if certificate_type == SSHCertificateType.USER:
        cert_builder.add_valid_principal(request.remote_username)
        # cert_builder is needed to obtain the SSH public key's fingerprint
        key_id = 'request[{}] for[{}] from[{}] command[{}] ssh_key:[{}]  ca:[{}] valid_to[{}]'.format(
            context.aws_request_id, request.bastion_user, request.bastion_user_ip, request.command,
            cert_builder.ssh_public_key.fingerprint, context.invoked_function_arn,
            time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(valid_before)))
        cert_builder.set_critical_option_source_address(request.bastion_ip)
    elif certificate_type == SSHCertificateType.HOST:
        if not validate_instance_id(request.instance_id, request, cross_account_role_arn):
            request.instance_id = None
        remote_hostnames = get_hostnames(request.service_name,
                                         request.service_instance,
                                         request.service_region,
                                         request.instance_id,
                                         request.instance_availability_zone,
                                         request.onebox_name,
                                         request.is_canary)
        for remote_hostname in remote_hostnames:
            cert_builder.add_valid_principal(remote_hostname)
        key_id = 'request[{}] ssh_key:[{}]  ca:[{}] valid_to[{}]'.format(
            context.aws_request_id, cert_builder.ssh_public_key.fingerprint,
            context.invoked_function_arn, time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(valid_before)))
    else:
        raise ValueError("Unknown certificate type")

    cert_builder.set_valid_before(valid_before)
    cert_builder.set_valid_after(valid_after)

    cert_builder.set_key_id(key_id)
    cert = cert_builder.get_cert_file()

    if certificate_type == SSHCertificateType.HOST:
        remote_name = ', '.join(remote_hostnames)
        bastion_ip = None
    else:
        remote_name = request.remote_username
        bastion_ip = request.bastion_ip

    logger.info(
        'Issued a cert to bastion_ip[{}] for the remote_username of [{}] with the key_id[{}] and '
        'valid_from[{}])'.format(
            bastion_ip, remote_name, key_id,
            time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(valid_after))))
    return cert
