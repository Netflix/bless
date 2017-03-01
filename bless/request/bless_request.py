"""
.. module: bless.request.bless_request
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
import re

import ipaddress
from marshmallow import Schema, fields, post_load, ValidationError, validates_schema

# man 8 useradd
USERNAME_PATTERN = re.compile('[a-z_][a-z0-9_-]*[$]?\Z')
VALID_SSH_RSA_PUBLIC_KEY_HEADER = "ssh-rsa AAAAB3NzaC1yc2"


def validate_ips(ips):
    try:
        for ip in ips.split(','):
            ipaddress.ip_network(ip, strict=True)
    except ValueError:
        raise ValidationError('Invalid IP address.')


def validate_user(user):
    if len(user) > 32:
        raise ValidationError('Username is too long')
    if USERNAME_PATTERN.match(user) is None:
        raise ValidationError('Username contains invalid characters')


def validate_ssh_public_key(public_key):
    if public_key.startswith(VALID_SSH_RSA_PUBLIC_KEY_HEADER):
        pass
    # todo other key types
    else:
        raise ValidationError('Invalid SSH Public Key.')


class BlessSchema(Schema):
    bastion_ips = fields.Str(validate=validate_ips, required=True)
    bastion_user = fields.Str(validate=validate_user, required=True)
    bastion_user_ip = fields.Str(validate=validate_ips, required=True)
    command = fields.Str(required=True)
    public_key_to_sign = fields.Str(validate=validate_ssh_public_key, required=True)
    remote_username = fields.Str(validate=validate_user, required=True)
    kmsauth_token = fields.Str(required=False)

    @validates_schema(pass_original=True)
    def check_unknown_fields(self, data, original_data):
        unknown = set(original_data) - set(self.fields)
        if unknown:
            raise ValidationError('Unknown field', unknown)

    @post_load
    def make_bless_request(self, data):
        return BlessRequest(**data)


class BlessRequest:
    def __init__(self, bastion_ips, bastion_user, bastion_user_ip, command, public_key_to_sign,
                 remote_username, kmsauth_token=None):
        """
        A BlessRequest must have the following key value pairs to be valid.
        :param bastion_ips: The source IPs where the SSH connection will be initiated from.  This is
        enforced in the issued certificate.
        :param bastion_user: The user on the bastion, who is initiating the SSH request.
        :param bastion_user_ip: The IP of the user accessing the bastion.
        :param command: Text information about the SSH request of the user.
        :param public_key_to_sign: The id_rsa.pub that will be used in the SSH request.  This is
        enforced in the issued certificate.
        :param remote_username: The username on the remote server that will be used in the SSH
        request.  This is enforced in the issued certificate.
        :param kmsauth_token: An optional kms auth token to authenticate the user
        """
        self.bastion_ips = bastion_ips
        self.bastion_user = bastion_user
        self.bastion_user_ip = bastion_user_ip
        self.command = command
        self.public_key_to_sign = public_key_to_sign
        self.remote_username = remote_username
        self.kmsauth_token = kmsauth_token

    def __eq__(self, other):
        return self.__dict__ == other.__dict__
