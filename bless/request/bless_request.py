"""
.. module: bless.request.bless_request
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
import ipaddress
import re
from marshmallow import Schema, fields, post_load, ValidationError

# man 8 useradd
USERNAME_PATTERN = re.compile('[a-z_][a-z0-9_-]*[$]?\Z')
HOSTNAME_PATTERN = re.compile('[a-z0-9_.-]+')


def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ValidationError('Invalid IP address.')


def validate_user(user):
    if len(user) > 32:
        raise ValidationError('Username is too long')
    if USERNAME_PATTERN.match(user) is None:
        raise ValidationError('Username contains invalid characters')


def validate_host(hostname):
    if len(hostname) > 64:
        raise ValidationError('Hostname is too long')
    if HOSTNAME_PATTERN.match(hostname) is None:
        raise ValidationError('Hostname contains invalid characters')


class BlessSchema(Schema):
    public_key_to_sign = fields.Str()

    @post_load
    def make_bless_request(self, data):
        return BlessRequest(**data)


class BlessUserSchema(BlessSchema):
    bastion_ip = fields.Str(validate=validate_ip)
    bastion_user = fields.Str(validate=validate_user)
    bastion_user_ip = fields.Str(validate=validate_ip)
    command = fields.Str()
    remote_username = fields.Str(validate=validate_user)

    @post_load
    def make_bless_request(self, data):
        return BlessUserRequest(**data)


class BlessHostSchema(BlessSchema):
    remote_hostnames = fields.List(fields.Str())

    @post_load
    def make_bless_request(self, data):
        return BlessHostRequest(**data)


class BlessRequest:
    def __init__(self, public_key_to_sign):
        """
        A BlessRequest must have the following key value pairs to be valid.
        :param public_key_to_sign: The id_rsa.pub that will be used in the SSH request.  This is
        enforced in the issued certificate.
        """

        self.public_key_to_sign = public_key_to_sign

    def __eq__(self, other):
        return self.__dict__ == other.__dict__


class BlessUserRequest(BlessRequest):
    def __init__(self, bastion_ip, bastion_user, bastion_user_ip, command, public_key_to_sign,
                 remote_username):
        """
        A BlessRequest must have the following key value pairs to be valid.
        :param bastion_ip: The source IP where the SSH connection will be initiated from.  This is
        enforced in the issued certificate.
        :param bastion_user: The user on the bastion, who is initiating the SSH request.
        :param bastion_user_ip: The IP of the user accessing the bastion.
        :param command: Text information about the SSH request of the user.
        :param public_key_to_sign: The id_rsa.pub that will be used in the SSH request.  This is
        enforced in the issued certificate.
        :param remote_username: The username on the remote server that will be used in the SSH
        """

        self.bastion_ip = bastion_ip
        self.bastion_user = bastion_user
        self.bastion_user_ip = bastion_user_ip
        self.command = command
        self.public_key_to_sign = public_key_to_sign
        self.remote_username = remote_username


class BlessHostRequest(BlessRequest):
    def __init__(self, public_key_to_sign, remote_hostnames):
        """
        A BlessRequest must have the following key value pairs to be valid.
        :param bastion_ip: The source IP where the SSH connection will be initiated from.  This is
        enforced in the issued certificate.
        :param public_key_to_sign: The id_rsa.pub that will be used in the SSH request.  This is
        enforced in the issued certificate.
        :param remote_hostnames: A list of hostnames on the server for which the certificate is valid
        request. This is enforced in the issued certificate.
        """

        self.public_key_to_sign = public_key_to_sign
        self.remote_hostnames = remote_hostnames
