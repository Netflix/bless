"""
.. module: bless.request.bless_request_user
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
import re
from enum import Enum

import ipaddress
from bless.config.bless_config import USERNAME_VALIDATION_OPTION, REMOTE_USERNAMES_VALIDATION_OPTION, \
    USERNAME_VALIDATION_DEFAULT, REMOTE_USERNAMES_VALIDATION_DEFAULT, REMOTE_USERNAMES_BLACKLIST_OPTION, \
    REMOTE_USERNAMES_BLACKLIST_DEFAULT
from bless.request.bless_request_common import validate_ssh_public_key
from marshmallow import Schema, fields, post_load, ValidationError, validates_schema
from marshmallow import validates
from marshmallow.validate import Email

# man 8 useradd
USERNAME_PATTERN = re.compile(r'[a-z_][a-z0-9_-]*[$]?\Z')

# debian
# On Debian, the only constraints are that usernames must neither start
# with a dash ('-') nor plus ('+') nor tilde ('~') nor contain a colon
# (':'), a comma (','), or a whitespace (space: ' ', end of line: '\n',
# tabulation: '\t', etc.). Note that using a slash ('/') may break the
# default algorithm for the definition of the user's home directory.
USERNAME_PATTERN_DEBIAN = re.compile(r'\A[^-+~][^:,\s]*\Z')

# It appears that most printable ascii is valid, excluding whitespace, #, and commas.
# There doesn't seem to be any practical size limits of an SSH Certificate Principal (> 4096B allowed).
PRINCIPAL_PATTERN = re.compile(r'[\d\w!"$%&\'()*+\-./:;<=>?@\[\\\]\^`{|}~]+\Z')

USERNAME_VALIDATION_OPTIONS = Enum('UserNameValidationOptions',
                                   'useradd '  # Allowable usernames per 'man 8 useradd'
                                   'debian '  # Allowable usernames on debian systems.
                                   'email '  # username is a valid email address.
                                   'principal '  # SSH Certificate Principal.  See 'man 5 sshd_config'.
                                   'disabled')  # no additional validation of the string.


def validate_ips(ips):
    try:
        for ip in ips.split(','):
            ipaddress.ip_network(ip, strict=True)
    except ValueError:
        raise ValidationError('Invalid IP address.')


def validate_user(user, username_validation, username_blacklist=None):
    if username_blacklist:
        if re.match(username_blacklist, user) is not None:
            raise ValidationError('Username contains invalid characters.')

    if username_validation == USERNAME_VALIDATION_OPTIONS.disabled:
        return
    elif username_validation == USERNAME_VALIDATION_OPTIONS.email:
        Email('Invalid email address.').__call__(user)
    elif username_validation == USERNAME_VALIDATION_OPTIONS.principal:
        _validate_principal(user)
    elif len(user) > 32:
        raise ValidationError('Username is too long.')
    elif username_validation == USERNAME_VALIDATION_OPTIONS.useradd:
        _validate_user_useradd(user)
    elif username_validation == USERNAME_VALIDATION_OPTIONS.debian:
        _validate_user_debian(user)
    else:
        raise ValidationError('Invalid username validator.')


def _validate_user_useradd(user):
    if USERNAME_PATTERN.match(user) is None:
        raise ValidationError('Username contains invalid characters.')


def _validate_user_debian(user):
    if USERNAME_PATTERN_DEBIAN.match(user) is None:
        raise ValidationError('Username contains invalid characters.')


def _validate_principal(principal):
    if PRINCIPAL_PATTERN.match(principal) is None:
        raise ValidationError('Principal contains invalid characters.')


class BlessUserSchema(Schema):
    bastion_ips = fields.Str(validate=validate_ips, required=True)
    bastion_user = fields.Str(required=True)
    bastion_user_ip = fields.Str(validate=validate_ips, required=True)
    command = fields.Str(required=True)
    public_key_to_sign = fields.Str(validate=validate_ssh_public_key, required=True)
    remote_usernames = fields.Str(required=True)
    kmsauth_token = fields.Str(required=False)

    @validates_schema(pass_original=True)
    def check_unknown_fields(self, data, original_data):
        unknown = set(original_data) - set(self.fields)
        if unknown:
            raise ValidationError('Unknown field', unknown)

    @post_load
    def make_bless_request(self, data):
        return BlessUserRequest(**data)

    @validates('bastion_user')
    def validate_bastion_user(self, user):
        if USERNAME_VALIDATION_OPTION in self.context:
            username_validation = USERNAME_VALIDATION_OPTIONS[self.context[USERNAME_VALIDATION_OPTION]]
        else:
            username_validation = USERNAME_VALIDATION_OPTIONS[USERNAME_VALIDATION_DEFAULT]
        validate_user(user, username_validation)

    @validates('remote_usernames')
    def validate_remote_usernames(self, remote_usernames):
        if REMOTE_USERNAMES_VALIDATION_OPTION in self.context:
            username_validation = USERNAME_VALIDATION_OPTIONS[self.context[REMOTE_USERNAMES_VALIDATION_OPTION]]
        else:
            username_validation = USERNAME_VALIDATION_OPTIONS[REMOTE_USERNAMES_VALIDATION_DEFAULT]
        if REMOTE_USERNAMES_BLACKLIST_OPTION in self.context:
            username_blacklist = self.context[REMOTE_USERNAMES_BLACKLIST_OPTION]
        else:
            username_blacklist = REMOTE_USERNAMES_BLACKLIST_DEFAULT
        for remote_username in remote_usernames.split(','):
            validate_user(remote_username, username_validation, username_blacklist)


class BlessUserRequest:
    def __init__(self, bastion_ips, bastion_user, bastion_user_ip, command, public_key_to_sign,
                 remote_usernames, kmsauth_token=None):
        """
        A BlessRequest must have the following key value pairs to be valid.
        :param bastion_ips: The source IPs where the SSH connection will be initiated from.  This is
        enforced in the issued certificate.
        :param bastion_user: The user on the bastion, who is initiating the SSH request.
        :param bastion_user_ip: The IP of the user accessing the bastion.
        :param command: Text information about the SSH request of the user.
        :param public_key_to_sign: The id_XXX.pub that will be used in the SSH request.  This is
        enforced in the issued certificate.
        :param remote_usernames: Comma-separated list of username(s) or authorized principals on the remote
        server that will be used in the SSH request.  This is enforced in the issued certificate.
        :param kmsauth_token: An optional kms auth token to authenticate the user.
        """
        self.bastion_ips = bastion_ips
        self.bastion_user = bastion_user
        self.bastion_user_ip = bastion_user_ip
        self.command = command
        self.public_key_to_sign = public_key_to_sign
        self.remote_usernames = remote_usernames
        self.kmsauth_token = kmsauth_token

    def __eq__(self, other):
        return self.__dict__ == other.__dict__
