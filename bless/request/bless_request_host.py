"""
.. module: bless.request.bless_request_host
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from enum import Enum

from bless.config.bless_config import HOSTNAME_VALIDATION_OPTION, HOSTNAME_VALIDATION_DEFAULT
from bless.request.bless_request_common import validate_ssh_public_key
from marshmallow import Schema, fields, validates_schema, ValidationError, post_load, validates
from marshmallow.validate import URL

HOSTNAME_VALIDATION_OPTIONS = Enum('HostNameValidationOptions',
                                   'url '  # Valid url format
                                   'disabled'  # no validation
                                   )


def validate_hostname(hostname, hostname_validation):
    if hostname_validation == HOSTNAME_VALIDATION_OPTIONS.disabled:
        return
    else:
        validator = URL(require_tld=False, schemes='ssh', error='Invalid hostname "{input}".')
        validator('ssh://{}'.format(hostname))


class BlessHostSchema(Schema):
    hostnames = fields.Str(required=True)
    public_key_to_sign = fields.Str(validate=validate_ssh_public_key, required=True)

    @validates_schema(pass_original=True)
    def check_unknown_fields(self, data, original_data):
        unknown = set(original_data) - set(self.fields)
        if unknown:
            raise ValidationError('Unknown field', unknown)

    @post_load
    def make_bless_request(self, data):
        return BlessHostRequest(**data)

    @validates('hostnames')
    def validate_hostnames(self, hostnames):
        if HOSTNAME_VALIDATION_OPTION in self.context:
            hostname_validation = HOSTNAME_VALIDATION_OPTIONS[self.context[HOSTNAME_VALIDATION_OPTION]]
        else:
            hostname_validation = HOSTNAME_VALIDATION_OPTIONS[HOSTNAME_VALIDATION_DEFAULT]
        for hostname in hostnames.split(','):
            validate_hostname(hostname, hostname_validation)


class BlessHostRequest:
    def __init__(self, hostnames, public_key_to_sign):
        """
        A BlessRequest must have the following key value pairs to be valid.
        :param hostnames: Comma-separated list of hostname(s) to include in this host certificate.
        :param public_key_to_sign: The id_XXX.pub that will be used in the SSH request. This is enforced in the issued certificate.
        """
        self.hostnames = hostnames
        self.public_key_to_sign = public_key_to_sign

    def __eq__(self, other):
        return self.__dict__ == other.__dict__
