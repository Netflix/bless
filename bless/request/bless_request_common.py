"""
.. module: bless.request.bless_request_common
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from marshmallow import ValidationError

VALID_SSH_RSA_PUBLIC_KEY_HEADER = "ssh-rsa AAAAB3NzaC1yc2"
VALID_SSH_ED25519_PUBLIC_KEY_HEADER = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"


def validate_ssh_public_key(public_key):
    if public_key.startswith(VALID_SSH_RSA_PUBLIC_KEY_HEADER) or public_key.startswith(
            VALID_SSH_ED25519_PUBLIC_KEY_HEADER):
        pass
    # todo other key types
    else:
        raise ValidationError('Invalid SSH Public Key.')
