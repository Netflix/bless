"""
.. module: bless.aws_lambda.bless_lambda
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from bless.aws_lambda.bless_lambda_lyft_host import lambda_lyft_host_handler


def lambda_handler(*args, **kwargs):
    """
    Wrapper to redirect to Lyft version of bless_lambda_host
    """
    return lambda_lyft_host_handler(*args, **kwargs)
