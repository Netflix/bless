"""
.. module: bless.aws_lambda.bless_lambda
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from bless.aws_lambda.bless_lambda_user import lambda_handler_user


def lambda_handler(*args, **kwargs):
    """
    Wrapper around lambda_handler_user for backwards compatibility
    """
    return lambda_handler_user(*args, **kwargs)
