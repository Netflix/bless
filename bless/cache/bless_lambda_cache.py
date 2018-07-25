import base64
import os

import boto3
from bless.config.bless_config import BlessConfig
from botocore.exceptions import ClientError


class BlessLambdaCache:
    region = None
    config = None
    ca_private_key_password = None
    ca_private_key_password_error = None

    def __init__(self, ca_private_key_password=None,
                 config_file=None):
        """

        :param ca_private_key_password: For local testing, if the password is provided, skip the KMS
        decrypt.
        :param config_file: The config file to load the SSH CA private key from, and additional settings.
        """
        # AWS Region determines configs related to KMS
        if 'AWS_REGION' in os.environ:
            self.region = os.environ['AWS_REGION']
        else:
            self.region = 'us-west-2'

            # Load the deployment config values
        self.config = BlessConfig(self.region, config_file=config_file)

        password_ciphertext_b64 = self.config.getpassword()

        # decrypt ca private key password
        if ca_private_key_password is None:
            kms_client = boto3.client('kms', region_name=self.region)
            try:
                ca_password = kms_client.decrypt(
                    CiphertextBlob=base64.b64decode(password_ciphertext_b64))
                self.ca_private_key_password = ca_password['Plaintext']
            except ClientError as e:
                self.ca_private_key_password_error = str(e)
        else:
            self.ca_private_key_password = ca_private_key_password
