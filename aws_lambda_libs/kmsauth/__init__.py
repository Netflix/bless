import logging
import hashlib
import json
import datetime
import base64
import os
import sys

import kmsauth.services
from kmsauth.utils import lru

TOKEN_SKEW = 3
TIME_FORMAT = "%Y%m%dT%H%M%SZ"
PY2 = sys.version[0] == '2'


class KMSTokenValidator(object):

    """A class that represents a token validator for KMS auth."""

    def __init__(
            self,
            auth_key,
            user_auth_key,
            to_auth_context,
            region,
            scoped_auth_keys=None,
            minimum_token_version=1,
            maximum_token_version=2,
            auth_token_max_lifetime=60,
            aws_creds=None
            ):
        """Create a KMSTokenValidator object.

        Args:
            auth_key: The KMS key ARN or alias to use for service
                authentication. Required.
            user_auth_key: The KMS key ARN or alias to use for user
                authentication. Required.
            to_auth_context: The KMS encryption context to use for the to
                context for authentication. Required.
            region: AWS region to connect to. Required.
            token_version: The version of the authentication token. Default: 2
            token_cache_file: he location to use for caching the auth token.
                If set to empty string, no cache will be used. Default: None
            token_lifetime: Lifetime of the authentication token generated.
                Default: 10
            aws_creds: A dict of AccessKeyId, SecretAccessKey, SessionToken.
                Useful if you wish to pass in assumed role credentials or MFA
                credentials. Default: None
        """
        self.auth_key = auth_key
        self.user_auth_key = user_auth_key
        self.to_auth_context = to_auth_context
        self.region = region
        if scoped_auth_keys is None:
            self.scoped_auth_keys = {}
        else:
            self.scoped_auth_keys = scoped_auth_keys
        self.minimum_token_version = minimum_token_version
        self.maximum_token_version = maximum_token_version
        self.auth_token_max_lifetime = auth_token_max_lifetime
        self.aws_creds = aws_creds
        if aws_creds:
            self.kms_client = kmsauth.services.get_boto_client(
                'kms',
                region=self.region,
                aws_access_key_id=self.aws_creds['AccessKeyId'],
                aws_secret_access_key=self.aws_creds['SecretAccessKey'],
                aws_session_token=self.aws_creds['SessionToken']
            )
        else:
            self.kms_client = kmsauth.services.get_boto_client(
                'kms',
                region=self.region
            )
        self.TOKENS = lru.LRUCache(4096)
        self.KEY_METADATA = {}
        self._validate_generator()

    def _validate_generator(self):
        if self.minimum_token_version < 1 or self.minimum_token_version > 2:
            raise ConfigurationError(
                'Invalid minimum_token_version provided.'
            )
        if self.maximum_token_version < 1 or self.maximum_token_version > 2:
            raise ConfigurationError(
                'Invalid maximum_token_version provided.'
            )
        if self.minimum_token_version > self.maximum_token_version:
            raise ConfigurationError(
                'minimum_token_version can not be greater than'
                ' self.minimum_token_version'
            )

    def _get_key_arn(self, key):
        if key not in self.KEY_METADATA:
            self.KEY_METADATA[key] = self.kms_client.describe_key(
                KeyId='{0}'.format(key)
            )
        return self.KEY_METADATA[key]['KeyMetadata']['Arn']

    def _get_key_alias_from_cache(self, key_arn):
        '''
        Find a key's alias by looking up its key_arn in the KEY_METADATA
        cache. This function will only work after a key has been lookedup by
        its alias and is meant as a convenience function for turning an ARN
        that's already been looked up back into its alias.
        '''
        for alias in self.KEY_METADATA:
            if self.KEY_METADATA[alias]['KeyMetadata']['Arn'] == key_arn:
                return alias
        return None

    def _valid_service_auth_key(self, key_arn):
        if self.auth_key is None:
            return False
        if key_arn == self._get_key_arn(self.auth_key):
            return True
        for key in self.scoped_auth_keys:
            if key_arn == self._get_key_arn(key):
                return True
        return False

    def _valid_user_auth_key(self, key_arn):
        if self.user_auth_key is None:
            return False
        if key_arn == self._get_key_arn(self.user_auth_key):
            return True
        return False

    def _parse_username(self, username):
        username_arr = username.split('/')
        if len(username_arr) == 3:
            # V2 token format: version/service/myservice or version/user/myuser
            version = int(username_arr[0])
            user_type = username_arr[1]
            _from = username_arr[2]
        elif len(username_arr) == 1:
            # Old format, specific to services: myservice
            version = 1
            _from = username_arr[0]
            user_type = 'service'
        else:
            raise TokenValidationError('Unsupported username format.')
        return version, user_type, _from

    def decrypt_token(self, username, token):
        '''
        Decrypt a token.
        '''
        version, user_type, _from = self._parse_username(username)
        if (version > self.maximum_token_version or
                version < self.minimum_token_version):
            raise TokenValidationError('Unacceptable token version.')
        try:
            if PY2:
                token_bytes = bytes(token)
            else:
                token_bytes = bytes(token, 'utf8')
            token_key = '{0}{1}{2}{3}'.format(
                hashlib.sha256(token_bytes).hexdigest(),
                _from,
                self.to_auth_context,
                user_type
            )
        except Exception:
            raise TokenValidationError('Authentication error.')
        if token_key not in self.TOKENS:
            try:
                token = base64.b64decode(token)
                context = {
                    'to': self.to_auth_context,
                    'from': _from
                }
                if version > 1:
                    context['user_type'] = user_type
                data = self.kms_client.decrypt(
                    CiphertextBlob=token,
                    EncryptionContext=context
                )
                # Decrypt doesn't take KeyId as an argument. We need to verify
                # the correct key was used to do the decryption.
                # Annoyingly, the KeyId from the data is actually an arn.
                key_arn = data['KeyId']
                if user_type == 'service':
                    if not self._valid_service_auth_key(key_arn):
                        raise TokenValidationError(
                            'Authentication error (wrong KMS key).'
                        )
                elif user_type == 'user':
                    if not self._valid_user_auth_key(key_arn):
                        raise TokenValidationError(
                            'Authentication error (wrong KMS key).'
                        )
                else:
                    raise TokenValidationError(
                        'Authentication error. Unsupported user_type.'
                    )
                plaintext = data['Plaintext']
                payload = json.loads(plaintext)
                key_alias = self._get_key_alias_from_cache(key_arn)
                ret = {'payload': payload, 'key_alias': key_alias}
            except TokenValidationError:
                raise
            # We don't care what exception is thrown. For paranoia's sake, fail
            # here.
            except Exception:
                logging.exception('Failed to validate token.')
                raise TokenValidationError(
                    'Authentication error. General error.'
                )
        else:
            ret = self.TOKENS[token_key]
        now = datetime.datetime.utcnow()
        try:
            not_before = datetime.datetime.strptime(
                ret['payload']['not_before'],
                TIME_FORMAT
            )
            not_after = datetime.datetime.strptime(
                ret['payload']['not_after'],
                TIME_FORMAT
            )
        except Exception:
            logging.exception(
                'Failed to get not_before and not_after from token payload.'
            )
            raise TokenValidationError(
                'Authentication error. Missing validity.'
            )
        delta = (not_after - not_before).seconds / 60
        if delta > self.auth_token_max_lifetime:
            logging.warning('Token used which exceeds max token lifetime.')
            raise TokenValidationError(
                'Authentication error. Token lifetime exceeded.'
            )
        if (now < not_before) or (now > not_after):
            logging.warning('Invalid time validity for token.')
            raise TokenValidationError(
                'Authentication error. Invalid time validity for token.'
            )
        self.TOKENS[token_key] = ret
        return self.TOKENS[token_key]


class KMSTokenGenerator(object):

    """A class that represents a token generator for KMS auth."""

    def __init__(
            self,
            auth_key,
            auth_context,
            region,
            token_version=2,
            token_cache_file=None,
            token_lifetime=10,
            aws_creds=None
            ):
        """Create a KMSTokenGenerator object.

        Args:
            auth_key: The KMS key ARN or alias to use for authentication.
                Required.
            auth_context: The KMS encryption context to use for authentication.
                Required.
            region: AWS region to connect to. Required.
            token_version: The version of the authentication token. Default: 2
            token_cache_file: he location to use for caching the auth token.
                If set to empty string, no cache will be used. Default: None
            token_lifetime: Lifetime of the authentication token generated.
                Default: 10
            aws_creds: A dict of AccessKeyId, SecretAccessKey, SessionToken.
                Useful if you wish to pass in assumed role credentials or MFA
                credentials. Default: None
        """
        self.auth_key = auth_key
        if auth_context is None:
            self.auth_context = {}
        else:
            self.auth_context = auth_context
        self.token_cache_file = token_cache_file
        self.token_lifetime = token_lifetime
        self.region = region
        self.token_version = token_version
        self.aws_creds = aws_creds
        if aws_creds:
            self.kms_client = kmsauth.services.get_boto_client(
                'kms',
                region=self.region,
                aws_access_key_id=self.aws_creds['AccessKeyId'],
                aws_secret_access_key=self.aws_creds['SecretAccessKey'],
                aws_session_token=self.aws_creds['SessionToken']
            )
        else:
            self.kms_client = kmsauth.services.get_boto_client(
                'kms',
                region=self.region
            )
        self._validate_generator()

    def _validate_generator(self):
        for key in ['from', 'to']:
            if key not in self.auth_context:
                raise ConfigurationError(
                    '{0} missing from auth_context.'.format(key)
                )
        if self.token_version > 1:
            if 'user_type' not in self.auth_context:
                raise ConfigurationError(
                    'user_type missing from auth_context.'
                )
        if self.token_version > 2:
            raise ConfigurationError(
                'Invalid token_version provided.'
            )

    def _get_cached_token(self):
        token = None
        if not self.token_cache_file:
            return token
        try:
            with open(self.token_cache_file, 'r') as f:
                token_data = json.load(f)
            _not_after = token_data['not_after']
            _auth_context = token_data['auth_context']
            _token = token_data['token']
            _not_after_cache = datetime.datetime.strptime(
                _not_after,
                TIME_FORMAT
            )
        except IOError as e:
            logging.debug(
                'Failed to read confidant auth token cache: {0}'.format(e)
            )
            return token
        except Exception:
            logging.exception('Failed to read confidant auth token cache.')
            return token
        skew_delta = datetime.timedelta(minutes=TOKEN_SKEW)
        _not_after_cache = _not_after_cache - skew_delta
        now = datetime.datetime.utcnow()
        if (now <= _not_after_cache and
                _auth_context == self.auth_context):
            logging.debug('Using confidant auth token cache.')
            token = _token
        return token

    def _cache_token(self, token, not_after):
        if not self.token_cache_file:
            return
        try:
            cachedir = os.path.dirname(self.token_cache_file)
            if not os.path.exists(cachedir):
                os.makedirs(cachedir)
            with open(self.token_cache_file, 'w') as f:
                json.dump({
                    'token': token,
                    'not_after': not_after,
                    'auth_context': self.auth_context
                }, f)
        except Exception:
            logging.exception('Failed to write confidant auth token cache.')

    def get_username(self):
        """Get a username formatted for a specific token version."""
        _from = self.auth_context['from']
        if self.token_version == 1:
            return '{0}'.format(_from)
        elif self.token_version == 2:
            _user_type = self.auth_context['user_type']
            return '{0}/{1}/{2}'.format(
                self.token_version,
                _user_type,
                _from
            )

    def get_token(self):
        """Get an authentication token."""
        # Generate string formatted timestamps for not_before and not_after,
        # for the lifetime specified in minutes.
        now = datetime.datetime.utcnow()
        # Start the not_before time x minutes in the past, to avoid clock skew
        # issues.
        _not_before = now - datetime.timedelta(minutes=TOKEN_SKEW)
        not_before = _not_before.strftime(TIME_FORMAT)
        # Set the not_after time in the future, by the lifetime, but ensure the
        # skew we applied to not_before is taken into account.
        _not_after = now + datetime.timedelta(
            minutes=self.token_lifetime - TOKEN_SKEW
        )
        not_after = _not_after.strftime(TIME_FORMAT)
        # Generate a json string for the encryption payload contents.
        payload = json.dumps({
            'not_before': not_before,
            'not_after': not_after
        })
        token = self._get_cached_token()
        if token:
            return token
        # Generate a base64 encoded KMS encrypted token to use for
        # authentication. We encrypt the token lifetime information as the
        # payload for verification in Confidant.
        try:
            token = self.kms_client.encrypt(
                KeyId=self.auth_key,
                Plaintext=payload,
                EncryptionContext=self.auth_context
            )['CiphertextBlob']
            if PY2:
                token_bytes = bytes(token)
            else:
                token_bytes = bytes(token, 'utf8')
            token = base64.b64encode(token_bytes)
        except Exception:
            logging.exception('Failed to create auth token.')
            raise TokenGenerationError()
        self._cache_token(token, not_after)
        return token


class ConfigurationError(Exception):

    """An exception raised when a token was unsuccessfully created."""

    pass


class TokenValidationError(Exception):
    """An exception raised when a token was unsuccessfully validated."""
    pass


class TokenGenerationError(Exception):

    """An exception raised when a token was unsuccessfully generated."""

    pass
