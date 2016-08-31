# Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
import copy
import logging

import botocore.serialize
import botocore.validate
from botocore import waiter, xform_name
from botocore.auth import AUTH_TYPE_MAPS
from botocore.awsrequest import prepare_request_dict
from botocore.config import Config
from botocore.docs.docstring import ClientMethodDocstring
from botocore.docs.docstring import PaginatorDocstring
from botocore.endpoint import EndpointCreator
from botocore.exceptions import ClientError, DataNotFoundError
from botocore.exceptions import OperationNotPageableError
from botocore.exceptions import UnknownSignatureVersionError
from botocore.hooks import first_non_none_response
from botocore.model import ServiceModel
from botocore.paginate import Paginator
from botocore.signers import RequestSigner
from botocore.utils import CachedProperty
from botocore.utils import fix_s3_host
from botocore.utils import get_service_module_name
from botocore.utils import switch_to_virtual_host_style
from botocore.utils import switch_host_s3_accelerate
from botocore.utils import S3_ACCELERATE_ENDPOINT
from botocore.utils import S3RegionRedirector


logger = logging.getLogger(__name__)


class ClientCreator(object):
    """Creates client objects for a service."""
    def __init__(self, loader, endpoint_resolver, user_agent, event_emitter,
                 retry_handler_factory, retry_config_translator,
                 response_parser_factory=None):
        self._loader = loader
        self._endpoint_resolver = endpoint_resolver
        self._user_agent = user_agent
        self._event_emitter = event_emitter
        self._retry_handler_factory = retry_handler_factory
        self._retry_config_translator = retry_config_translator
        self._response_parser_factory = response_parser_factory

    def create_client(self, service_name, region_name, is_secure=True,
                      endpoint_url=None, verify=None,
                      credentials=None, scoped_config=None,
                      api_version=None,
                      client_config=None):
        service_model = self._load_service_model(service_name, api_version)
        cls = self._create_client_class(service_name, service_model)
        endpoint_bridge = ClientEndpointBridge(
            self._endpoint_resolver, scoped_config, client_config,
            service_signing_name=service_model.metadata.get('signingName'))
        client_args = self._get_client_args(
            service_model, region_name, is_secure, endpoint_url,
            verify, credentials, scoped_config, client_config, endpoint_bridge)
        service_client = cls(**client_args)
        self._create_s3_redirector(service_client, endpoint_bridge)
        return service_client

    def create_client_class(self, service_name, api_version=None):
        service_model = self._load_service_model(service_name, api_version)
        return self._create_client_class(service_name, service_model)

    def _create_client_class(self, service_name, service_model):
        class_attributes = self._create_methods(service_model)
        py_name_to_operation_name = self._create_name_mapping(service_model)
        class_attributes['_PY_TO_OP_NAME'] = py_name_to_operation_name
        bases = [BaseClient]
        self._event_emitter.emit('creating-client-class.%s' % service_name,
                                 class_attributes=class_attributes,
                                 base_classes=bases)
        class_name = get_service_module_name(service_model)
        cls = type(str(class_name), tuple(bases), class_attributes)
        return cls

    def _load_service_model(self, service_name, api_version=None):
        json_model = self._loader.load_service_model(service_name, 'service-2',
                                                     api_version=api_version)
        service_model = ServiceModel(json_model, service_name=service_name)
        self._register_retries(service_model)
        return service_model

    def _register_retries(self, service_model):
        endpoint_prefix = service_model.endpoint_prefix

        # First, we load the entire retry config for all services,
        # then pull out just the information we need.
        original_config = self._loader.load_data('_retry')
        if not original_config:
            return

        retry_config = self._retry_config_translator.build_retry_config(
            endpoint_prefix, original_config.get('retry', {}),
            original_config.get('definitions', {}))

        logger.debug("Registering retry handlers for service: %s",
                     service_model.service_name)
        handler = self._retry_handler_factory.create_retry_handler(
            retry_config, endpoint_prefix)
        unique_id = 'retry-config-%s' % endpoint_prefix
        self._event_emitter.register('needs-retry.%s' % endpoint_prefix,
                                     handler, unique_id=unique_id)

    def _inject_s3_configuration(self, config_kwargs, scoped_config,
                                 client_config):
        s3_configuration = None

        # Check the scoped config first.
        if scoped_config is not None:
            s3_configuration = scoped_config.get('s3')
            # Until we have proper validation of the config file (including
            # nested types), we have to account for the fact that the s3
            # key could be parsed as a string, e.g 's3 = foo'.
            # In the case we'll ignore the key for now.
            if not isinstance(s3_configuration, dict):
                logger.debug("The s3 config key is not a dictionary type, "
                             "ignoring its value of: %s", s3_configuration)
                s3_configuration = None

            # Convert logic for several s3 keys in the scoped config
            # so that the various strings map to the appropriate boolean value.
            if s3_configuration:
                boolean_keys = ['use_accelerate_endpoint',
                                'payload_signing_enabled']
                s3_configuration = self._convert_config_to_bool(
                    s3_configuration, boolean_keys)

        # Next specific client config values takes precedence over
        # specific values in the scoped config.
        if client_config is not None:
            if client_config.s3 is not None:
                if s3_configuration is None:
                    s3_configuration = client_config.s3
                else:
                    # The current s3_configuration dictionary may be
                    # from a source that only should be read from so
                    # we want to be safe and just make a copy of it to modify
                    # before it actually gets updated.
                    s3_configuration = s3_configuration.copy()
                    s3_configuration.update(client_config.s3)

        config_kwargs['s3'] = s3_configuration

    def _convert_config_to_bool(self, config_dict, keys):
        # Make sure any further modifications to this section of the config
        # will not affect the scoped config by making a copy of it.
        config_copy = config_dict.copy()
        present_keys = [k for k in keys if k in config_copy]
        for key in present_keys:
            # Normalize on different possible values of True
            if config_copy[key] in [True, 'True', 'true']:
                config_copy[key] = True
            else:
                config_copy[key] = False
        return config_copy

    def _conditionally_unregister_fix_s3_host(self, endpoint_url, emitter):
        # If the user is providing a custom endpoint, we should not alter it.
        if endpoint_url is not None:
            emitter.unregister('before-sign.s3', fix_s3_host)

    def _create_s3_redirector(self, client, endpoint_bridge):
        if client.meta.service_model.service_name != 's3':
            return
        S3RegionRedirector(endpoint_bridge, client).register()

    def _get_client_args(self, service_model, region_name, is_secure,
                         endpoint_url, verify, credentials,
                         scoped_config, client_config, endpoint_bridge):
        service_name = service_model.endpoint_prefix
        protocol = service_model.metadata['protocol']
        parameter_validation = True
        if client_config and not client_config.parameter_validation:
            parameter_validation = False
        elif scoped_config:
            raw_value = str(scoped_config.get('parameter_validation', ''))
            if raw_value.lower() == 'false':
                parameter_validation = False
        serializer = botocore.serialize.create_serializer(
            protocol, parameter_validation)

        event_emitter = copy.copy(self._event_emitter)
        response_parser = botocore.parsers.create_parser(protocol)
        endpoint_config = endpoint_bridge.resolve(
            service_name, region_name, endpoint_url, is_secure)

        # Override the user agent if specified in the client config.
        user_agent = self._user_agent
        if client_config is not None:
            if client_config.user_agent is not None:
                user_agent = client_config.user_agent
            if client_config.user_agent_extra is not None:
                user_agent += ' %s' % client_config.user_agent_extra

        signer = RequestSigner(
            service_name, endpoint_config['signing_region'],
            endpoint_config['signing_name'],
            endpoint_config['signature_version'],
            credentials, event_emitter)

        # Create a new client config to be passed to the client based
        # on the final values. We do not want the user to be able
        # to try to modify an existing client with a client config.
        config_kwargs = dict(
            region_name=endpoint_config['region_name'],
            signature_version=endpoint_config['signature_version'],
            user_agent=user_agent)
        if client_config is not None:
            config_kwargs.update(
                connect_timeout=client_config.connect_timeout,
                read_timeout=client_config.read_timeout)

        # Add any additional s3 configuration for client
        self._inject_s3_configuration(
            config_kwargs, scoped_config, client_config)
        self._conditionally_unregister_fix_s3_host(endpoint_url, event_emitter)

        new_config = Config(**config_kwargs)
        endpoint_creator = EndpointCreator(event_emitter)
        endpoint = endpoint_creator.create_endpoint(
            service_model, region_name=endpoint_config['region_name'],
            endpoint_url=endpoint_config['endpoint_url'], verify=verify,
            response_parser_factory=self._response_parser_factory,
            timeout=(new_config.connect_timeout, new_config.read_timeout))

        return {
            'serializer': serializer,
            'endpoint': endpoint,
            'response_parser': response_parser,
            'event_emitter': event_emitter,
            'request_signer': signer,
            'service_model': service_model,
            'loader': self._loader,
            'client_config': new_config
        }

    def _create_methods(self, service_model):
        op_dict = {}
        for operation_name in service_model.operation_names:
            py_operation_name = xform_name(operation_name)
            op_dict[py_operation_name] = self._create_api_method(
                py_operation_name, operation_name, service_model)
        return op_dict

    def _create_name_mapping(self, service_model):
        # py_name -> OperationName, for every operation available
        # for a service.
        mapping = {}
        for operation_name in service_model.operation_names:
            py_operation_name = xform_name(operation_name)
            mapping[py_operation_name] = operation_name
        return mapping

    def _create_api_method(self, py_operation_name, operation_name,
                           service_model):
        def _api_call(self, *args, **kwargs):
            # We're accepting *args so that we can give a more helpful
            # error message than TypeError: _api_call takes exactly
            # 1 argument.
            if args:
                raise TypeError(
                    "%s() only accepts keyword arguments." % py_operation_name)
            # The "self" in this scope is referring to the BaseClient.
            return self._make_api_call(operation_name, kwargs)

        _api_call.__name__ = str(py_operation_name)

        # Add the docstring to the client method
        operation_model = service_model.operation_model(operation_name)
        docstring = ClientMethodDocstring(
            operation_model=operation_model,
            method_name=operation_name,
            event_emitter=self._event_emitter,
            method_description=operation_model.documentation,
            example_prefix='response = client.%s' % py_operation_name,
            include_signature=False
        )
        _api_call.__doc__ = docstring
        return _api_call


class ClientEndpointBridge(object):
    """Bridges endpoint data and client creation

    This class handles taking out the relevant arguments from the endpoint
    resolver and determining which values to use, taking into account any
    client configuration options and scope configuration options.

    This class also handles determining what, if any, region to use if no
    explicit region setting is provided. For example, Amazon S3 client will
    utilize "us-east-1" by default if no region can be resolved."""

    DEFAULT_ENDPOINT = '{service}.{region}.amazonaws.com'

    def __init__(self, endpoint_resolver, scoped_config=None,
                 client_config=None, default_endpoint=None,
                 service_signing_name=None):
        self.service_signing_name = service_signing_name
        self.endpoint_resolver = endpoint_resolver
        self.scoped_config = scoped_config
        self.client_config = client_config
        self.default_endpoint = default_endpoint or self.DEFAULT_ENDPOINT

    def resolve(self, service_name, region_name=None, endpoint_url=None,
                is_secure=True):
        region_name = self._check_default_region(service_name, region_name)
        resolved = self.endpoint_resolver.construct_endpoint(
            service_name, region_name)
        if resolved:
            return self._create_endpoint(
                resolved, service_name, region_name, endpoint_url, is_secure)
        else:
            return self._assume_endpoint(service_name, region_name,
                                         endpoint_url, is_secure)

    def _check_default_region(self, service_name, region_name):
        if region_name is not None:
            return region_name
        # Use the client_config region if no explicit region was provided.
        if self.client_config and self.client_config.region_name is not None:
            return self.client_config.region_name

    def _create_endpoint(self, resolved, service_name, region_name,
                         endpoint_url, is_secure):
        region_name, signing_region = self._pick_region_values(
            resolved, region_name, endpoint_url)
        if endpoint_url is None:
            # Use the sslCommonName over the hostname for Python 2.6 compat.
            hostname = resolved.get('sslCommonName', resolved.get('hostname'))
            endpoint_url = self._make_url(hostname, is_secure,
                                          resolved.get('protocols', []))
        signature_version = self._resolve_signature_version(
            service_name, resolved)
        signing_name = self._resolve_signing_name(service_name, resolved)
        return self._create_result(
            service_name=service_name, region_name=region_name,
            signing_region=signing_region, signing_name=signing_name,
            endpoint_url=endpoint_url, metadata=resolved,
            signature_version=signature_version)

    def _assume_endpoint(self, service_name, region_name, endpoint_url,
                         is_secure):
        if endpoint_url is None:
            # Expand the default hostname URI template.
            hostname = self.default_endpoint.format(
                service=service_name, region=region_name)
            endpoint_url = self._make_url(hostname, is_secure,
                                          ['http', 'https'])
        logger.debug('Assuming an endpoint for %s, %s: %s',
                     service_name, region_name, endpoint_url)
        # We still want to allow the user to provide an explicit version.
        signature_version = self._resolve_signature_version(
            service_name, {'signatureVersions': ['v4']})
        signing_name = self._resolve_signing_name(service_name, resolved={})
        return self._create_result(
            service_name=service_name, region_name=region_name,
            signing_region=region_name, signing_name=signing_name,
            signature_version=signature_version, endpoint_url=endpoint_url,
            metadata={})

    def _create_result(self, service_name, region_name, signing_region,
                       signing_name, endpoint_url, signature_version,
                       metadata):
        return {
            'service_name': service_name,
            'region_name': region_name,
            'signing_region': signing_region,
            'signing_name': signing_name,
            'endpoint_url': endpoint_url,
            'signature_version': signature_version,
            'metadata': metadata
        }

    def _make_url(self, hostname, is_secure, supported_protocols):
        if is_secure and 'https' in supported_protocols:
            scheme = 'https'
        else:
            scheme = 'http'
        return '%s://%s' % (scheme, hostname)

    def _resolve_signing_name(self, service_name, resolved):
        # CredentialScope overrides everything else.
        if 'credentialScope' in resolved \
                and 'service' in resolved['credentialScope']:
            return resolved['credentialScope']['service']
        # Use the signingName from the model if present.
        if self.service_signing_name:
            return self.service_signing_name
        # Just assume is the same as the service name.
        return service_name

    def _pick_region_values(self, resolved, region_name, endpoint_url):
        signing_region = region_name
        if endpoint_url is None:
            # Do not use the region name or signing name from the resolved
            # endpoint if the user explicitly provides an endpoint_url. This
            # would happen if we resolve to an endpoint where the service has
            # a "defaults" section that overrides all endpoint with a single
            # hostname and credentialScope. This has been the case historically
            # for how STS has worked. The only way to resolve an STS endpoint
            # was to provide a region_name and an endpoint_url. In that case,
            # we would still resolve an endpoint, but we would not use the
            # resolved endpointName or signingRegion because we want to allow
            # custom endpoints.
            region_name = resolved['endpointName']
            signing_region = region_name
            if 'credentialScope' in resolved \
                    and 'region' in resolved['credentialScope']:
                signing_region = resolved['credentialScope']['region']
        return region_name, signing_region

    def _resolve_signature_version(self, service_name, resolved):
        # Client config overrides everything.
        client = self.client_config
        if client and client.signature_version is not None:
            return client.signature_version
        # Scoped config overrides picking from the endpoint metadata.
        scoped = self.scoped_config
        if scoped is not None:
            service_config = scoped.get(service_name)
            if service_config is not None and isinstance(service_config, dict):
                version = service_config.get('signature_version')
                if version:
                    logger.debug(
                        "Switching signature version for service %s "
                        "to version %s based on config file override.",
                        service_name, version)
                    return version
        # Pick a signature version from the endpoint metadata if present.
        if 'signatureVersions' in resolved:
            potential_versions = resolved['signatureVersions']
            if service_name == 's3':
                # We currently prefer s3 over s3v4.
                if 's3' in potential_versions:
                    return 's3'
                elif 's3v4' in potential_versions:
                    return 's3v4'
            if 'v4' in potential_versions:
                return 'v4'
            # Now just iterate over the signature versions in order until we
            # find the first one that is known to Botocore.
            for known in AUTH_TYPE_MAPS:
                if known in potential_versions:
                    return known
        raise UnknownSignatureVersionError(
            signature_version=resolved.get('signatureVersions'))


class BaseClient(object):

    # This is actually reassigned with the py->op_name mapping
    # when the client creator creates the subclass.  This value is used
    # because calls such as client.get_paginator('list_objects') use the
    # snake_case name, but we need to know the ListObjects form.
    # xform_name() does the ListObjects->list_objects conversion, but
    # we need the reverse mapping here.
    _PY_TO_OP_NAME = {}

    def __init__(self, serializer, endpoint, response_parser,
                 event_emitter, request_signer, service_model, loader,
                 client_config):
        self._serializer = serializer
        self._endpoint = endpoint
        self._response_parser = response_parser
        self._request_signer = request_signer
        self._cache = {}
        self._loader = loader
        self._client_config = client_config
        self.meta = ClientMeta(event_emitter, self._client_config,
                               endpoint.host, service_model,
                               self._PY_TO_OP_NAME)
        self._register_handlers()

    def _register_handlers(self):
        # Register the handler required to sign requests.
        self.meta.events.register('request-created.%s' %
                                  self.meta.service_model.endpoint_prefix,
                                  self._request_signer.handler)

        self._register_s3_specific_handlers()

    def _register_s3_specific_handlers(self):
        # Register all of the s3 specific handlers
        if self.meta.config.s3 is None:
            s3_addressing_style = None
            s3_accelerate = None
        else:
            s3_addressing_style = self.meta.config.s3.get('addressing_style')
            s3_accelerate = self.meta.config.s3.get('use_accelerate_endpoint')

        # Enable accelerate if the configuration is set to to true or the
        # endpoint being used matches one of the Accelerate endpoints.
        if s3_accelerate or S3_ACCELERATE_ENDPOINT in self._endpoint.host:
            # Amazon S3 accelerate is being used then always use the virtual
            # style of addressing because it is required.
            self._force_virtual_style_s3_addressing()
            # Also make sure that the hostname gets switched to
            # s3-accelerate.amazonaws.com
            self.meta.events.register_first(
                'request-created.s3', switch_host_s3_accelerate)
        elif s3_addressing_style:
            # Otherwise go ahead with the style the user may have specified.
            if s3_addressing_style == 'path':
                self._force_path_style_s3_addressing()
            elif s3_addressing_style == 'virtual':
                self._force_virtual_style_s3_addressing()

    def _force_path_style_s3_addressing(self):
        # Do not try to modify the host if path is specified. The
        # ``fix_s3_host`` usually switches the addresing style to virtual.
        self.meta.events.unregister('before-sign.s3', fix_s3_host)

    def _force_virtual_style_s3_addressing(self):
        # If the virtual host addressing style is being forced,
        # switch the default fix_s3_host handler for the more general
        # switch_to_virtual_host_style handler that does not have opt out
        # cases (other than throwing an error if the name is DNS incompatible)
        self.meta.events.unregister('before-sign.s3', fix_s3_host)
        self.meta.events.register(
            'before-sign.s3', switch_to_virtual_host_style)

    @property
    def _service_model(self):
        return self.meta.service_model

    def _make_api_call(self, operation_name, api_params):
        operation_model = self._service_model.operation_model(operation_name)
        request_context = {
            'client_region': self.meta.region_name,
            'client_config': self.meta.config,
            'has_streaming_input': operation_model.has_streaming_input
        }
        request_dict = self._convert_to_request_dict(
            api_params, operation_model, context=request_context)

        handler, event_response = self.meta.events.emit_until_response(
            'before-call.{endpoint_prefix}.{operation_name}'.format(
                endpoint_prefix=self._service_model.endpoint_prefix,
                operation_name=operation_name),
            model=operation_model, params=request_dict,
            request_signer=self._request_signer, context=request_context)

        if event_response is not None:
            http, parsed_response = event_response
        else:
            http, parsed_response = self._endpoint.make_request(
                operation_model, request_dict)

        self.meta.events.emit(
            'after-call.{endpoint_prefix}.{operation_name}'.format(
                endpoint_prefix=self._service_model.endpoint_prefix,
                operation_name=operation_name),
            http_response=http, parsed=parsed_response,
            model=operation_model, context=request_context
        )

        if http.status_code >= 300:
            raise ClientError(parsed_response, operation_name)
        else:
            return parsed_response

    def _convert_to_request_dict(self, api_params, operation_model,
                                 context=None):
        # Given the API params provided by the user and the operation_model
        # we can serialize the request to a request_dict.
        operation_name = operation_model.name

        # Emit an event that allows users to modify the parameters at the
        # beginning of the method. It allows handlers to modify existing
        # parameters or return a new set of parameters to use.
        responses = self.meta.events.emit(
            'provide-client-params.{endpoint_prefix}.{operation_name}'.format(
                endpoint_prefix=self._service_model.endpoint_prefix,
                operation_name=operation_name),
            params=api_params, model=operation_model, context=context)
        api_params = first_non_none_response(responses, default=api_params)

        event_name = (
            'before-parameter-build.{endpoint_prefix}.{operation_name}')
        self.meta.events.emit(
            event_name.format(
                endpoint_prefix=self._service_model.endpoint_prefix,
                operation_name=operation_name),
            params=api_params, model=operation_model, context=context)

        request_dict = self._serializer.serialize_to_request(
            api_params, operation_model)
        prepare_request_dict(request_dict, endpoint_url=self._endpoint.host,
                             user_agent=self._client_config.user_agent,
                             context=context)
        return request_dict

    def get_paginator(self, operation_name):
        """Create a paginator for an operation.

        :type operation_name: string
        :param operation_name: The operation name.  This is the same name
            as the method name on the client.  For example, if the
            method name is ``create_foo``, and you'd normally invoke the
            operation as ``client.create_foo(**kwargs)``, if the
            ``create_foo`` operation can be paginated, you can use the
            call ``client.get_paginator("create_foo")``.

        :raise OperationNotPageableError: Raised if the operation is not
            pageable.  You can use the ``client.can_paginate`` method to
            check if an operation is pageable.

        :rtype: L{botocore.paginate.Paginator}
        :return: A paginator object.

        """
        if not self.can_paginate(operation_name):
            raise OperationNotPageableError(operation_name=operation_name)
        else:
            actual_operation_name = self._PY_TO_OP_NAME[operation_name]

            # Create a new paginate method that will serve as a proxy to
            # the underlying Paginator.paginate method. This is needed to
            # attach a docstring to the method.
            def paginate(self, **kwargs):
                return Paginator.paginate(self, **kwargs)

            paginator_config = self._cache['page_config'][
                actual_operation_name]
            # Add the docstring for the paginate method.
            paginate.__doc__ = PaginatorDocstring(
                paginator_name=actual_operation_name,
                event_emitter=self.meta.events,
                service_model=self.meta.service_model,
                paginator_config=paginator_config,
                include_signature=False
            )

            # Rename the paginator class based on the type of paginator.
            paginator_class_name = str('%s.Paginator.%s' % (
                get_service_module_name(self.meta.service_model),
                actual_operation_name))

            # Create the new paginator class
            documented_paginator_cls = type(
                paginator_class_name, (Paginator,), {'paginate': paginate})

            paginator = documented_paginator_cls(
                getattr(self, operation_name),
                paginator_config)
            return paginator

    def can_paginate(self, operation_name):
        """Check if an operation can be paginated.

        :type operation_name: string
        :param operation_name: The operation name.  This is the same name
            as the method name on the client.  For example, if the
            method name is ``create_foo``, and you'd normally invoke the
            operation as ``client.create_foo(**kwargs)``, if the
            ``create_foo`` operation can be paginated, you can use the
            call ``client.get_paginator("create_foo")``.

        :return: ``True`` if the operation can be paginated,
            ``False`` otherwise.

        """
        if 'page_config' not in self._cache:
            try:
                page_config = self._loader.load_service_model(
                    self._service_model.service_name,
                    'paginators-1',
                    self._service_model.api_version)['pagination']
                self._cache['page_config'] = page_config
            except DataNotFoundError:
                self._cache['page_config'] = {}
        actual_operation_name = self._PY_TO_OP_NAME[operation_name]
        return actual_operation_name in self._cache['page_config']

    def _get_waiter_config(self):
        if 'waiter_config' not in self._cache:
            try:
                waiter_config = self._loader.load_service_model(
                    self._service_model.service_name,
                    'waiters-2',
                    self._service_model.api_version)
                self._cache['waiter_config'] = waiter_config
            except DataNotFoundError:
                self._cache['waiter_config'] = {}
        return self._cache['waiter_config']

    def get_waiter(self, waiter_name):
        config = self._get_waiter_config()
        if not config:
            raise ValueError("Waiter does not exist: %s" % waiter_name)
        model = waiter.WaiterModel(config)
        mapping = {}
        for name in model.waiter_names:
            mapping[xform_name(name)] = name
        if waiter_name not in mapping:
            raise ValueError("Waiter does not exist: %s" % waiter_name)

        return waiter.create_waiter_with_client(
            mapping[waiter_name], model, self)

    @CachedProperty
    def waiter_names(self):
        """Returns a list of all available waiters."""
        config = self._get_waiter_config()
        if not config:
            return []
        model = waiter.WaiterModel(config)
        # Waiter configs is a dict, we just want the waiter names
        # which are the keys in the dict.
        return [xform_name(name) for name in model.waiter_names]


class ClientMeta(object):
    """Holds additional client methods.

    This class holds additional information for clients.  It exists for
    two reasons:

        * To give advanced functionality to clients
        * To namespace additional client attributes from the operation
          names which are mapped to methods at runtime.  This avoids
          ever running into collisions with operation names.

    """

    def __init__(self, events, client_config, endpoint_url, service_model,
                 method_to_api_mapping):
        self.events = events
        self._client_config = client_config
        self._endpoint_url = endpoint_url
        self._service_model = service_model
        self._method_to_api_mapping = method_to_api_mapping

    @property
    def service_model(self):
        return self._service_model

    @property
    def region_name(self):
        return self._client_config.region_name

    @property
    def endpoint_url(self):
        return self._endpoint_url

    @property
    def config(self):
        return self._client_config

    @property
    def method_to_api_mapping(self):
        return self._method_to_api_mapping
