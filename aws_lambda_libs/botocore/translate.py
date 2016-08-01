# Copyright (c) 2012-2013 Mitch Garnaat http://garnaat.org/
# Copyright 2012-2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

"""Translate the raw json files into python specific descriptions."""
import os
import re
from copy import deepcopy

import jmespath

from botocore.compat import OrderedDict, json
from botocore.utils import merge_dicts
from botocore import xform_name


class ModelFiles(object):
    """Container object to hold all the various parsed json files.

    Includes:

        * The json service description.
        * The _retry.json file.
        * The <service>.extra.json enhancements file.
        * The name of the service.

    """
    def __init__(self, model, retry, enhancements, name=''):
        self.model = model
        self.retry = retry
        self.enhancements = enhancements
        self.name = name


def load_model_files(args):
    model = json.load(open(args.modelfile),
                      object_pairs_hook=OrderedDict)
    retry = json.load(open(args.retry_file),
                      object_pairs_hook=OrderedDict)
    enhancements = _load_enhancements_file(args.enhancements_file)
    service_name = os.path.splitext(os.path.basename(args.modelfile))[0]
    return ModelFiles(model, retry, enhancements, name=service_name)


def _load_enhancements_file(file_path):
    if not os.path.isfile(file_path):
        return {}
    else:
        return json.load(open(file_path),
                         object_pairs_hook=OrderedDict)


def translate(model):
    new_model = deepcopy(model.model)
    new_model.update(model.enhancements.get('extra', {}))
    try:
        del new_model['pagination']
    except KeyError:
        pass
    handle_op_renames(new_model, model.enhancements)
    handle_remove_deprecated_params(new_model, model.enhancements)
    handle_remove_deprecated_operations(new_model, model.enhancements)
    handle_filter_documentation(new_model, model.enhancements)
    handle_rename_params(new_model, model.enhancements)
    add_pagination_configs(
        new_model,
        model.enhancements.get('pagination', {}))
    add_waiter_configs(
        new_model,
        model.enhancements.get('waiters', {}))
    # Merge in any per operation overrides defined in the .extras.json file.
    merge_dicts(new_model['operations'],
                model.enhancements.get('operations', {}))
    add_retry_configs(
        new_model, model.retry.get('retry', {}),
        definitions=model.retry.get('definitions', {}))
    return new_model


def handle_op_renames(new_model, enhancements):
    # This allows for operations to be renamed.  The only
    # implemented transformation is removing part of the operation name
    # (because that's all we currently need.)
    remove = enhancements.get('transformations', {}).get(
        'operation-name', {}).get('remove')
    if remove is not None:
        # We're going to recreate the dictionary because we want to preserve
        # the order.  This is the only option we have unless we have our own
        # custom OrderedDict.
        remove_regex = re.compile(remove)
        operations = new_model['operations']
        new_operation = OrderedDict()
        for key in operations:
            new_key = remove_regex.sub('', key)
            new_operation[new_key] = operations[key]
        new_model['operations'] = new_operation


def handle_remove_deprecated_operations(new_model, enhancements):
    # This removes any operation whose documentation string contains
    # the specified phrase that marks a deprecated parameter.
    keyword = enhancements.get('transformations', {}).get(
        'remove-deprecated-operations', {}).get('deprecated_keyword')
    remove = []
    if keyword is not None:
        operations = new_model['operations']
        for op_name in operations:
            operation = operations[op_name]
            if operation:
                docs = operation['documentation']
                if docs and docs.find(keyword) >= 0:
                    remove.append(op_name)
    for op in remove:
        del new_model['operations'][op]


def handle_remove_deprecated_params(new_model, enhancements):
    # This removes any parameter whose documentation string contains
    # the specified phrase that marks a deprecated parameter.
    keyword = enhancements.get('transformations', {}).get(
        'remove-deprecated-params', {}).get('deprecated_keyword')
    if keyword is not None:
        operations = new_model['operations']
        for op_name in operations:
            operation = operations[op_name]
            params = operation.get('input', {}).get('members')
            if params:
                new_params = OrderedDict()
                for param_name in params:
                    param = params[param_name]
                    docs = param['documentation']
                    if docs and docs.find(keyword) >= 0:
                        continue
                    new_params[param_name] = param
                operation['input']['members'] = new_params


def _filter_param_doc(param, replacement, regex):
    # Recurse into complex parameters looking for documentation.
    doc = param.get('documentation')
    if doc:
        param['documentation'] = regex.sub(replacement, doc)
    if param['type'] == 'structure':
        for member_name in param['members']:
            member = param['members'][member_name]
            _filter_param_doc(member, replacement, regex)
    if param['type'] == 'map':
        _filter_param_doc(param['keys'], replacement, regex)
        _filter_param_doc(param['members'], replacement, regex)
    elif param['type'] == 'list':
        _filter_param_doc(param['members'], replacement, regex)


def handle_filter_documentation(new_model, enhancements):
    # This provides a way to filter undesireable content (e.g. CDATA)
    # from documentation strings.
    doc_filter = enhancements.get('transformations', {}).get(
        'filter-documentation', {}).get('filter')
    if doc_filter is not None:
        filter_regex = re.compile(doc_filter.get('regex', ''), re.DOTALL)
        replacement = doc_filter.get('replacement')
        operations = new_model['operations']
        for op_name in operations:
            operation = operations[op_name]
            doc = operation.get('documentation')
            if doc:
                new_doc = filter_regex.sub(replacement, doc)
                operation['documentation'] = new_doc
            params = operation.get('input', {}).get('members')
            if params:
                for param_name in params:
                    param = params[param_name]
                    _filter_param_doc(param, replacement, filter_regex)


def handle_rename_params(new_model, enhancements):
    renames = enhancements.get('transformations', {}).get(
        'renames', {})
    if not renames:
        return
    # This is *extremely* specific to botocore's translations, but
    # we support a restricted set of argument renames based on a
    # jmespath expression.
    for expression, new_value in renames.items():
        # First we take everything up until the last dot.
        parent_expression, key = expression.rsplit('.', 1)
        matched = jmespath.search(parent_expression, new_model['operations'])
        current = matched[key]
        del matched[key]
        matched[new_value] = current


def resembles_jmespath_exp(value):
    # For now, we'll do a naive check.
    if '.' in value or '[' in value:
        return True
    return False


def add_pagination_configs(new_model, pagination):
    # Adding in pagination configs means copying the config to a top level
    # 'pagination' key in the new model, and it also means adding the
    # pagination config to each individual operation.
    # Also, the input_token needs to be transformed to the python specific
    # name, so we're adding a py_input_token (e.g. NextToken -> next_token).
    if pagination:
        new_model['pagination'] = pagination
    for name in pagination:
        config = pagination[name]
        _check_known_pagination_keys(config)
        if 'py_input_token' not in config:
            _add_py_input_token(config)
        _validate_result_key_exists(config)
        _validate_referenced_operation_exists(new_model, name)
        operation = new_model['operations'][name]
        _validate_operation_has_output(operation, name)
        _check_input_keys_match(config, operation)
        _check_output_keys_match(config, operation,
                                 new_model.get('endpoint_prefix', ''))
        operation['pagination'] = config.copy()


def _validate_operation_has_output(operation, name):
    if not operation['output']:
        raise ValueError("Trying to add pagination config for an "
                         "operation with no output members: %s" % name)


def _validate_referenced_operation_exists(new_model, name):
    if name not in new_model['operations']:
        raise ValueError("Trying to add pagination config for non "
                         "existent operation: %s" % name)


def _validate_result_key_exists(config):
    # result_key must be defined.
    if 'result_key' not in config:
        raise ValueError("Required key 'result_key' is missing from "
                         "from pagination config: %s" % config)


def _add_py_input_token(config):
    input_token = config['input_token']
    if isinstance(input_token, list):
        py_input_token = []
        for token in input_token:
            py_input_token.append(xform_name(token))
        config['py_input_token'] = py_input_token
    else:
        config['py_input_token'] = xform_name(input_token)


def add_waiter_configs(new_model, waiters):
    if waiters:
        denormalized = denormalize_waiters(waiters)
        # Before adding it to the new model, we need to verify the
        # final denormalized model.
        for value in denormalized.values():
            if value['operation'] not in new_model['operations']:
                raise ValueError()
        new_model['waiters'] = denormalized


def denormalize_waiters(waiters):
    # The waiter configuration is normalized to avoid duplication.
    # You can inherit defaults, and extend from other definitions.
    # We're going to denormalize this so that the implementation for
    # consuming waiters is simple.
    default = waiters.get('__default__', {})
    new_waiters = {}
    for key, value in waiters.items():
        if key.startswith('__'):
            # Keys that start with '__' are considered abstract/internal
            # and are only used for inheritance.  Because we're going
            # to denormalize the configs and perform all the lookups
            # during this translation process, the abstract/internal
            # configs don't need to make it into the final translated
            # config so we can just skip these.
            continue
        new_waiters[key] = denormalize_single_waiter(value, default, waiters)
    return new_waiters


def denormalize_single_waiter(value, default, waiters):
    """Denormalize a single waiter config.

    :param value: The dictionary of a single waiter config, e.g.
        the ``InstanceRunning`` or ``TableExists`` config.  This
        is the config we're going to denormalize.
    :param default: The ``__default__`` (if any) configuration.
        This is needed to resolve the lookup process.
    :param waiters: The full configuration of the waiters.
        This is needed if we need to look up at parent class that the
        current config extends.
    :return: The denormalized config.
    :rtype: dict

    """
    # First we need to resolve all the keys based on the inheritance
    # hierarchy.  The lookup process is:
    # The most bottom/leaf class is ``value``.  From there we need
    # to look up anything it inherits from (denoted via the ``extends``
    # key).  We need to perform this process recursively until we hit
    # a config that has no ``extends`` key.
    # And finally if we haven't found our value yet, we check in the
    # ``__default__`` key.
    # So the first thing we need to do is build the lookup chain that
    # starts with ``value`` and ends with ``__default__``.
    lookup_chain = [value]
    current = value
    while True:
        if 'extends' not in current:
            break
        current = waiters[current.get('extends')]
        lookup_chain.append(current)
    lookup_chain.append(default)
    new_waiter = {}
    # Now that we have this lookup chain we can build the entire set
    # of values by starting at the most parent class and walking down
    # to the children.  At each step the child is merged onto the parent's
    # config items.  This is the desired behavior as a child's values
    # overrides its parents.  This is what the ``reversed(...)`` call
    # is for.
    for element in reversed(lookup_chain):
        new_waiter.update(element)
    # We don't care about 'extends' so we can safely remove that key.
    new_waiter.pop('extends', {})
    # Now we need to resolve the success/failure values.  We
    # want to completely remove the acceptor types.
    # The logic here is that if there is no success/failure_* variable
    # defined, it inherits this value from the matching acceptor_* variable.
    new_waiter['success_type'] = new_waiter.get(
        'success_type', new_waiter.get('acceptor_type'))
    new_waiter['success_path'] = new_waiter.get(
        'success_path', new_waiter.get('acceptor_path'))
    new_waiter['success_value'] = new_waiter.get(
        'success_value', new_waiter.get('acceptor_value'))
    new_waiter['failure_type'] = new_waiter.get(
        'failure_type', new_waiter.get('acceptor_type'))
    new_waiter['failure_path'] = new_waiter.get(
        'failure_path', new_waiter.get('acceptor_path'))
    new_waiter['failure_value'] = new_waiter.get(
        'failure_value', new_waiter.get('acceptor_value'))
    # We can remove acceptor_* vars because they're only used for lookups
    # and we've already performed this step in the lines above.
    new_waiter.pop('acceptor_type', '')
    new_waiter.pop('acceptor_path', '')
    new_waiter.pop('acceptor_value', '')
    # Remove any keys with a None value.
    for key in list(new_waiter.keys()):
        if new_waiter[key] is None:
            del new_waiter[key]
    # Check required keys.
    for required in ['operation', 'success_type']:
        if required not in new_waiter:
            raise ValueError('Missing required waiter configuration '
                             'value "%s": %s' % (required, new_waiter))
        if new_waiter.get(required) is None:
            raise ValueError('Required waiter configuration '
                             'value cannot be None "%s": %s' %
                             (required, new_waiter))
    # Finally, success/failure values can be a scalar or a list.  We're going
    # to just always make them a list.
    if 'success_value' in new_waiter and not \
            isinstance(new_waiter['success_value'], list):
        new_waiter['success_value'] = [new_waiter['success_value']]
    if 'failure_value' in new_waiter and not \
            isinstance(new_waiter['failure_value'], list):
        new_waiter['failure_value'] = [new_waiter['failure_value']]
    _transform_waiter(new_waiter)
    return new_waiter


def _transform_waiter(new_waiter):
    # This transforms the waiters into a format that's slightly
    # easier to consume.
    if 'success_type' in new_waiter:
        success = {'type': new_waiter.pop('success_type')}
        if 'success_path' in new_waiter:
            success['path'] = new_waiter.pop('success_path')
        if 'success_value' in new_waiter:
            success['value'] = new_waiter.pop('success_value')
        new_waiter['success'] = success
    if 'failure_type' in new_waiter:
        failure = {'type': new_waiter.pop('failure_type')}
        if 'failure_path' in new_waiter:
            failure['path'] = new_waiter.pop('failure_path')
        if 'failure_value' in new_waiter:
            failure['value'] = new_waiter.pop('failure_value')
        new_waiter['failure'] = failure


def _check_known_pagination_keys(config):
    # Verify that the pagination config only has keys we expect to see.
    expected = set(['input_token', 'py_input_token', 'output_token',
                    'result_key', 'limit_key', 'more_results',
                    'non_aggregate_keys'])
    for key in config:
        if key not in expected:
            raise ValueError("Unknown key in pagination config: %s" % key)


def _check_output_keys_match(config, operation, service_name):
    output_members = list(operation['output']['members'])
    jmespath_seen = False
    for output_key in _get_all_page_output_keys(config):
        if resembles_jmespath_exp(output_key):
            # We don't validate jmespath expressions for now.
            jmespath_seen = True
            continue
        if output_key not in output_members:
            raise ValueError("Key %r is not an output member: %s" %
                             (output_key,
                              output_members))
        output_members.remove(output_key)
    # Some services echo the input parameters in the response
    # output.  We should not trigger a validation error
    # if those params are still not accounted for.
    for input_name in operation['input']['members']:
        if input_name in output_members:
            output_members.remove(input_name)
    if not jmespath_seen and output_members:
        # Because we can't validate jmespath expressions yet,
        # we can't say for user if output_members actually has
        # remaining keys or not.
        if service_name == 's3' and output_members == ['Name']:
            # The S3 model uses 'Name' for the output key, which
            # actually maps to the 'Bucket' input param so we don't
            # need to validate this output member.  This is the only
            # model that has this, so we can just special case this
            # for now.
            return
        raise ValueError("Output members still exist for operation %s: %s" % (
            operation['name'], output_members))


def _get_all_page_output_keys(config):
    if not isinstance(config['result_key'], list):
        yield config['result_key']
    else:
        for result_key in config['result_key']:
            yield result_key
    if not isinstance(config['output_token'], list):
        yield config['output_token']
    else:
        for result_key in config['output_token']:
            yield result_key
    if 'more_results' in config:
        yield config['more_results']
    for key in config.get('non_aggregate_keys', []):
        yield key


def _check_input_keys_match(config, operation):
    input_tokens = config['input_token']
    if not isinstance(input_tokens, list):
        input_tokens = [input_tokens]
    valid_input_names = operation['input']['members']
    for token in input_tokens:
        if token not in valid_input_names:
            raise ValueError("input_token refers to a non existent "
                             "input name for operation %s: %s.  "
                             "Must be one of: %s" % (operation['name'], token,
                                                     list(valid_input_names)))
    if 'limit_key' in config and config['limit_key'] not in valid_input_names:
        raise ValueError("limit_key refers to a non existent input name for "
                         "operation %s: %s.  Must be one of: %s" % (
                             operation['name'], config['limit_key'],
                             list(valid_input_names)))


def add_retry_configs(new_model, retry_model, definitions):
    if not retry_model:
        new_model['retry'] = {}
        return
    # The service specific retry config is keyed off of the endpoint
    # prefix as defined in the JSON model.
    endpoint_prefix = new_model.get('endpoint_prefix', '')
    final_retry_config = build_retry_config(endpoint_prefix, retry_model,
                                            definitions)
    new_model['retry'] = final_retry_config


def build_retry_config(endpoint_prefix, retry_model, definitions):
    service_config = retry_model.get(endpoint_prefix, {})
    resolve_references(service_config, definitions)
    # We want to merge the global defaults with the service specific
    # defaults, with the service specific defaults taking precedence.
    # So we use the global defaults as the base.
    final_retry_config = {'__default__': retry_model.get('__default__', {})}
    resolve_references(final_retry_config, definitions)
    # The merge the service specific config on top.
    merge_dicts(final_retry_config, service_config)
    return final_retry_config


def resolve_references(config, definitions):
    """Recursively replace $ref keys.

    To cut down on duplication, common definitions can be declared
    (and passed in via the ``definitions`` attribute) and then
    references as {"$ref": "name"}, when this happens the reference
    dict is placed with the value from the ``definition`` dict.

    This is recursively done.

    """
    for key, value in config.items():
        if isinstance(value, dict):
            if len(value) == 1 and list(value.keys())[0] == '$ref':
                # Then we need to resolve this reference.
                config[key] = definitions[list(value.values())[0]]
            else:
                resolve_references(value, definitions)
