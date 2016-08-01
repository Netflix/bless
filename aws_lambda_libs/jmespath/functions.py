import math
import json
import weakref

from jmespath import exceptions
from jmespath.compat import string_type as STRING_TYPE
from jmespath.compat import get_methods


# python types -> jmespath types
TYPES_MAP = {
    'bool': 'boolean',
    'list': 'array',
    'dict': 'object',
    'NoneType': 'null',
    'unicode': 'string',
    'str': 'string',
    'float': 'number',
    'int': 'number',
    'OrderedDict': 'object',
    '_Projection': 'array',
    '_Expression': 'expref',
}


# jmespath types -> python types
REVERSE_TYPES_MAP = {
    'boolean': ('bool',),
    'array': ('list', '_Projection'),
    'object': ('dict', 'OrderedDict',),
    'null': ('None',),
    'string': ('unicode', 'str'),
    'number': ('float', 'int'),
    'expref': ('_Expression',),
}


def populate_function_table(cls):
    func_table = cls.FUNCTION_TABLE
    for name, method in get_methods(cls):
        signature = getattr(method, 'signature', None)
        if signature is not None:
            func_table[name[6:]] = {"function": method,
                                    "signature": signature}
    return cls


def builtin_function(*arguments):
    def _record_arity(func):
        func.signature = arguments
        return func
    return _record_arity


@populate_function_table
class RuntimeFunctions(object):
    # The built in functions are automatically populated in the FUNCTION_TABLE
    # using the @builtin_function decorator on methods defined in this class.

    FUNCTION_TABLE = {
    }

    def __init__(self):
        self._interpreter = None

    @property
    def interpreter(self):
        if self._interpreter is None:
            return None
        else:
            return self._interpreter()

    @interpreter.setter
    def interpreter(self, value):
        # A weakref is used because we have
        # a cyclic reference and we want to allow
        # for the memory to be properly freed when
        # the objects are no longer needed.
        self._interpreter = weakref.ref(value)

    def call_function(self, function_name, resolved_args):
        try:
            spec = self.FUNCTION_TABLE[function_name]
        except KeyError:
            raise exceptions.UnknownFunctionError(
                "Unknown function: %s()" % function_name)
        function = spec['function']
        signature = spec['signature']
        self._validate_arguments(resolved_args, signature, function_name)
        return function(self, *resolved_args)

    def _validate_arguments(self, args, signature, function_name):
        if signature and signature[-1].get('variadic'):
            if len(args) < len(signature):
                raise exceptions.VariadictArityError(
                    len(signature), len(args), function_name)
        elif len(args) != len(signature):
            raise exceptions.ArityError(
                len(signature), len(args), function_name)
        return self._type_check(args, signature, function_name)

    def _type_check(self, actual, signature, function_name):
        for i in range(len(signature)):
            allowed_types = signature[i]['types']
            if allowed_types:
                self._type_check_single(actual[i], allowed_types,
                                        function_name)

    def _type_check_single(self, current, types, function_name):
        # Type checking involves checking the top level type,
        # and in the case of arrays, potentially checking the types
        # of each element.
        allowed_types, allowed_subtypes = self._get_allowed_pytypes(types)
        # We're not using isinstance() on purpose.
        # The type model for jmespath does not map
        # 1-1 with python types (booleans are considered
        # integers in python for example).
        actual_typename = type(current).__name__
        if actual_typename not in allowed_types:
            raise exceptions.JMESPathTypeError(
                function_name, current,
                self._convert_to_jmespath_type(actual_typename), types)
        # If we're dealing with a list type, we can have
        # additional restrictions on the type of the list
        # elements (for example a function can require a
        # list of numbers or a list of strings).
        # Arrays are the only types that can have subtypes.
        if allowed_subtypes:
            self._subtype_check(current, allowed_subtypes,
                                types, function_name)

    def _get_allowed_pytypes(self, types):
        allowed_types = []
        allowed_subtypes = []
        for t in types:
            type_ = t.split('-', 1)
            if len(type_) == 2:
                type_, subtype = type_
                allowed_subtypes.append(REVERSE_TYPES_MAP[subtype])
            else:
                type_ = type_[0]
            allowed_types.extend(REVERSE_TYPES_MAP[type_])
        return allowed_types, allowed_subtypes

    def _subtype_check(self, current, allowed_subtypes, types, function_name):
        if len(allowed_subtypes) == 1:
            # The easy case, we know up front what type
            # we need to validate.
            allowed_subtypes = allowed_subtypes[0]
            for element in current:
                actual_typename = type(element).__name__
                if actual_typename not in allowed_subtypes:
                    raise exceptions.JMESPathTypeError(
                        function_name, element, actual_typename, types)
        elif len(allowed_subtypes) > 1 and current:
            # Dynamic type validation.  Based on the first
            # type we see, we validate that the remaining types
            # match.
            first = type(current[0]).__name__
            for subtypes in allowed_subtypes:
                if first in subtypes:
                    allowed = subtypes
                    break
            else:
                raise exceptions.JMESPathTypeError(
                    function_name, current[0], first, types)
            for element in current:
                actual_typename = type(element).__name__
                if actual_typename not in allowed:
                    raise exceptions.JMESPathTypeError(
                        function_name, element, actual_typename, types)

    @builtin_function({'types': ['number']})
    def _func_abs(self, arg):
        return abs(arg)

    @builtin_function({'types': ['array-number']})
    def _func_avg(self, arg):
        return sum(arg) / float(len(arg))

    @builtin_function({'types': [], 'variadic': True})
    def _func_not_null(self, *arguments):
        for argument in arguments:
            if argument is not None:
                return argument

    @builtin_function({'types': []})
    def _func_to_array(self, arg):
        if isinstance(arg, list):
            return arg
        else:
            return [arg]

    @builtin_function({'types': []})
    def _func_to_string(self, arg):
        if isinstance(arg, STRING_TYPE):
            return arg
        else:
            return json.dumps(arg, separators=(',', ':'),
                              default=str)

    @builtin_function({'types': []})
    def _func_to_number(self, arg):
        if isinstance(arg, (list, dict, bool)):
            return None
        elif arg is None:
            return None
        elif isinstance(arg, (int, float)):
            return arg
        else:
            try:
                if '.' in arg:
                    return float(arg)
                else:
                    return int(arg)
            except ValueError:
                return None

    @builtin_function({'types': ['array', 'string']}, {'types': []})
    def _func_contains(self, subject, search):
        return search in subject

    @builtin_function({'types': ['string', 'array', 'object']})
    def _func_length(self, arg):
        return len(arg)

    @builtin_function({'types': ['string']}, {'types': ['string']})
    def _func_ends_with(self, search, suffix):
        return search.endswith(suffix)

    @builtin_function({'types': ['string']}, {'types': ['string']})
    def _func_starts_with(self, search, suffix):
        return search.startswith(suffix)

    @builtin_function({'types': ['array', 'string']})
    def _func_reverse(self, arg):
        if isinstance(arg, STRING_TYPE):
            return arg[::-1]
        else:
            return list(reversed(arg))

    @builtin_function({"types": ['number']})
    def _func_ceil(self, arg):
        return math.ceil(arg)

    @builtin_function({"types": ['number']})
    def _func_floor(self, arg):
        return math.floor(arg)

    @builtin_function({"types": ['string']}, {"types": ['array-string']})
    def _func_join(self, separator, array):
        return separator.join(array)

    @builtin_function({'types': ['expref']}, {'types': ['array']})
    def _func_map(self, expref, arg):
        result = []
        for element in arg:
            result.append(self.interpreter.visit(expref.expression, element))
        return result

    @builtin_function({"types": ['array-number', 'array-string']})
    def _func_max(self, arg):
        if arg:
            return max(arg)
        else:
            return None

    @builtin_function({"types": ["object"], "variadic": True})
    def _func_merge(self, *arguments):
        merged = {}
        for arg in arguments:
            merged.update(arg)
        return merged

    @builtin_function({"types": ['array-number', 'array-string']})
    def _func_min(self, arg):
        if arg:
            return min(arg)
        else:
            return None

    @builtin_function({"types": ['array-string', 'array-number']})
    def _func_sort(self, arg):
        return list(sorted(arg))

    @builtin_function({"types": ['array-number']})
    def _func_sum(self, arg):
        return sum(arg)

    @builtin_function({"types": ['object']})
    def _func_keys(self, arg):
        # To be consistent with .values()
        # should we also return the indices of a list?
        return list(arg.keys())

    @builtin_function({"types": ['object']})
    def _func_values(self, arg):
        return list(arg.values())

    @builtin_function({'types': []})
    def _func_type(self, arg):
        if isinstance(arg, STRING_TYPE):
            return "string"
        elif isinstance(arg, bool):
            return "boolean"
        elif isinstance(arg, list):
            return "array"
        elif isinstance(arg, dict):
            return "object"
        elif isinstance(arg, (float, int)):
            return "number"
        elif arg is None:
            return "null"

    @builtin_function({'types': ['array']}, {'types': ['expref']})
    def _func_sort_by(self, array, expref):
        if not array:
            return array
        # sort_by allows for the expref to be either a number of
        # a string, so we have some special logic to handle this.
        # We evaluate the first array element and verify that it's
        # either a string of a number.  We then create a key function
        # that validates that type, which requires that remaining array
        # elements resolve to the same type as the first element.
        required_type = self._convert_to_jmespath_type(
            type(self.interpreter.visit(expref.expression, array[0])).__name__)
        if required_type not in ['number', 'string']:
            raise exceptions.JMESPathTypeError(
                'sort_by', array[0], required_type, ['string', 'number'])
        keyfunc = self._create_key_func(expref.expression,
                                        [required_type],
                                        'sort_by')
        return list(sorted(array, key=keyfunc))

    @builtin_function({'types': ['array']}, {'types': ['expref']})
    def _func_min_by(self, array, expref):
        keyfunc = self._create_key_func(expref.expression,
                                        ['number', 'string'],
                                        'min_by')
        return min(array, key=keyfunc)

    @builtin_function({'types': ['array']}, {'types': ['expref']})
    def _func_max_by(self, array, expref):
        keyfunc = self._create_key_func(expref.expression,
                                        ['number', 'string'],
                                        'min_by')
        return max(array, key=keyfunc)

    def _create_key_func(self, expr_node, allowed_types, function_name):
        interpreter = self.interpreter

        def keyfunc(x):
            result = interpreter.visit(expr_node, x)
            actual_typename = type(result).__name__
            jmespath_type = self._convert_to_jmespath_type(actual_typename)
            # allowed_types is in term of jmespath types, not python types.
            if jmespath_type not in allowed_types:
                raise exceptions.JMESPathTypeError(
                    function_name, result, jmespath_type, allowed_types)
            return result
        return keyfunc

    def _convert_to_jmespath_type(self, pyobject):
        return TYPES_MAP.get(pyobject, 'unknown')
