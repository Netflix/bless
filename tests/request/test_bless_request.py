import pytest
from bless.request.bless_request import validate_ips, validate_user
from marshmallow import ValidationError


def test_validate_ips():
    validate_ips(u'127.0.0.1')
    with pytest.raises(ValidationError):
        validate_ips(u'256.0.0.0')
    validate_ips(u'127.0.0.1,172.1.1.1')
    with pytest.raises(ValidationError):
        validate_ips(u'256.0.0.0,172.1.1.1')


def test_validate_user_too_long():
    with pytest.raises(ValidationError) as e:
        validate_user('a33characterusernameyoumustbenuts')
    assert e.value.message == 'Username is too long'


@pytest.mark.parametrize("test_input", [
    ('user#invalid'),
    ('$userinvalid'),
    ('userinvali$d'),
    ('userin&valid')
])
def test_validate_user_contains_junk(test_input):
    with pytest.raises(ValidationError) as e:
        validate_user(test_input)
    assert e.value.message == 'Username contains invalid characters'


@pytest.mark.parametrize("test_input", [
    ('uservalid'),
    ('a32characterusernameyoumustok$'),
    ('_uservalid$'),
    ('abc123_-valid')
])
def test_validate_user(test_input):
    validate_user(test_input)
