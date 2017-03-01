import pytest
from bless.request.bless_request import validate_ip, validate_user
from marshmallow import ValidationError


@pytest.mark.parametrize("test_input", [
    (u'127.0.0.1'),
    (u'192.168.0.0/24'),
    (u','.join([u'127.0.0.1', u'10.10.255.0/24']))
])
def test_validate_ip(test_input):
    validate_ip(test_input)


@pytest.mark.parametrize("test_input", [
    (u'256.0.0.0'),
    (u'127.0.0.1/24'),
    (u'127.0.0.1,256.0.0.0'),
    (u'127.0.0.1;10.10.255.0/24')
])
def test_validate_ip_contains_invalid_ips(test_input):
    with pytest.raises(ValidationError) as e:
        validate_ip(test_input)
    assert e.value.message == 'Invalid IP address.'


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