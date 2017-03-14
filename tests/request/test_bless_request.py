import pytest
from bless.request.bless_request import validate_ips, validate_user, validate_principals, set_username_validation, USERNAME_VALIDATION_OPTIONS
from marshmallow import ValidationError


def test_validate_ips():
    validate_ips(u'127.0.0.1')
    with pytest.raises(ValidationError):
        validate_ips(u'256.0.0.0')
    validate_ips(u'127.0.0.1,172.1.1.1')
    with pytest.raises(ValidationError):
        validate_ips(u'256.0.0.0,172.1.1.1')


def test_validate_ips_cidr():
    validate_ips(u'10.0.0.0/8,172.1.1.1')
    with pytest.raises(ValidationError):
        validate_ips(u'10.10.10.10/8')


def test_validate_user_too_long():
    with pytest.raises(ValidationError) as e:
        validate_user('a33characterusernameyoumustbenuts')
    assert e.value.message == 'Username is too long.'


@pytest.mark.parametrize("test_input", [
    ('user#invalid'),
    ('$userinvalid'),
    ('userinvali$d'),
    ('userin&valid'),
    (' userinvalid')
])
def test_validate_user_contains_junk(test_input):
    with pytest.raises(ValidationError) as e:
        validate_user(test_input)
    assert e.value.message == 'Username contains invalid characters.'


@pytest.mark.parametrize("test_input", [
    ('uservalid'),
    ('a32characterusernameyoumustok$'),
    ('_uservalid$'),
    ('abc123_-valid')
])
def test_validate_user(test_input):
    validate_user(test_input)


def test_validate_user_debian_too_long(monkeypatch):
    monkeypatch.setattr('bless.request.bless_request.username_validation', USERNAME_VALIDATION_OPTIONS.debian)
    with pytest.raises(ValidationError) as e:
        validate_user('a33characterusernameyoumustbenuts')
    assert e.value.message == 'Username is too long.'


@pytest.mark.parametrize("test_input", [
    ('~userinvalid'),
    ('-userinvalid'),
    ('+userinvalid'),
    ('user:invalid'),
    ('user,invalid'),
    ('user invalid'),
    ('user\tinvalid'),
    ('user\ninvalid'),
])
def test_validate_user_debian_invalid(test_input, monkeypatch):
    monkeypatch.setattr('bless.request.bless_request.username_validation', USERNAME_VALIDATION_OPTIONS.debian)
    with pytest.raises(ValidationError) as e:
        validate_user(test_input)
    assert e.value.message == 'Username contains invalid characters.'


@pytest.mark.parametrize("test_input", [
    ('uservalid'),
    ('a32characterusernameyoumustok$'),
    ('_uservalid$'),
    ('abc123_-valid'),
    ('user~valid'),
    ('user-valid'),
    ('user+valid'),
])
def test_validate_user_debian(test_input, monkeypatch):
    monkeypatch.setattr('bless.request.bless_request.username_validation', USERNAME_VALIDATION_OPTIONS.debian)
    validate_user(test_input)


def test_validate_user_relaxed_too_long(monkeypatch):
    monkeypatch.setattr('bless.request.bless_request.username_validation', USERNAME_VALIDATION_OPTIONS.relaxed)
    with pytest.raises(ValidationError) as e:
        validate_user('a33characterusernameyoumustbenuts')
    assert e.value.message == 'Username is too long.'


@pytest.mark.parametrize("test_input", [
    ('uservalid'),
    ('a32characterusernameyoumustok$'),
    ('_uservalid$'),
    ('abc123_-valid'),
    ('user~valid'),
    ('user-valid'),
    ('user+valid'),
    ('~uservalid'),
    ('-uservalid'),
    ('+uservalid'),
    ('user:valid'),
    ('user,valid'),
    ('user valid'),
    ('user\tvalid'),
    ('user\nvalid'),
])
def test_validate_user_relaxed(test_input, monkeypatch):
    monkeypatch.setattr('bless.request.bless_request.username_validation', USERNAME_VALIDATION_OPTIONS.relaxed)
    validate_user(test_input)


@pytest.mark.parametrize("test_input", [
    ('a33characterusernameyoumustbenuts'),
    ('~:, \n\t@')
])
def test_validate_user_disabled(test_input, monkeypatch):
    monkeypatch.setattr('bless.request.bless_request.username_validation', USERNAME_VALIDATION_OPTIONS.disabled)
    validate_user(test_input)


@pytest.mark.parametrize("test_input", [
    ('uservalid'),
    ('uservalid,uservalid2'),
    ('uservalid,!"$%&\'()*+-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~,uservalid2')
])
def test_validate_multiple_principals(test_input):
    validate_principals(test_input)

@pytest.mark.parametrize("test_input", [
    ('user invalid'),
    ('uservalid,us#erinvalid2'),
    ('uservalid,,uservalid2'),
    (' uservalid'),
])
def test_validate_multiple_principals(test_input):
    with pytest.raises(ValidationError) as e:
        validate_principals(test_input)
    assert e.value.message == 'Principal contains invalid characters.'


def test_set_username_validation_invalid():
    with pytest.raises(KeyError) as e:
        set_username_validation('random')


@pytest.mark.parametrize("test_input", [
    ('useradd'),
    ('debian'),
    ('relaxed'),
    ('disabled')
])
def test_set_username_validation(test_input):
    set_username_validation(test_input)
