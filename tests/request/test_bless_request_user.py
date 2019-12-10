import pytest
from bless.config.bless_config import USERNAME_VALIDATION_OPTION, REMOTE_USERNAMES_VALIDATION_OPTION, \
    REMOTE_USERNAMES_BLACKLIST_OPTION
from bless.request.bless_request_user import validate_ips, validate_user, USERNAME_VALIDATION_OPTIONS, BlessUserSchema
from marshmallow import ValidationError


def test_validate_ips():
    validate_ips('127.0.0.1')
    with pytest.raises(ValidationError):
        validate_ips('256.0.0.0')
    validate_ips('127.0.0.1,172.1.1.1')
    with pytest.raises(ValidationError):
        validate_ips('256.0.0.0,172.1.1.1')


def test_validate_ips_cidr():
    validate_ips('10.0.0.0/8,172.1.1.1')
    with pytest.raises(ValidationError):
        validate_ips('10.10.10.10/8')


def test_validate_user_too_long():
    with pytest.raises(ValidationError) as e:
        validate_user('a33characterusernameyoumustbenuts', USERNAME_VALIDATION_OPTIONS.useradd)
    assert str(e.value) == 'Username is too long.'


@pytest.mark.parametrize("test_input", [
    ('user#invalid'),
    ('$userinvalid'),
    ('userinvali$d'),
    ('userin&valid'),
    (' userinvalid')
])
def test_validate_user_contains_junk(test_input):
    with pytest.raises(ValidationError) as e:
        validate_user(test_input, USERNAME_VALIDATION_OPTIONS.useradd)
    assert str(e.value) == 'Username contains invalid characters.'


@pytest.mark.parametrize("test_input", [
    ('uservalid'),
    ('a32characterusernameyoumustok$'),
    ('_uservalid$'),
    ('abc123_-valid')
])
def test_validate_user(test_input):
    validate_user(test_input, USERNAME_VALIDATION_OPTIONS.useradd)


def test_validate_user_debian_too_long():
    with pytest.raises(ValidationError) as e:
        validate_user('a33characterusernameyoumustbenuts', USERNAME_VALIDATION_OPTIONS.debian)
    assert str(e.value) == 'Username is too long.'


@pytest.mark.parametrize("test_input", [
    ('~userinvalid'),
    ('-userinvalid'),
    ('+userinvalid'),
    ('user:invalid'),
    ('user,invalid'),
    ('user invalid'),
    ('user\tinvalid'),
    ('user\ninvalid')
])
def test_validate_user_debian_invalid(test_input):
    with pytest.raises(ValidationError) as e:
        validate_user(test_input, USERNAME_VALIDATION_OPTIONS.debian)
    assert str(e.value) == 'Username contains invalid characters.'


@pytest.mark.parametrize("test_input", [
    ('root'),
    ("admin"),
    ("administrator"),
    ('balrog'),
    ("teal'c")
])
def test_validate_user_blacklist(test_input):
    with pytest.raises(ValidationError) as e:
        validate_user(test_input, USERNAME_VALIDATION_OPTIONS.principal, 'root|admin.*|balrog|.+\'.*')
    assert str(e.value) == 'Username contains invalid characters.'


@pytest.mark.parametrize("test_input", [
    ('uservalid'),
    ('a32characterusernameyoumustok$'),
    ('_uservalid$'),
    ('abc123_-valid'),
    ('user~valid'),
    ('user-valid'),
    ('user+valid'),
])
def test_validate_user_debian(test_input):
    validate_user(test_input, USERNAME_VALIDATION_OPTIONS.debian)


@pytest.mark.parametrize("test_input", [
    ('uservalid'),
    ('a32characterusernameyoumustok$'),
    ('!"$%&\'()*+-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~')
])
def test_validate_user_principal(test_input):
    validate_user(test_input, USERNAME_VALIDATION_OPTIONS.principal)


@pytest.mark.parametrize("test_input", [
    ('a33characterusernameyoumustbenuts@example.com'),
    ('a@example.com'),
    ('a+b@example.com')
])
def test_validate_user_email(test_input):
    validate_user(test_input, USERNAME_VALIDATION_OPTIONS.email)


@pytest.mark.parametrize("test_input", [
    ('a33characterusernameyoumustbenuts@ex@mple.com'),
    ('a@example'),
])
def test_invalid_user_email(test_input):
    with pytest.raises(ValidationError) as e:
        validate_user(test_input, USERNAME_VALIDATION_OPTIONS.email)
    assert str(e.value) == 'Invalid email address.'


@pytest.mark.parametrize("test_input", [
    ('a33characterusernameyoumustbenuts'),
    ('~:, \n\t@'),
    ('uservalid,!"$%&\'()*+-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~,'),
])
def test_validate_user_disabled(test_input):
    validate_user(test_input, USERNAME_VALIDATION_OPTIONS.disabled)


@pytest.mark.parametrize("test_input", [
    ('uservalid'),
    ('uservalid,uservalid2'),
    ('uservalid,!"$%&\'()*+-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~,'
     'uservalid2')
])
def test_validate_multiple_principals(test_input):
    BlessUserSchema().validate_remote_usernames(test_input)

    schema = BlessUserSchema()
    schema.context[USERNAME_VALIDATION_OPTION] = USERNAME_VALIDATION_OPTIONS.principal.name
    schema.context[REMOTE_USERNAMES_VALIDATION_OPTION] = USERNAME_VALIDATION_OPTIONS.principal.name
    schema.context[REMOTE_USERNAMES_BLACKLIST_OPTION] = 'balrog'
    schema.validate_remote_usernames(test_input)


@pytest.mark.parametrize("test_input", [
    ('user invalid'),
    ('uservalid,us#erinvalid2'),
    ('uservalid,,uservalid2'),
    (' uservalid'),
    ('user\ninvalid'),
    ('~:, \n\t@')
])
def test_invalid_multiple_principals(test_input):
    with pytest.raises(ValidationError) as e:
        BlessUserSchema().validate_remote_usernames(test_input)
    assert str(e.value) == 'Principal contains invalid characters.'


def test_invalid_user_with_default_context_of_useradd():
    with pytest.raises(ValidationError) as e:
        BlessUserSchema().validate_bastion_user('user#invalid')
    assert str(e.value) == 'Username contains invalid characters.'


def test_invalid_call_of_validate_user():
    with pytest.raises(ValidationError) as e:
        validate_user('test', None)
    assert str(e.value) == 'Invalid username validator.'
