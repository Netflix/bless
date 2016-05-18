import pytest
from bless.ssh.protocol.ssh_protocol import pack_ssh_mpint, _hex_characters_length, \
    pack_ssh_uint32, pack_ssh_uint64, pack_ssh_string


def test_strings():
    strings = {'': '00000000'.decode('hex'), u'abc': '00000003616263'.decode('hex'),
               b'1234': '0000000431323334'.decode('hex'), '1234': '0000000431323334'.decode('hex')}

    for known_input, known_answer in strings.iteritems():
        assert known_answer == pack_ssh_string(known_input)


def test_mpint_known_answers():
    # mipint values are from https://www.ietf.org/rfc/rfc4251.txt
    mpints = {long(0): '00000000'.decode('hex'),
              long(0x9a378f9b2e332a7): '0000000809a378f9b2e332a7'.decode('hex'),
              long(0x80): '000000020080'.decode('hex'), long(-0x1234): '00000002edcc'.decode('hex'),
              long(-0xdeadbeef): '00000005ff21524111'.decode('hex')}
    for known_input, known_answer in mpints.iteritems():
        assert known_answer == pack_ssh_mpint(known_input)


def test_mpints():
    mpints = {long(-1): '00000001ff'.decode('hex'), long(1): '0000000101'.decode('hex'),
              long(127): '000000017f'.decode('hex'), long(128): '000000020080'.decode('hex'),
              long(-128): '0000000180'.decode('hex'), long(-129): '00000002ff7f'.decode('hex'),
              long(255): '0000000200ff'.decode('hex'), long(256): '000000020100'.decode('hex'),
              long(-256): '00000002ff00'.decode('hex'), long(-257): '00000002feff'.decode('hex')}
    for known_input, known_answer in mpints.iteritems():
        assert known_answer == pack_ssh_mpint(known_input)


def test_hex_characters_length():
    digits = {0: 0, 1: 2, 64: 2, 127: 2, 128: 4, 16384: 4, 32767: 4, 32768: 6, -1: 2,
              long(-0x1234): 4, long(-0xdeadbeef): 10, -128: 2}
    for known_input, known_answer in digits.iteritems():
        assert known_answer == _hex_characters_length(known_input)


def test_uint32():
    uint32s = {0x00: '00000000'.decode('hex'), 0x0a: '0000000a'.decode('hex'),
               0xab: '000000ab'.decode('hex'), 0xabcd: '0000abcd'.decode('hex'),
               0xabcdef: '00abcdef'.decode('hex'), 0xffffffff: 'ffffffff'.decode('hex'),
               0xf0f0f0f0: 'f0f0f0f0'.decode('hex'), 0x0f0f0f0f: '0f0f0f0f'.decode('hex')}

    for known_input, known_answer in uint32s.iteritems():
        assert known_answer == pack_ssh_uint32(known_input)


def test_uint64():
    uint64s = {0x00: '0000000000000000'.decode('hex'), 0x0a: '000000000000000a'.decode('hex'),
               0xab: '00000000000000ab'.decode('hex'), 0xabcd: '000000000000abcd'.decode('hex'),
               0xabcdef: '0000000000abcdef'.decode('hex'),
               0xffffffff: '00000000ffffffff'.decode('hex'),
               0xf0f0f0f0: '00000000f0f0f0f0'.decode('hex'),
               0x0f0f0f0f: '000000000f0f0f0f'.decode('hex'),
               0xf0f0f0f000000000: 'f0f0f0f000000000'.decode('hex'),
               0x0f0f0f0f00000000: '0f0f0f0f00000000'.decode('hex'),
               0xffffffffffffffff: 'ffffffffffffffff'.decode('hex')}

    for known_input, known_answer in uint64s.iteritems():
        assert known_answer == pack_ssh_uint64(known_input)


def test_floats():
    with pytest.raises(TypeError):
        pack_ssh_uint64(4.2)

    with pytest.raises(TypeError):
        pack_ssh_uint32(4.2)


def test_uint_too_long():
    with pytest.raises(ValueError):
        pack_ssh_uint64(0x1FFFFFFFFFFFFFFFF)

    with pytest.raises(ValueError):
        pack_ssh_uint32(long(0x1FFFFFFFF))

    with pytest.raises(ValueError):
        pack_ssh_uint32(int(0x1FFFFFFFF))
