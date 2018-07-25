import binascii
import pytest
from bless.ssh.protocol.ssh_protocol import pack_ssh_mpint, _hex_characters_length, \
    pack_ssh_uint32, pack_ssh_uint64, pack_ssh_string


def test_strings():
    strings = {'': binascii.unhexlify('00000000'), 'abc': binascii.unhexlify('00000003616263'),
               b'1234': binascii.unhexlify('0000000431323334'), '1234': binascii.unhexlify('0000000431323334')}

    for known_input, known_answer in strings.items():
        assert known_answer == pack_ssh_string(known_input)


def test_mpint_known_answers():
    # mipint values are from https://www.ietf.org/rfc/rfc4251.txt
    mpints = {int(0): binascii.unhexlify('00000000'),
              int(0x9a378f9b2e332a7): binascii.unhexlify('0000000809a378f9b2e332a7'),
              int(0x80): binascii.unhexlify('000000020080'), int(-0x1234): binascii.unhexlify('00000002edcc'),
              int(-0xdeadbeef): binascii.unhexlify('00000005ff21524111')}
    for known_input, known_answer in mpints.items():
        assert known_answer == pack_ssh_mpint(known_input)


def test_mpints():
    mpints = {int(-1): binascii.unhexlify('00000001ff'), int(1): binascii.unhexlify('0000000101'),
              int(127): binascii.unhexlify('000000017f'), int(128): binascii.unhexlify('000000020080'),
              int(-128): binascii.unhexlify('0000000180'), int(-129): binascii.unhexlify('00000002ff7f'),
              int(255): binascii.unhexlify('0000000200ff'), int(256): binascii.unhexlify('000000020100'),
              int(-256): binascii.unhexlify('00000002ff00'), int(-257): binascii.unhexlify('00000002feff')}
    for known_input, known_answer in mpints.items():
        assert known_answer == pack_ssh_mpint(known_input)


def test_hex_characters_length():
    digits = {0: 0, 1: 2, 64: 2, 127: 2, 128: 4, 16384: 4, 32767: 4, 32768: 6, -1: 2,
              int(-0x1234): 4, int(-0xdeadbeef): 10, -128: 2}
    for known_input, known_answer in digits.items():
        assert known_answer == _hex_characters_length(known_input)


def test_uint32():
    uint32s = {0x00: binascii.unhexlify('00000000'), 0x0a: binascii.unhexlify('0000000a'),
               0xab: binascii.unhexlify('000000ab'), 0xabcd: binascii.unhexlify('0000abcd'),
               0xabcdef: binascii.unhexlify('00abcdef'), 0xffffffff: binascii.unhexlify('ffffffff'),
               0xf0f0f0f0: binascii.unhexlify('f0f0f0f0'), 0x0f0f0f0f: binascii.unhexlify('0f0f0f0f')}

    for known_input, known_answer in uint32s.items():
        assert known_answer == pack_ssh_uint32(known_input)


def test_uint64():
    uint64s = {0x00: binascii.unhexlify('0000000000000000'), 0x0a: binascii.unhexlify('000000000000000a'),
               0xab: binascii.unhexlify('00000000000000ab'), 0xabcd: binascii.unhexlify('000000000000abcd'),
               0xabcdef: binascii.unhexlify('0000000000abcdef'),
               0xffffffff: binascii.unhexlify('00000000ffffffff'),
               0xf0f0f0f0: binascii.unhexlify('00000000f0f0f0f0'),
               0x0f0f0f0f: binascii.unhexlify('000000000f0f0f0f'),
               0xf0f0f0f000000000: binascii.unhexlify('f0f0f0f000000000'),
               0x0f0f0f0f00000000: binascii.unhexlify('0f0f0f0f00000000'),
               0xffffffffffffffff: binascii.unhexlify('ffffffffffffffff')}

    for known_input, known_answer in uint64s.items():
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
        pack_ssh_uint32(int(0x1FFFFFFFF))

    with pytest.raises(ValueError):
        pack_ssh_uint32(int(0x1FFFFFFFF))
