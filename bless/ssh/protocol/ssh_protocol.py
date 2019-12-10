"""
.. module: bless.ssh.protocol.ssh_protocol
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
import binascii
import struct


def pack_ssh_mpint(mpint):
    """
    Packs multiple precision integers.
    See Section 5 of https://www.ietf.org/rfc/rfc4251.txt for more information.
    :param mpint: Signed long or int to pack.
    :return: An SSH string containing the mpint in two's complement format.
    """
    if mpint != 0:
        hex_digits = _hex_characters_length(mpint)
        format_string = "0{:d}x".format(hex_digits)

        # Take the 2's complement of negative numbers.
        # If it was needed, this will result in a leading 0xFF
        if mpint < 0:
            # hex_digits * 4 = number of bits.
            mpint += 1 << (hex_digits * 4)

        # If the results needed an extra byte of padding, this will provide a leading 0x00
        hex_mpint = format(mpint, format_string)
        bytes = binascii.unhexlify(hex_mpint)
    else:
        # Per RFC4251 a 0 value mpint results in a null string.
        bytes = ''

    ret = pack_ssh_string(bytes)

    return ret


def pack_ssh_string(string):
    """
    Packs arbitrary length binary strings.
    See Section 5 of https://www.ietf.org/rfc/rfc4251.txt for more information.
    :param string: String or Unicode string.  Unicode is encoded as utf-8.
    :return: An SSH String stored as a unint32 representing the length of the input string,
    followed by that many bytes.
    """
    if isinstance(string, str):
        string = string.encode('utf-8')

    str_len = len(string)

    if len(string) > 4294967295:
        raise ValueError("String must be less than 2^32 bytes long.")

    return struct.pack('>I{}s'.format(str_len), str_len, string)


def pack_ssh_uint64(i):
    """
    Packs a 64-bit unsigned integer.
    :param i: integer
    :return: Eight bytes in the order of decreasing significance (network byte order).
    """
    if not isinstance(i, int):
        raise TypeError("Must be an int")
    elif i.bit_length() > 64:
        raise ValueError("Must be a 64bit value.")

    return struct.pack('>Q', i)


def pack_ssh_uint32(i):
    """
    Packs a 32-bit unsigned integer.
    :param i: integer or long.
    :return: Four bytes in the order of decreasing significance (network byte order).
    """
    if not isinstance(i, int):
        raise TypeError("Must be an int")
    elif i.bit_length() > 32:
        raise ValueError("Must be a 32bit value.")

    return struct.pack('>I', i)


def _hex_characters_length(mpint):
    """
    Subroutine for pack_ssh_mpint.
    :param mpint: Signed long or int to pack.
    :return: The number of hex characters needed to represent a multiple precision integer.
    """
    if mpint == 0:
        return 0

    # how many bytes?
    num_bits = mpint.bit_length()
    num_bytes = num_bits // 8

    # if there are remaining bits, we need an extra byte
    if num_bits % 8:
        num_bytes += 1

    # What is the highest bit in the highest byte?
    shift = (num_bytes * 8) - 1
    mask = 1 << shift

    if mpint > 0:
        if mpint & mask:
            # if the mpint is positive, and the MSB of the highest byte is set,
            # pack_ssh_mpint will need to pad with a leading 0x00
            num_bytes += 1
    else:
        if not mpint & mask:
            # if the mpint is negative, and the MSB of the highest byte is not set,
            # pack_ssh_mpint will need pad with a leading 0xFF
            num_bytes += 1

    return num_bytes * 2
