#!/usr/bin/env python2.6
"""The Data Encryption Standard is a cryptographic standard endorsed by the
United States' National Institute of Standards and Technology.  Its official
description can be found in Federal Information Processing Standards
Publication 46-3.  As of the late 1990s, it is no longer strong enough to
provide secure cryptographic communication."""

from extensions.itertools import reorder as oreorder, strict_slices
from miscellaneous import typecasted_arithmetic
from random import randint
import sys

reorder = lambda sequence, ordering: list(oreorder(sequence, ordering))

#These constants are the same for all DES implementations.
BLOCK_SIZE = 64
INITIAL_PERMUTATION = [57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19,
                       11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39,
                       31, 23, 15, 7, 56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42,
                       34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62,
                       54, 46, 38, 30, 22, 14, 6]
EXPANSION = [31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10, 11, 12, 11, 12,
             13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24,
             23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0]
FINAL_PERMUTATION = [INITIAL_PERMUTATION.index(_i) for _i in xrange(64)]
KEY_PERMUTATION1 = [56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1,
                    58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 62, 54, 46,
                    38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 60, 52,
                    44, 36, 28, 20, 12, 4, 27, 19, 11, 3]
KEY_PERMUTATION2 = [13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3,
                    25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29,
                    39, 50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35,
                    28, 31]
ROUND_PERMUTATION = [15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30,
                     9, 1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3,
                     24]
SBOX = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]
SHIFT_SIZES = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
SUBKEY_LENGTH = 48

def main(argv=None):
    if argv is None:
        argv = sys.argv
    for i in xrange(1000000):
        encipher(randint(0, 2**64 - 1), 0x3b3898371520f75e)

def add_bits(addend, augend):
    """Take the exclusive-or of each item in the given bit sequence."""
    if len(addend) != len(augend):
        raise TypeError("This will be dealt with later.")
    return [bit1 ^ bit2 for bit1, bit2 in zip(addend, augend)]

def bits_to_integer(bits):
    """Convert a sequence of zeros and ones to an integer.  The lowest-indexed
    bit is the most significant."""
    if len(bits) == 0 or set(bits) not in (set([0]), set([1]), set([0, 1])):
        raise TypeError(str(bits) + " is not a valid bit sequence.")
    return sum(bit * 2 ** exp for exp, bit in enumerate(reversed(bits)))

def decipher(blocks, key):
    """Encipher a message with a the given key.  The message must be an
    integer.  The key must be a 64 bit key as defined by the DES standard."""
    old_key = key
    key = integer_to_bits(key, 64)
    if not is_des_key(key):
        raise TypeError("0x%x is not a valid DES key." % old_key)
    keys = reversed(list(round_keys(key)))
    for block in blocks:
        yield bits_to_integer(encipher_block(integer_to_bits(block, BLOCK_SIZE), keys))

def encipher(blocks, key):
    """Encipher a message with a the given key.  The message must be an
    integer.  The key must be a 64 bit key as defined by the DES standard."""
    old_key = key
    key = integer_to_bits(key, 64)
    if not is_des_key(key):
        raise TypeError("0x%x is not a valid DES key." % old_key)
    keys = round_keys(key)
    for block in blocks:
        yield bits_to_integer(encipher_block(integer_to_bits(block, BLOCK_SIZE), keys))

def encipher_block(block, keys):
    """Encipher a 64-bit block of with the given key schedule."""
    if len(block) > BLOCK_SIZE:
        raise TypeError("DES has a block size of 64 bits.")
    block = reorder(block, INITIAL_PERMUTATION)
    for key in keys:
        block = round_(block, key)
    block = rotate_bits(block, BLOCK_SIZE / 2)
    block = reorder(block, FINAL_PERMUTATION)
    return block

def integer_to_bits(integer, min_bits=None):
    """Convert an integer to a sequence of 0 and 1.  The lowest-indexed bit is
    the most significant.  min_bits, if specified, indicates the minimum length
    of the generated list."""
    if integer < 0:
        raise TypeError(str(integer) + " cannot be converted to a bit "
                        "sequence.")
    if integer == 0:
        return pad_bits([0], min_bits)
    bits = []
    while integer > 0:
        bits.insert(0, integer % 2)
        integer //= 2
    return pad_bits(bits, min_bits)

def is_des_key(key):
    """Determine if the given key is a valid DES key.  Every eighth bit should
    be a parity bit.  Each byte of the key must have an even number of 'on' bits."""
    if len(key) != BLOCK_SIZE:
        return False
    return all(byte.count(0) % 2 == 1 for byte in strict_slices(key, 8))

def pad_bits(bits, min_bits=None):
    """Pad a sequence of zeroes and ones to a minimum length of min_bits by
    appending zeroes to the front of the list."""
    if min_bits > len(bits):
        return [0] * (min_bits - len(bits)) + bits
    return bits

def rotate_bits(bits, size):
    """Rotate a sequence of bits by a specified number of steps."""
    return bits[size:] + bits[:size]

def round_(block, key):
    """Perform one round of DES on the given block, using the given round
    key."""
    left, right = block[:BLOCK_SIZE / 2], block[BLOCK_SIZE / 2:]
    temp = reorder(right, EXPANSION)
    temp = add_bits(temp, key)
    temp = sbox(temp)
    temp = reorder(temp, ROUND_PERMUTATION)
    temp = add_bits(temp, left)
    return right + temp

def round_keys(key):
    """Generate a list of round keys from the given cipher key."""
    key = reorder(key, KEY_PERMUTATION1)
    left, right = key[:28], key[28:]
    for shift in SHIFT_SIZES:
        left, right = rotate_bits(left, shift), rotate_bits(right, shift)
        round_key = reorder(left + right, KEY_PERMUTATION2)
        yield round_key

def sbox(block):
    """Apply the DES substitution table, or S-box, to a block."""
    new_block = []
    for i in xrange(8):
        slice_ = block[i*6:(i+1)*6]
        new_block.extend(substitute(slice_, i))
    return new_block

def substitute(slice_, slice_index):
    """Substitute a 4 bit integer for a six bit one using the DES substitution
    table."""
    row = slice_[0] * 2 + slice_[-1]
    column = bits_to_integer(slice_[1:-1])
    return integer_to_bits(SBOX[slice_index][row][column], 4)

if __name__ == "__main__":
    sys.exit(main())

#******************************************************************************
#********************************* UNIT TESTS *********************************
#******************************************************************************

from py.test import raises

def test_add_bits():
    assert [0, 0, 0, 0] == add_bits([0, 0, 0, 0], [0, 0, 0, 0])
    assert [0, 0, 0, 0] == add_bits([1, 1, 1, 1], [1, 1, 1, 1])
    assert [1, 1, 0, 1] == add_bits([1, 0, 1, 1], [0, 1, 1, 0])

def test_bits_to_integer():
    assert 0 == bits_to_integer([0])
    assert 1 == bits_to_integer([1])
    assert 0b10 == bits_to_integer([1, 0])
    assert 0b11 == bits_to_integer([1, 1])
    assert 0b100 == bits_to_integer([1, 0, 0])
    assert 0b101 == bits_to_integer([1, 0, 1])
    assert 0b110 == bits_to_integer([1, 1, 0])
    assert 0b111 == bits_to_integer([1, 1, 1])
    assert 0b1000 == bits_to_integer([1, 0, 0, 0])
    assert 0b1001 == bits_to_integer([1, 0, 0, 1])
    assert 0b1010 == bits_to_integer([1, 0, 1, 0])
    assert 0b1011 == bits_to_integer([1, 0, 1, 1])
    assert 0b1100 == bits_to_integer([1, 1, 0, 0])
    assert 0b1101 == bits_to_integer([1, 1, 0, 1])
    assert 0b1110 == bits_to_integer([1, 1, 1, 0])
    assert 0b1111 == bits_to_integer([1, 1, 1, 1])
    raises(TypeError, bits_to_integer, [[]])
    raises(TypeError, bits_to_integer, [-1])
    raises(TypeError, bits_to_integer, [1, 0, 1, 0, 2])
    raises(TypeError, bits_to_integer, [1, 0, 1, 0, -1])

def test_decipher():
    ceiling = 2 ** 64 - 1
    key = 0x3b3898371520f75e
    print "%x", ceiling
    for i in xrange(50):
        message = [randint(0, ceiling)]
        assert message == list(decipher(encipher(message, key), key))

def test_encipher():
    message = [0x123456789abcdef]
    ciphertext = [0xaa39b9777efc3c14]
    key = 0x3b3898371520f75e
    assert ciphertext == list(encipher(message, key))
    raises(TypeError, encipher, [22, 0])

def test_encipher_block():
    message = integer_to_bits(0x123456789abcdef, 64)
    ciphertext = integer_to_bits(0xaa39b9777efc3c14, 64)
    key = integer_to_bits(0x3b3898371520f75e, 64)
    assert ciphertext == encipher_block(message, round_keys(key))

def test_final_permuation():
    permuted = list(reorder(range(64), INITIAL_PERMUTATION))
    assert range(64) == list(reorder(permuted, FINAL_PERMUTATION))

def test_integer_to_bits():
    assert [0] == integer_to_bits(0)
    assert [1] == integer_to_bits(1)
    assert [1, 0] == integer_to_bits(0b10)
    assert [1, 1] == integer_to_bits(0b11)
    assert [1, 0, 0] == integer_to_bits(0b100)
    assert [1, 0, 1] == integer_to_bits(0b101)
    assert [1, 1, 0] == integer_to_bits(0b110)
    assert [1, 1, 1] == integer_to_bits(0b111)
    assert [1, 0, 0, 0] == integer_to_bits(0b1000)
    assert [1, 0, 0, 1] == integer_to_bits(0b1001)
    assert [1, 0, 1, 0] == integer_to_bits(0b1010)
    assert [1, 0, 1, 1] == integer_to_bits(0b1011)
    assert [1, 1, 0, 0] == integer_to_bits(0b1100)
    assert [1, 1, 0, 1] == integer_to_bits(0b1101)
    assert [1, 1, 1, 0] == integer_to_bits(0b1110)
    assert [1, 1, 1, 1] == integer_to_bits(0b1111)
    raises(TypeError, integer_to_bits, [-1])

def test_is_des_key():
    isd = lambda key: is_des_key(integer_to_bits(key, 64))
    assert not isd(0xfffffffffffffffffffff)
    assert isd(0x1313131313131313)
    assert not isd(0x13131313ff131313)
    assert not isd(0xff131313ff131313)
    assert not isd(0)
    assert not isd(0xffffffffffffffff)
    assert not isd(0x0f0f0f0f0f0f0f0f)
    assert not isd(0x5555555555555555)
    assert not isd(0x550faa550faa550f)
    assert not isd(0x4555555555555555)

def test_pad_bits():
    for i in xrange(256):
        assert 8 == len(integer_to_bits(i, 8))

def test_rotate_bits():
    start = [0, 0, 1, 1, 1, 0]
    assert start == rotate_bits(start, 0)
    assert [0, 1, 1, 1, 0, 0] == rotate_bits(start, 1)
    assert [1, 1, 1, 0, 0, 0] == rotate_bits(start, 2)

def test_round():
    r = lambda block, key: bits_to_integer(round_(integer_to_bits(block, 64), integer_to_bits(key, 48)))
    assert 0xa7ce3b83ff31aa89 == r(0xa7ce3b83, 0x81bdf785afaf)
    assert 0xaa4aa9cbc85235ca == r(0xaa4aa9cb, 0xce891ee38623)
    assert 0x262d7d5f8b903a1a == r(0x262d7d5f, 0xcc9acc326cd6)
    assert 0x4592a6cba9834b4e == r(0x4592a6cb, 0x6de3948c885a)
    assert 0x6fe0c5946d614835 == r(0x6fe0c594, 0x44dabcbc111e)
    assert 0xc56b9352ee9ff1d0 == r(0xc56b9352, 0x374379564cac)
    assert 0x115b56399aa889ed == r(0x115b5639, 0xd1023aab4db7)
    assert 0x8473fe7d3138f417 == r(0x8473fe7d, 0xae97d484084c)
    assert 0xaa23aa4a049a641c == r(0xaa23aa4a, 0x2b8a229b2f57)
    assert 0x8dcf540610e3a522 == r(0x8dcf5406, 0xb8880bc14130)
    assert 0xbeaca0c2f579fb55 == r(0xbeaca0c2, 0x1349a999f9c4)
    assert 0x23d765f33ffc2507 == r(0x23d765f3, 0xfb58941bada1)
    assert 0x40348024df5885cd == r(0x40348024, 0xa1edb11e7cf6)
    assert 0x29022149d0813f4a == r(0x29022149, 0x599e465fdc34)
    assert 0x3fa9fa9dd428a2bc == r(0x3fa9fa9d, 0x6b008aeb39b5)
    assert 0xe26811521dd29eae == r(0xe2681152, 0xf5713254e7a6)
    assert 0xe5d5982a996c4165 == r(0xe5d5982a, 0x9d0d6ed31604)
    assert 0x8db9ef5fe6b8aa8c == r(0x8db9ef5f, 0xe0502a917f99)
    assert 0x90b8179105aa91cb == r(0x90b81791, 0x3654d823efa1)
    assert 0xbd9e984f9972c14 == r(0xbd9e984, 0x3e1ce35fa11f)

def test_round_keys():
    lrks = lambda key: [bits_to_integer(subkey) for subkey in round_keys(integer_to_bits(key, 64))]
    keys = [101190710169423, 89257748502476, 234077963203823,
            91839393619625, 114970488110459, 195165170948400,
            176208327307122, 198028946147868, 38333700081276,
            114767295004548, 41528461911741, 78072631752839,
            210593280057787, 34233215564615, 63860207158258,
            19226452025678]
    assert keys == lrks(0x3b3898371520f75e)
    keys = [41922922417150, 1036527330690, 5829410170701, 109270980555470,
            168798681618347, 89071642623083, 58894821817200, 19828894199674,
            70567684628317, 76948711379964, 73279705571233, 132783802035773,
            247944351283612, 35745253389243, 58377513678887, 70760798077783]
    assert keys == lrks(0x922fb510c71f436e)

def test_sbox():
    lsbox = lambda value: bits_to_integer(sbox(integer_to_bits(value, 48)))
    assert 0x394dc2c0 == lsbox(0x43f2ee0a8a30)
    assert 0xc2be0e9 == lsbox(0x718d2afb2b92)
    assert 0xb768bac8 == lsbox(0xcf523c86f5c4)
    assert 0x1996782b == lsbox(0xb5b1ca22a122)
    assert 0x7a764735 == lsbox(0x15e589ef7abc)
    assert 0xceb8d205 == lsbox(0xc866ef6070d3)
    assert 0xdcffef32 == lsbox(0x358cf072da82)
    assert 0x11ee263c == lsbox(0x195f0400cab3)
    assert 0xe5ca7cab == lsbox(0x93b50e2ecb4c)
    assert 0x8303eb54 == lsbox(0x98c16107c54f)
    assert 0x9632350d == lsbox(0x67629265cd76)
    assert 0x1425643a == lsbox(0x185d16396f6b)
    assert 0xf044885c == lsbox(0x2b9c7eb8eeaa)
    assert 0xa0ddff04 == lsbox(0x47996d5ad2a9)
    assert 0x4d9c4acf == lsbox(0x8031f9eef483)
    assert 0x4b68d704 == lsbox(0xa6620337728f)
    assert 0xf4ed5ca7 == lsbox(0x86a5ee440b5e)
    assert 0xe3127544 == lsbox(0x29c929eb8a4)
    assert 0x5f18eaca == lsbox(0x6c97fcaefa10)
    assert 0xde0537dd == lsbox(0xa0fb8753096f)

def test_substitute():
    lsub = lambda value, index: bits_to_integer(substitute(integer_to_bits(value, 6), index))
    assert 5 == lsub(24, 0)
    assert 4 == lsub(14, 1)
    assert 10 == lsub(35, 2)
    assert 14 == lsub(63, 3)
    assert 12 == lsub(7, 4)
    assert 5 == lsub(43, 5)
    assert 6 == lsub(33, 6)
    assert 12 == lsub(28, 7)
