#!/usr/bin/env python2.6
"""The Data Encryption Standard is a cryptographic standard endorsed by the
United States' National Institute of Standards and Technology.  Its official
description can be found in Federal Information Processing Standards
Publication 46-3.  As of the late 1990s, it is no longer strong enough to
provide secure cryptographic communication."""

from miscellaneous import main_function
from random import randint

#These constants are the same for all DES implementations.
BLOCK_SIZE = 64
EFFECTIVE_KEY_SIZE = 56
HALF_BLOCK_SIZE = 32
HALF_EFFECTIVE_KEY_SIZE = 28
EXPANSION = [0x1, 0x80000000, 0x40000000, 0x20000000, 0x10000000, 0x8000000,
             0x10000000, 0x8000000, 0x4000000, 0x2000000, 0x1000000, 0x800000,
             0x1000000, 0x800000, 0x400000, 0x200000, 0x100000, 0x80000,
             0x100000, 0x80000, 0x40000, 0x20000, 0x10000, 0x8000, 0x10000,
             0x8000, 0x4000, 0x2000, 0x1000, 0x800, 0x1000, 0x800, 0x400,
             0x200, 0x100, 0x80, 0x100, 0x80, 0x40, 0x20, 0x10, 0x8, 0x10, 0x8,
             0x4, 0x2, 0x1, 0x80000000]
FINAL_PERMUTATION = [0x1000000, 0x100000000000000, 0x10000, 0x1000000000000,
                     0x100, 0x10000000000, 0x1, 0x100000000, 0x2000000,
                     0x200000000000000, 0x20000, 0x2000000000000, 0x200,
                     0x20000000000, 0x2, 0x200000000, 0x4000000,
                     0x400000000000000, 0x40000, 0x4000000000000, 0x400,
                     0x40000000000, 0x4, 0x400000000, 0x8000000,
                     0x800000000000000, 0x80000, 0x8000000000000, 0x800,
                     0x80000000000, 0x8, 0x800000000, 0x10000000,
                     0x1000000000000000, 0x100000, 0x10000000000000, 0x1000,
                     0x100000000000, 0x10, 0x1000000000, 0x20000000,
                     0x2000000000000000, 0x200000, 0x20000000000000, 0x2000,
                     0x200000000000, 0x20, 0x2000000000, 0x40000000,
                     0x4000000000000000, 0x400000, 0x40000000000000, 0x4000,
                     0x400000000000, 0x40, 0x4000000000, 0x80000000,
                     0x8000000000000000, 0x800000, 0x80000000000000, 0x8000,
                     0x800000000000, 0x80, 0x8000000000]
INITIAL_PERMUTATION = [0x40, 0x4000, 0x400000, 0x40000000, 0x4000000000,
                       0x400000000000, 0x40000000000000, 0x4000000000000000,
                       0x10, 0x1000, 0x100000, 0x10000000, 0x1000000000,
                       0x100000000000, 0x10000000000000, 0x1000000000000000,
                       0x4, 0x400, 0x40000, 0x4000000, 0x400000000,
                       0x40000000000, 0x4000000000000, 0x400000000000000, 0x1,
                       0x100, 0x10000, 0x1000000, 0x100000000, 0x10000000000,
                       0x1000000000000, 0x100000000000000, 0x80, 0x8000,
                       0x800000, 0x80000000, 0x8000000000, 0x800000000000,
                       0x80000000000000, 0x8000000000000000, 0x20, 0x2000,
                       0x200000, 0x20000000, 0x2000000000, 0x200000000000,
                       0x20000000000000, 0x2000000000000000, 0x8, 0x800,
                       0x80000, 0x8000000, 0x800000000, 0x80000000000,
                       0x8000000000000, 0x800000000000000, 0x2, 0x200, 0x20000,
                       0x2000000, 0x200000000, 0x20000000000, 0x2000000000000,
                       0x200000000000000]
KEY_PERMUTATION1 = [0x80, 0x8000, 0x800000, 0x80000000, 0x8000000000,
                    0x800000000000, 0x80000000000000, 0x8000000000000000, 0x40,
                    0x4000, 0x400000, 0x40000000, 0x4000000000, 0x400000000000,
                    0x40000000000000, 0x4000000000000000, 0x20, 0x2000,
                    0x200000, 0x20000000, 0x2000000000, 0x200000000000,
                    0x20000000000000, 0x2000000000000000, 0x10, 0x1000,
                    0x100000, 0x10000000, 0x2, 0x200, 0x20000, 0x2000000,
                    0x200000000, 0x20000000000, 0x2000000000000,
                    0x200000000000000, 0x4, 0x400, 0x40000, 0x4000000,
                    0x400000000, 0x40000000000, 0x4000000000000,
                    0x400000000000000, 0x8, 0x800, 0x80000, 0x8000000,
                    0x800000000, 0x80000000000, 0x8000000000000,
                    0x800000000000000, 0x1000000000, 0x100000000000,
                    0x10000000000000, 0x1000000000000000]
KEY_PERMUTATION2 = [0x40000000000, 0x8000000000, 0x200000000000, 0x100000000,
                    0x80000000000000, 0x8000000000000, 0x20000000000000,
                    0x10000000, 0x20000000000, 0x4000000000000, 0x800000000,
                    0x400000000000, 0x200000000, 0x2000000000, 0x100000000000,
                    0x10000000000000, 0x40000000, 0x1000000000000,
                    0x10000000000, 0x2000000000000, 0x20000000, 0x1000000000,
                    0x80000000000, 0x40000000000000, 0x8000, 0x10, 0x2000000,
                    0x80000, 0x200, 0x2, 0x4000000, 0x10000, 0x20, 0x800,
                    0x800000, 0x100, 0x1000, 0x80, 0x20000, 0x1, 0x400000, 0x8,
                    0x400, 0x4000, 0x40, 0x100000, 0x8000000, 0x1000000]
KEY_SIZE = 64
ROUND_PERMUTATION = [0x10000, 0x2000000, 0x1000, 0x800, 0x8, 0x100000, 0x10,
                     0x8000, 0x80000000, 0x20000, 0x200, 0x40, 0x8000000,
                     0x4000, 0x2, 0x400000, 0x40000000, 0x1000000, 0x100,
                     0x40000, 0x1, 0x20, 0x20000000, 0x800000, 0x2000, 0x80000,
                     0x4, 0x4000000, 0x400, 0x200000, 0x10000000, 0x80]
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

@main_function()
def main(options, arguments):
    for i in xrange(1000000):
        encipher(randint(0, 2**64 - 1), 0x3b3898371520f75e)

def bit_count(integer):
    count = 0
    while integer:
        count += 1
        integer &= integer - 1
    return count

def decipher(blocks, key):
    """Decipher a message with a the given key.  The message must be an
    integer.  The key must be a 64 bit key as defined by the DES standard."""
    if not is_des_key(key):
        raise ValueError("0x%x is not a valid DES key." % key)
    keys = reversed(list(round_keys(key)))
    for block in blocks:
        yield encipher_block(block, keys)

def encipher(blocks, key):
    """Encipher a message with a the given key.  The message must be an
    integer.  The key must be a 64 bit key as defined by the DES standard."""
    if not is_des_key(key):
        raise ValueError("0x%x is not a valid DES key." % key)
    keys = round_keys(key)
    for block in blocks:
        yield encipher_block(block, keys)

def encipher_block(block, keys):
    """Encipher a 64-bit block of with the given key schedule."""
    if block > 0xffffffffffffffff:
        raise ValueError("DES has a block size of 64 bits.")
    block = reorder_integer(block, INITIAL_PERMUTATION)
    for key in keys:
        block = round_(block, key)
    block = swap(block)
    return reorder_integer(block, FINAL_PERMUTATION)

def integer_to_key(integer):
    """Convert the given 56 bit integer into a 64-bit DES key."""
    if integer > 0xffffffffffffff:
        raise ValueError("DES keys cannot have an effective key length > 56 bits.")
    key = 0
    for i in xrange(EFFECTIVE_KEY_SIZE / 7):
        slice_ = (integer & 0x7f) << 1
        integer >>= 7
        slice_ ^= (7 - bit_count(slice_)) & 1
        slice_ <<= 8 * i
        key ^= slice_
    return key

def is_des_key(key):
    """Determine if the given key is a valid DES key.  Every eighth bit should
    be a parity bit.  Each byte of the key must have an even number of 'on' bits."""
    if key > 0xffffffffffffffff:
        return False
    for i in xrange(BLOCK_SIZE / 8):
        slice_ = (key & 0xff)
        key >>= 8
        if bit_count(slice_) & 1 == 0:
            return False
    return True

def reorder_integer(integer, ordering, num_bits=None):
    if num_bits is None:
        num_bits = len(ordering)
    new_integer = 0
    for i, bitmask in enumerate(ordering):
        if integer & bitmask:
            new_integer ^= (1 << len(ordering) - i - 1)
    return new_integer

def rotate_round_key(chunk, shift):
    overflow = chunk & 0x8000000 if shift == 1 else chunk & 0xc000000
    overflow >>= (HALF_EFFECTIVE_KEY_SIZE - shift)
    main_chunk = chunk & 0x7ffffff if shift == 1 else chunk & 0x3ffffff
    main_chunk <<= shift
    return main_chunk ^ overflow

def round_(block, key):
    """Perform one round of DES on the given block, using the given round
    key."""
    left, right = block >> HALF_BLOCK_SIZE, block & 0x00000000ffffffff
    temp = reorder_integer(right, EXPANSION, HALF_BLOCK_SIZE)
    temp ^= key
    temp = sbox(temp)
    temp = reorder_integer(temp, ROUND_PERMUTATION)
    temp ^= left
    right <<= 32
    return right ^ temp

def round_keys(key):
    """Generate a list of round keys from the given cipher key."""
    key = reorder_integer(key, KEY_PERMUTATION1, KEY_SIZE)
    left = key >> HALF_EFFECTIVE_KEY_SIZE
    right = key & 0x0000000fffffff
    for shift in SHIFT_SIZES:
        left = rotate_round_key(left, shift)
        right = rotate_round_key(right, shift)
        yield reorder_integer((left << HALF_EFFECTIVE_KEY_SIZE) ^ right,
                              KEY_PERMUTATION2, EFFECTIVE_KEY_SIZE)

def sbox(block):
    """Apply the DES substitution table, or S-box, to a block."""
    new_block = 0
    for i in xrange(8):
        slice_ = (block & 0xfc0000000000) >> (SUBKEY_LENGTH - 6)
        block <<= 6
        new_block <<= 4
        new_block ^= substitute(slice_, i)
    return new_block

def substitute(slice_, slice_index):
    """Substitute a 4 bit integer for a six bit one using the DES substitution
    table."""
    row = ((slice_ & 0x20) >> 4) ^ (slice_ & 1)
    column = (slice_ & 0x1e) >> 1
    return SBOX[slice_index][row][column]

def swap(block):
    left = (block & 0x00000000ffffffff) << HALF_BLOCK_SIZE
    right = block >> HALF_BLOCK_SIZE
    return left ^ right

if __name__ == "__main__":
    main()

#******************************************************************************
#********************************* UNIT TESTS *********************************
#******************************************************************************

from py.test import raises

def test_decipher():
    ceiling = 2 ** 64 - 1
    key = 0x3b3898371520f75e
    for i in xrange(50):
        message = [randint(0, ceiling)]
        assert message == list(decipher(encipher(message, key), key))

def test_encipher():
    message = [0x123456789abcdef]
    ciphertext = [0xaa39b9777efc3c14]
    key = 0x3b3898371520f75e
    assert ciphertext == list(encipher(message, key))

def test_encipher_block():
    message = 0x123456789abcdef
    ciphertext = 0xaa39b9777efc3c14
    key = 0x3b3898371520f75e
    assert ciphertext == encipher_block(message, round_keys(key))
    raises(ValueError, encipher_block, 2**100, round_keys(key))

def test_integer_to_key():
    ceiling = 2 ** 64 - 1
    for i in xrange(100):
        key = randint(0, ceiling)
        assert is_des_key(integer_to_key(i))

def test_is_des_key():
    assert not is_des_key(0xfffffffffffffffffffff)
    assert is_des_key(0x1313131313131313)
    assert not is_des_key(0x13131313ff131313)
    assert not is_des_key(0xff131313ff131313)
    assert not is_des_key(0)
    assert not is_des_key(0xffffffffffffffff)
    assert not is_des_key(0x0f0f0f0f0f0f0f0f)
    assert not is_des_key(0x5555555555555555)
    assert not is_des_key(0x550faa550faa550f)
    assert not is_des_key(0x4555555555555555)

def test_round():
    assert 0xa7ce3b83ff31aa89 == round_(0xa7ce3b83, 0x81bdf785afaf)
    assert 0xaa4aa9cbc85235ca == round_(0xaa4aa9cb, 0xce891ee38623)
    assert 0x262d7d5f8b903a1a == round_(0x262d7d5f, 0xcc9acc326cd6)
    assert 0x4592a6cba9834b4e == round_(0x4592a6cb, 0x6de3948c885a)
    assert 0x6fe0c5946d614835 == round_(0x6fe0c594, 0x44dabcbc111e)
    assert 0xc56b9352ee9ff1d0 == round_(0xc56b9352, 0x374379564cac)
    assert 0x115b56399aa889ed == round_(0x115b5639, 0xd1023aab4db7)
    assert 0x8473fe7d3138f417 == round_(0x8473fe7d, 0xae97d484084c)
    assert 0xaa23aa4a049a641c == round_(0xaa23aa4a, 0x2b8a229b2f57)
    assert 0x8dcf540610e3a522 == round_(0x8dcf5406, 0xb8880bc14130)
    assert 0xbeaca0c2f579fb55 == round_(0xbeaca0c2, 0x1349a999f9c4)
    assert 0x23d765f33ffc2507 == round_(0x23d765f3, 0xfb58941bada1)
    assert 0x40348024df5885cd == round_(0x40348024, 0xa1edb11e7cf6)
    assert 0x29022149d0813f4a == round_(0x29022149, 0x599e465fdc34)
    assert 0x3fa9fa9dd428a2bc == round_(0x3fa9fa9d, 0x6b008aeb39b5)
    assert 0xe26811521dd29eae == round_(0xe2681152, 0xf5713254e7a6)
    assert 0xe5d5982a996c4165 == round_(0xe5d5982a, 0x9d0d6ed31604)
    assert 0x8db9ef5fe6b8aa8c == round_(0x8db9ef5f, 0xe0502a917f99)
    assert 0x90b8179105aa91cb == round_(0x90b81791, 0x3654d823efa1)
    assert 0xbd9e984f9972c14 == round_(0xbd9e984, 0x3e1ce35fa11f)

def test_round_keys():
    keys = [101190710169423, 89257748502476, 234077963203823,
            91839393619625, 114970488110459, 195165170948400,
            176208327307122, 198028946147868, 38333700081276,
            114767295004548, 41528461911741, 78072631752839,
            210593280057787, 34233215564615, 63860207158258,
            19226452025678]
    assert keys == list(round_keys(0x3b3898371520f75e))
    keys = [41922922417150, 1036527330690, 5829410170701, 109270980555470,
            168798681618347, 89071642623083, 58894821817200, 19828894199674,
            70567684628317, 76948711379964, 73279705571233, 132783802035773,
            247944351283612, 35745253389243, 58377513678887, 70760798077783]
    assert keys == list(round_keys(0x922fb510c71f436e))

def test_sbox():
    assert 0x394dc2c0 == sbox(0x43f2ee0a8a30)
    assert 0xc2be0e9 == sbox(0x718d2afb2b92)
    assert 0xb768bac8 == sbox(0xcf523c86f5c4)
    assert 0x1996782b == sbox(0xb5b1ca22a122)
    assert 0x7a764735 == sbox(0x15e589ef7abc)
    assert 0xceb8d205 == sbox(0xc866ef6070d3)
    assert 0xdcffef32 == sbox(0x358cf072da82)
    assert 0x11ee263c == sbox(0x195f0400cab3)
    assert 0xe5ca7cab == sbox(0x93b50e2ecb4c)
    assert 0x8303eb54 == sbox(0x98c16107c54f)
    assert 0x9632350d == sbox(0x67629265cd76)
    assert 0x1425643a == sbox(0x185d16396f6b)
    assert 0xf044885c == sbox(0x2b9c7eb8eeaa)
    assert 0xa0ddff04 == sbox(0x47996d5ad2a9)
    assert 0x4d9c4acf == sbox(0x8031f9eef483)
    assert 0x4b68d704 == sbox(0xa6620337728f)
    assert 0xf4ed5ca7 == sbox(0x86a5ee440b5e)
    assert 0xe3127544 == sbox(0x29c929eb8a4)
    assert 0x5f18eaca == sbox(0x6c97fcaefa10)
    assert 0xde0537dd == sbox(0xa0fb8753096f)

def test_substitute():
    assert 5 == substitute(24, 0)
    assert 4 == substitute(14, 1)
    assert 10 == substitute(35, 2)
    assert 14 == substitute(63, 3)
    assert 12 == substitute(7, 4)
    assert 5 == substitute(43, 5)
    assert 6 == substitute(33, 6)
    assert 12 == substitute(28, 7)
