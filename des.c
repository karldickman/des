#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

int BLOCK_SIZE = 64;
int INITIAL_PERMUTATION[] = {57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27,
    19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
    56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44,
    36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6};
int EXPANSION[] = {31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10, 11, 12,
    11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24, 23,
    24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0};
int FINAL_PERMUTATION[] = {39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54,
    22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9,
    49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24};
int KEY_PERMUTATION1[] = {56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17,
    9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 62, 54, 46, 38, 30,
    22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 60, 52, 44, 36, 28, 20, 12, 4,
    27, 19, 11, 3};
int KEY_PERMUTATION2[] = {13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18,
    11, 3, 25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39, 50, 44,
    32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31};
int NUM_ROUNDS = 16;
int ROUND_PERMUTATION[] = {15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17,
    30, 9, 1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24};
int SBOX[][16][4] = {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,

    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,

    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,

    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
    3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,

    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,

    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,

    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,

    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11};
int SHIFT_SIZES[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
int SUBKEY_LENGTH = 48;

long long* encipher();
long long encipher_block();
bool is_des_key();
long long reorder();
long long round_();
long long* round_keys();
int sbox();
int substitute();

int main() {
    for(int i=0; i < 1000; i++) {
        encipher(rand() % 0xffffffffffffffff, 0x3b3898371520f75e);
    }
}

/* Decipher a message with the given key.  The message must be an array of long
 * longs.  The key must be a 64 bit key as defined by the DES standard. */
long long* decipher(long long message[], long long key, int num_blocks) {
    long long* keys = calloc(NUM_ROUNDS, sizeof(long long));
    long long* old_keys = calloc(NUM_ROUNDS, sizeof(long long));
    long long* plaintext = calloc(num_blocks, sizeof(long long));
    if(!is_des_key()) {
        //TODO
        //Raise a value error
    }
    old_keys = round_keys(key);
    for(int i = 0; i < NUM_ROUNDS; i++) {
        keys[i] = old_keys[NUM_ROUNDS - i];
    }
    for(int i = 0; i < num_blocks; i++) {
        plaintext[i] = encipher_block(message[i], keys);
    }
    return plaintext;
}

/* Encipher a message with the given key.  The message must be an array of long
 * longs.  The key must a 64 bit key as defined by the DES standard. */
long long* encipher(long long message[], long long key, int num_blocks) {
    long long* keys = calloc(NUM_ROUNDS, sizeof(long long));
    long long* ciphertext = calloc(num_blocks, sizeof(long long));
    if(!is_des_key(key)) {
        //TODO
        //Do the equivalent of raising a value error.
    }
    keys = round_keys(key);
    for(int i = 0; i < num_blocks; i++) {
        ciphertext[i] = encipher_block(message[i], keys);
    }
    return ciphertext;
}

/* Encipher a 64-bit block with the given key schedule. */
long long encipher_block(long long block, long long keys[]) {
    block = reorder(block, INITIAL_PERMUTATION);
    for(int i = 0; i < NUM_ROUNDS; i++) {
        block = round_(block, keys[i]);
    }
    //TODO perform a 32-bit shift on the block
    return reorder(block, FINAL_PERMUTATION);
}

bool is_des_key(long long key) {
    //TODO How the hell do you do this?
}

long long reorder(long long block, int permutation[]) {
    //TODO how the hell do you reorder the bits in an integer?
}

/* Perform one round of DES on the given block, using the given round key. */
long long round_(long long block, long long key) {
    int left;
    int right;
    int temp;
    //Decompose block into left and right
    temp = reorder(right, EXPANSION);
    temp ^= key;
    temp = sbox(temp);
    temp ^= left;
    //Concatenate right and temp and return it
}

long long* round_keys(long long key) {
    //TODO
}

/* Apply the DES substitution table, or S-box, to a block. */
int sbox(long long block) {
    int slice, new_block;
    for(int i = 0; i < 8; i++) {
        // TODO Construct a 6-bit slice from the block
        slice = substitute(slice, i);
        // Concatenate slice with the new block constructed
    }
    return new_block;
}

/* Substitute a four bit integer for a six bit one using the DES substitution
 * table. */
int substitute(int slice, int slice_index) {
    int row, column;//TODO How do you get these?
    return SBOX[slice_index][row][column];
}
