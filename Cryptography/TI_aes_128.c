/*
 * TI_aes_128.c - AES-128 software encryption and decryption
 *
 * FIPS-197 compliant AES-128 implementation supporting both
 * encryption and decryption of 16-byte blocks in ECB mode.
 *
 * Optimised for embedded targets (CC13xx/CC26xx); no dynamic
 * allocation and no hardware dependencies.
 */

#include "TI_aes_128.h"

/* ---------------------------------------------------------------------------
 * AES S-box (encryption substitution table, FIPS-197 Figure 7)
 * ---------------------------------------------------------------------------*/
static const unsigned char sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/* ---------------------------------------------------------------------------
 * AES inverse S-box (decryption substitution table, FIPS-197 Figure 14)
 * ---------------------------------------------------------------------------*/
static const unsigned char rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

/* Round constants for key schedule (FIPS-197 Section 5.2) */
static const unsigned char rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* Number of AES-128 rounds */
#define AES_NR  10

/* ---------------------------------------------------------------------------
 * GF(2^8) multiplication helpers
 * ---------------------------------------------------------------------------*/
static unsigned char xtime(unsigned char x)
{
    return (unsigned char)(((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00)) & 0xff);
}

static unsigned char gmul(unsigned char a, unsigned char b)
{
    unsigned char p = 0;
    unsigned char i;
    for (i = 0; i < 8; i++) {
        if (b & 0x01) {
            p ^= a;
        }
        b >>= 1;
        a = xtime(a);
    }
    return p;
}

/* ---------------------------------------------------------------------------
 * Key expansion – produces (AES_NR+1) * 16 bytes of round key material
 * ---------------------------------------------------------------------------*/
static void key_expansion(const unsigned char *key,
                           unsigned char       *roundKey)
{
    unsigned char temp[4];
    unsigned char k;
    int i;

    /* Copy the original key into the first round key */
    for (i = 0; i < AES_KEY_SIZE; i++) {
        roundKey[i] = key[i];
    }

    /* Derive the remaining round keys */
    for (i = AES_KEY_SIZE; i < (AES_NR + 1) * AES_BLOCK_SIZE; i += 4) {
        temp[0] = roundKey[i - 4];
        temp[1] = roundKey[i - 3];
        temp[2] = roundKey[i - 2];
        temp[3] = roundKey[i - 1];

        if ((i / 4) % (AES_KEY_SIZE / 4) == 0) {
            /* RotWord */
            k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;
            /* SubWord */
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
            /* XOR with round constant */
            temp[0] ^= rcon[i / AES_KEY_SIZE];
        }

        roundKey[i + 0] = roundKey[i - AES_KEY_SIZE + 0] ^ temp[0];
        roundKey[i + 1] = roundKey[i - AES_KEY_SIZE + 1] ^ temp[1];
        roundKey[i + 2] = roundKey[i - AES_KEY_SIZE + 2] ^ temp[2];
        roundKey[i + 3] = roundKey[i - AES_KEY_SIZE + 3] ^ temp[3];
    }
}

/* ---------------------------------------------------------------------------
 * AddRoundKey
 * ---------------------------------------------------------------------------*/
static void add_round_key(unsigned char *state, const unsigned char *roundKey,
                           int round)
{
    int i;
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] ^= roundKey[round * AES_BLOCK_SIZE + i];
    }
}

/* ---------------------------------------------------------------------------
 * SubBytes (encryption)
 * ---------------------------------------------------------------------------*/
static void sub_bytes(unsigned char *state)
{
    int i;
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] = sbox[state[i]];
    }
}

/* ---------------------------------------------------------------------------
 * InvSubBytes (decryption)
 * ---------------------------------------------------------------------------*/
static void inv_sub_bytes(unsigned char *state)
{
    int i;
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        state[i] = rsbox[state[i]];
    }
}

/* ---------------------------------------------------------------------------
 * ShiftRows (encryption) – state is column-major, rows shifted left
 * state layout: [col0_row0, col0_row1, col0_row2, col0_row3,
 *                col1_row0, col1_row1, col1_row2, col1_row3, ...]
 * which means row r contains state[r], state[r+4], state[r+8], state[r+12].
 * ---------------------------------------------------------------------------*/
static void shift_rows(unsigned char *state)
{
    unsigned char tmp;

    /* Row 1: shift left by 1 */
    tmp       = state[1];
    state[1]  = state[5];
    state[5]  = state[9];
    state[9]  = state[13];
    state[13] = tmp;

    /* Row 2: shift left by 2 */
    tmp       = state[2];
    state[2]  = state[10];
    state[10] = tmp;
    tmp       = state[6];
    state[6]  = state[14];
    state[14] = tmp;

    /* Row 3: shift left by 3 (= shift right by 1) */
    tmp       = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7]  = state[3];
    state[3]  = tmp;
}

/* ---------------------------------------------------------------------------
 * InvShiftRows (decryption)
 * ---------------------------------------------------------------------------*/
static void inv_shift_rows(unsigned char *state)
{
    unsigned char tmp;

    /* Row 1: shift right by 1 */
    tmp       = state[13];
    state[13] = state[9];
    state[9]  = state[5];
    state[5]  = state[1];
    state[1]  = tmp;

    /* Row 2: shift right by 2 */
    tmp       = state[2];
    state[2]  = state[10];
    state[10] = tmp;
    tmp       = state[6];
    state[6]  = state[14];
    state[14] = tmp;

    /* Row 3: shift right by 3 (= shift left by 1) */
    tmp       = state[3];
    state[3]  = state[7];
    state[7]  = state[11];
    state[11] = state[15];
    state[15] = tmp;
}

/* ---------------------------------------------------------------------------
 * MixColumns (encryption)
 * ---------------------------------------------------------------------------*/
static void mix_columns(unsigned char *state)
{
    int col;
    unsigned char s0, s1, s2, s3;

    for (col = 0; col < 4; col++) {
        s0 = state[col * 4 + 0];
        s1 = state[col * 4 + 1];
        s2 = state[col * 4 + 2];
        s3 = state[col * 4 + 3];

        state[col * 4 + 0] = (unsigned char)(gmul(0x02, s0) ^ gmul(0x03, s1) ^ s2 ^ s3);
        state[col * 4 + 1] = (unsigned char)(s0 ^ gmul(0x02, s1) ^ gmul(0x03, s2) ^ s3);
        state[col * 4 + 2] = (unsigned char)(s0 ^ s1 ^ gmul(0x02, s2) ^ gmul(0x03, s3));
        state[col * 4 + 3] = (unsigned char)(gmul(0x03, s0) ^ s1 ^ s2 ^ gmul(0x02, s3));
    }
}

/* ---------------------------------------------------------------------------
 * InvMixColumns (decryption)
 * ---------------------------------------------------------------------------*/
static void inv_mix_columns(unsigned char *state)
{
    int col;
    unsigned char s0, s1, s2, s3;

    for (col = 0; col < 4; col++) {
        s0 = state[col * 4 + 0];
        s1 = state[col * 4 + 1];
        s2 = state[col * 4 + 2];
        s3 = state[col * 4 + 3];

        state[col * 4 + 0] = (unsigned char)(gmul(0x0e, s0) ^ gmul(0x0b, s1) ^ gmul(0x0d, s2) ^ gmul(0x09, s3));
        state[col * 4 + 1] = (unsigned char)(gmul(0x09, s0) ^ gmul(0x0e, s1) ^ gmul(0x0b, s2) ^ gmul(0x0d, s3));
        state[col * 4 + 2] = (unsigned char)(gmul(0x0d, s0) ^ gmul(0x09, s1) ^ gmul(0x0e, s2) ^ gmul(0x0b, s3));
        state[col * 4 + 3] = (unsigned char)(gmul(0x0b, s0) ^ gmul(0x0d, s1) ^ gmul(0x09, s2) ^ gmul(0x0e, s3));
    }
}

/* ---------------------------------------------------------------------------
 * aes_enc_dec – public entry point
 * ---------------------------------------------------------------------------*/
void aes_enc_dec(unsigned char *state, unsigned char *key, unsigned char dir)
{
    unsigned char roundKey[(AES_NR + 1) * AES_BLOCK_SIZE];
    int round;

    key_expansion(key, roundKey);

    if (dir == AES_ENCRYPT) {
        /* Initial round */
        add_round_key(state, roundKey, 0);

        /* Main rounds */
        for (round = 1; round < AES_NR; round++) {
            sub_bytes(state);
            shift_rows(state);
            mix_columns(state);
            add_round_key(state, roundKey, round);
        }

        /* Final round (no MixColumns) */
        sub_bytes(state);
        shift_rows(state);
        add_round_key(state, roundKey, AES_NR);
    } else {
        /* Initial round */
        add_round_key(state, roundKey, AES_NR);

        /* Main rounds */
        for (round = AES_NR - 1; round > 0; round--) {
            inv_shift_rows(state);
            inv_sub_bytes(state);
            add_round_key(state, roundKey, round);
            inv_mix_columns(state);
        }

        /* Final round (no InvMixColumns) */
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, roundKey, 0);
    }
}
