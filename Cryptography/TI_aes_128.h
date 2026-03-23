/*
 * TI_aes_128.h - AES-128 software encryption and decryption
 *
 * FIPS-197 compliant AES-128 implementation.
 * Provides both encryption and decryption via a single function.
 *
 * Usage:
 *   aes_enc_dec(state, key, AES_ENCRYPT);  // encrypt 16-byte block in place
 *   aes_enc_dec(state, key, AES_DECRYPT);  // decrypt 16-byte block in place
 */

#ifndef TI_AES_128_H
#define TI_AES_128_H

/* AES-128 block and key size in bytes */
#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE    16

/* Direction constants for aes_enc_dec() */
#define AES_ENCRYPT     0
#define AES_DECRYPT     1

/*
 * aes_enc_dec - AES-128 encrypt or decrypt a 16-byte block in place
 *
 * state : pointer to the 16-byte data block (modified in place)
 * key   : pointer to the 16-byte AES-128 key
 * dir   : AES_ENCRYPT (0) to encrypt, AES_DECRYPT (1) to decrypt
 */
void aes_enc_dec(unsigned char *state, unsigned char *key, unsigned char dir);

#endif /* TI_AES_128_H */
