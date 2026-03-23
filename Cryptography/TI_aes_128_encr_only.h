/*
 * TI_aes_128_encr_only.h - AES-128 software encryption (transmitter nodes)
 *
 * Optimised encryption-only variant of the TI AES-128 library.
 * Omits decryption tables and code to reduce flash footprint (~2 KB).
 *
 * Usage:
 *   aes_encrypt(state, key);   // encrypt 16-byte block in place
 */

#ifndef TI_AES_128_ENCR_ONLY_H
#define TI_AES_128_ENCR_ONLY_H

/* AES-128 block and key size in bytes */
#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE    16

/*
 * aes_encrypt - AES-128 encrypt a 16-byte block in place
 *
 * state : pointer to the 16-byte data block (modified in place)
 * key   : pointer to the 16-byte AES-128 key
 */
void aes_encrypt(unsigned char *state, unsigned char *key);

#endif /* TI_AES_128_ENCR_ONLY_H */
