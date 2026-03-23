/*
 * CryptoUtils_TI.c - Software AES-128 abstraction layer
 *
 * Wraps the TI AES-128 software library (TI_aes_128.c) and exposes the
 * same encrypt/decrypt interface as the hardware AESECB-based CryptoUtils.c.
 * Uses the same static AES-128 key as the hardware implementation so the two
 * backends are fully interchangeable.
 *
 * No hardware dependencies – works on all CC13xx/CC26xx devices.
 */

#include <string.h>
#include <stdint.h>

#include "CryptoUtils_TI.h"
#include "Cryptography/TI_aes_128.h"

/* Static AES-128 key – must match the key used in CryptoUtils.c */
/* WARNING: In production, use secure key storage */
static const uint8_t aesKey[CRYPTO_KEY_SIZE] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static uint8_t cryptoInitialised = 0;

/* ---------------------------------------------------------------------------
 * CryptoUtils_TI_init
 * ---------------------------------------------------------------------------*/
CryptoStatus_t CryptoUtils_TI_init(void)
{
    cryptoInitialised = 1;
    return CRYPTO_SUCCESS;
}

/* ---------------------------------------------------------------------------
 * CryptoUtils_TI_encrypt
 * ---------------------------------------------------------------------------*/
CryptoStatus_t CryptoUtils_TI_encrypt(uint8_t  *plaintext,
                                       uint8_t  *ciphertext,
                                       uint16_t  length)
{
    uint16_t offset;
    uint8_t  block[AES_BLOCK_SIZE];

    if (!cryptoInitialised || plaintext == NULL || ciphertext == NULL ||
        length == 0 || (length % AES_BLOCK_SIZE) != 0)
    {
        return CRYPTO_ERROR_ENCRYPT;
    }

    /* Process one 16-byte ECB block at a time */
    for (offset = 0; offset < length; offset += AES_BLOCK_SIZE) {
        memcpy(block, plaintext + offset, AES_BLOCK_SIZE);
        aes_enc_dec(block, (unsigned char *)aesKey, AES_ENCRYPT);
        memcpy(ciphertext + offset, block, AES_BLOCK_SIZE);
    }

    return CRYPTO_SUCCESS;
}

/* ---------------------------------------------------------------------------
 * CryptoUtils_TI_decrypt
 * ---------------------------------------------------------------------------*/
CryptoStatus_t CryptoUtils_TI_decrypt(uint8_t  *ciphertext,
                                       uint8_t  *plaintext,
                                       uint16_t  length)
{
    uint16_t offset;
    uint8_t  block[AES_BLOCK_SIZE];

    if (!cryptoInitialised || ciphertext == NULL || plaintext == NULL ||
        length == 0 || (length % AES_BLOCK_SIZE) != 0)
    {
        return CRYPTO_ERROR_DECRYPT;
    }

    /* Process one 16-byte ECB block at a time */
    for (offset = 0; offset < length; offset += AES_BLOCK_SIZE) {
        memcpy(block, ciphertext + offset, AES_BLOCK_SIZE);
        aes_enc_dec(block, (unsigned char *)aesKey, AES_DECRYPT);
        memcpy(plaintext + offset, block, AES_BLOCK_SIZE);
    }

    return CRYPTO_SUCCESS;
}
