/*
 * CryptoUtils.h - AES Encryption/Decryption Utilities
 */

#ifndef CRYPTOUTILS_H_
#define CRYPTOUTILS_H_

#include <stdint.h>
#include <ti/drivers/AESECB.h>
#include <ti/drivers/cryptoutils/cryptokey/CryptoKeyPlaintext.h>

/* AES-128 key size in bytes */
#define CRYPTO_KEY_SIZE 16

/* Encryption/Decryption error codes */
typedef enum {
    CRYPTO_SUCCESS = 0,
    CRYPTO_ERROR_INIT = -1,
    CRYPTO_ERROR_ENCRYPT = -2,
    CRYPTO_ERROR_DECRYPT = -3
} CryptoStatus_t;

/* Initialize crypto module */
CryptoStatus_t CryptoUtils_init(void);

/* Encrypt data using AES-ECB mode */
CryptoStatus_t CryptoUtils_encrypt(uint8_t *plaintext, uint8_t *ciphertext, uint16_t length);

/* Decrypt data using AES-ECB mode */
CryptoStatus_t CryptoUtils_decrypt(uint8_t *ciphertext, uint8_t *plaintext, uint16_t length);

#endif /* CRYPTOUTILS_H_ */
