/*
 * CryptoUtils_TI.h - Software AES-128 abstraction layer
 *
 * Provides the same interface as the hardware AESECB-based CryptoUtils.h
 * but uses the TI AES-128 software library with no hardware dependencies.
 * Suitable for all CC13xx/CC26xx devices.
 */

#ifndef CRYPTOUTILS_TI_H_
#define CRYPTOUTILS_TI_H_

#include <stdint.h>

/* Re-use the status codes from CryptoUtils.h */
#include "CryptoUtils.h"

/*
 * CryptoUtils_TI_init - Initialise the software AES-128 module
 *
 * No hardware resources are claimed.  Call once before first use.
 *
 * Returns: CRYPTO_SUCCESS
 */
CryptoStatus_t CryptoUtils_TI_init(void);

/*
 * CryptoUtils_TI_encrypt - AES-128 ECB encrypt
 *
 * plaintext  : input buffer  (must be a multiple of 16 bytes)
 * ciphertext : output buffer (same size as plaintext)
 * length     : number of bytes to encrypt (must be > 0 and multiple of 16)
 *
 * Returns: CRYPTO_SUCCESS or CRYPTO_ERROR_ENCRYPT
 */
CryptoStatus_t CryptoUtils_TI_encrypt(uint8_t *plaintext,
                                       uint8_t *ciphertext,
                                       uint16_t length);

/*
 * CryptoUtils_TI_decrypt - AES-128 ECB decrypt
 *
 * ciphertext : input buffer  (must be a multiple of 16 bytes)
 * plaintext  : output buffer (same size as ciphertext)
 * length     : number of bytes to decrypt (must be > 0 and multiple of 16)
 *
 * Returns: CRYPTO_SUCCESS or CRYPTO_ERROR_DECRYPT
 */
CryptoStatus_t CryptoUtils_TI_decrypt(uint8_t *ciphertext,
                                       uint8_t *plaintext,
                                       uint16_t length);

#endif /* CRYPTOUTILS_TI_H_ */
