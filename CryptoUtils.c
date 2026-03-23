/*
  CryptoUtils.c - AES Encryption/Decryption Utilities
 */

#include <xdc/std.h>
#include <xdc/runtime/System.h>
#include <ti/drivers/Power.h>
#include <ti/drivers/power/PowerCC26XX.h>
#include <ti/drivers/AESECB.h>
#include <ti/drivers/cryptoutils/cryptokey/CryptoKeyPlaintext.h>


#include "Board.h"
#include "CryptoUtils.h"
#include "NodeTask.h"
#include "Display.h"

static Display_Handle hDisplaySerial;

/* Static AES key - SAME for all nodes */
/* WARNING: In production, use secure key storage (e.g., hardware-backed keystore) */
static uint8_t aesKey[CRYPTO_KEY_SIZE] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static AESECB_Handle aesecbHandle = NULL;
static CryptoKey cryptoKey;

CryptoStatus_t CryptoUtils_init(void)
{
    
    /* Get the display handle */
    hDisplaySerial = Display_open(Display_Type_UART, NULL);
    
    /* Power on Crypto module */
    Power_setDependency(PowerCC26XX_PERIPH_CRYPTO);

    /* Open AES ECB handle */
    aesecbHandle = AESECB_open(Board_AESECB0, NULL);
    if (!aesecbHandle) {
        return CRYPTO_ERROR_INIT;
    }

    /* Initialize the AES key */
    CryptoKeyPlaintext_initKey(&cryptoKey, aesKey, CRYPTO_KEY_SIZE);

    return CRYPTO_SUCCESS;
}


CryptoStatus_t CryptoUtils_encrypt(uint8_t *plaintext, uint8_t *ciphertext, uint16_t length)
{
    AESECB_Operation encryptOp;
    int i;  // Declare variable at function start

    if (!aesecbHandle || length == 0 || length % 16 != 0) {
        Display_printf(hDisplaySerial, 4, 0, "ENCRYPT ERROR: Invalid parameters");
        return CRYPTO_ERROR_ENCRYPT;
    }

    /* Setup encryption operation */
    AESECB_Operation_init(&encryptOp);
    encryptOp.key = &cryptoKey;
    encryptOp.inputLength = length;
    encryptOp.input = plaintext;
    encryptOp.output = ciphertext;

     Display_printf(hDisplaySerial, 5, 0,"ENCRYPTING: %d bytes\n", length);
    Display_printf(hDisplaySerial, 6, 0,"Plaintext (first 16 bytes): ");
    for(i = 0; i < (length < 16 ? length : 16); i++) {  // Use 'i' declared above
        Display_printf(hDisplaySerial, 7, 0,"%02f ", plaintext[i]);
    
    }
    /* Perform encryption */
    if (AESECB_oneStepEncrypt(aesecbHandle, &encryptOp) != AESECB_STATUS_SUCCESS) {
        Display_printf(hDisplaySerial, 8, 0, "ENCRYPT FAILED");
        return CRYPTO_ERROR_ENCRYPT;
    }

    Display_printf(hDisplaySerial, 9, 0,"Ciphertext (first 16 bytes): ");
    
    for(i = 0; i < (length < 16 ? length : 16); i++) {  // Reuse 'i'
       Display_printf(hDisplaySerial, 10, 0,"%02x ", ciphertext[i]);
    }


    return CRYPTO_SUCCESS;
}

CryptoStatus_t CryptoUtils_decrypt(uint8_t *ciphertext, uint8_t *plaintext, uint16_t length)
{
    AESECB_Operation decryptOp;

    if (!aesecbHandle || length == 0 || length % 16 != 0) {
        return CRYPTO_ERROR_DECRYPT;
    }

    /* Setup decryption operation */
    AESECB_Operation_init(&decryptOp);
    decryptOp.key = &cryptoKey;
    decryptOp.inputLength = length;
    decryptOp.input = ciphertext;
    decryptOp.output = plaintext;

    /* Perform decryption */
    if (AESECB_oneStepDecrypt(aesecbHandle, &decryptOp) != AESECB_STATUS_SUCCESS) {
        return CRYPTO_ERROR_DECRYPT;
    }

    return CRYPTO_SUCCESS;
}
