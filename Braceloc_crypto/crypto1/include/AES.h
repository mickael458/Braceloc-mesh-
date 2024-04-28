#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include <string.h>
#include "Arduino.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

class AESManager {
private:
    mbedtls_aes_context aes;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

public:
    AESManager() {
        mbedtls_aes_init(&aes);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        const char *personalization = "MyAESIVGenerator";
        mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const unsigned char *)personalization,
                              strlen(personalization));
    }

    ~AESManager() {
        mbedtls_aes_free(&aes);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
    }

    void encryptCBC(const unsigned char *text, size_t text_len, const unsigned char *key, unsigned char *outputBuffer) {
        unsigned char iv[16];
        mbedtls_ctr_drbg_random(&ctr_drbg, iv, sizeof(iv));

        mbedtls_aes_setkey_enc(&aes, key, 128);
        size_t padded_len = text_len;
        if (padded_len % 16 != 0) {
            padded_len = (padded_len / 16 + 1) * 16;
        }
        unsigned char padded_text[padded_len];
        memcpy(padded_text, text, text_len);
        memset(padded_text + text_len, 0, padded_len - text_len);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv, padded_text, outputBuffer + 16);
        memcpy(outputBuffer, iv, 16); // Store IV at the beginning of the output buffer
    }

    /*void decryptCBC(unsigned char *enc_text, size_t enc_text_len, const unsigned char *key, unsigned char *outputBuffer) {
        mbedtls_aes_setkey_dec(&aes, key, 128);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, enc_text_len - 16, enc_text, enc_text + 16, outputBuffer);
    }*/

    void decryptCBC(unsigned char *enc_text, size_t enc_text_len, const unsigned char *key, unsigned char *outputBuffer) {
        mbedtls_aes_setkey_dec(&aes, key, 128);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, enc_text_len - 16, enc_text + 16, enc_text, outputBuffer);

        // Correct padding removal
        int padValue = outputBuffer[enc_text_len - 17]; // last byte value
        if (padValue > 0 && padValue <= 16) { // Check for valid PKCS#7 padding
            bool validPad = true;
            for (int i = 0; i < padValue; i++) {
                if (outputBuffer[enc_text_len - 17 - i] != padValue) {
                    validPad = false;
                    break;
                }
            }
            if (validPad) {
                memset(outputBuffer + enc_text_len - 16 - padValue, 0, padValue); // Clear padding
            }
        }
        outputBuffer[enc_text_len - 16 - padValue] = 0; // Null-terminate the string
    }
};