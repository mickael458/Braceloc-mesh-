#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include <string.h>
#include "Arduino.h"
#include <LoRa.h>

class AESManager {
private:
    mbedtls_aes_context aes;

public:
    AESManager() {
        mbedtls_aes_init(&aes);
    }

    ~AESManager() {
        mbedtls_aes_free(&aes);
    }

    void encryptCBC(const unsigned char *text, size_t text_len, const unsigned char *key, const unsigned char *iv, unsigned char *outputBuffer) {
        mbedtls_aes_setkey_enc(&aes, key, 128);
        // Padding if necessary (simple zero-padding)
        size_t padded_len = text_len;
        if (padded_len % 16 != 0) {
            padded_len = (padded_len / 16 + 1) * 16;
        }
        unsigned char padded_text[padded_len];
        memcpy(padded_text, text, text_len);
        memset(padded_text + text_len, 0, padded_len - text_len); // Zero padding
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, (unsigned char *)iv, padded_text, outputBuffer);
    }

    /*void decryptCBC(const unsigned char *enc_text, size_t enc_text_len, const unsigned char *key, const unsigned char *iv, unsigned char *outputBuffer) {
        mbedtls_aes_setkey_dec(&aes, key, 128);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, enc_text_len, (unsigned char *)iv, enc_text, outputBuffer);
        // Remove padding if necessary here
        int lastByte = outputBuffer[enc_text_len - 1];
        if (lastByte > 0 && lastByte <= 16) {
            bool validPadding = true;
            for (int i = 1; i < lastByte; i++) {
                if (outputBuffer[enc_text_len - 1 - i] != lastByte) {
                    validPadding = false;
                    break;
                }
            }
            if (validPadding) {
                memset(outputBuffer + enc_text_len - lastByte, 0, lastByte);
            }
        }
    }*/
    void decryptCBC(const unsigned char *enc_text, size_t enc_text_len, const unsigned char *key, const unsigned char *iv, unsigned char *outputBuffer) {
        mbedtls_aes_setkey_dec(&aes, key, 128);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, enc_text_len, (unsigned char *)iv, enc_text, outputBuffer);
        // Improved padding removal
        size_t lastByte = outputBuffer[enc_text_len - 1];
        bool validPadding = true;
        if (lastByte > 0 && lastByte <= 16) {
            for (size_t i = 0; i < lastByte; i++) {
                if (outputBuffer[enc_text_len - 1 - i] != lastByte) {
                    validPadding = false;
                    break;
                }
            }
            if (validPadding) {
                memset(outputBuffer + enc_text_len - lastByte, 0, lastByte);
            }
        }
    }

};