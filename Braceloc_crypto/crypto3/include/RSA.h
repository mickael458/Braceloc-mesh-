#include "Arduino.h"
#include "mbedtls/config.h"
#include "mbedtls/platform.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/md.h" // Pour la signature
#include "mbedtls/bignum.h" // Pour utiliser mbedtls_mpi
#include <cstring>
#include <cstdio>

class RSAEncryptor {
public:
    RSAEncryptor() {
        const char *pers = "rsa_encrypt";
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

        int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 
                                        (const unsigned char *)pers, strlen(pers));
        if (ret!= 0) {
            print_mbedtls_error("mbedtls_ctr_drbg_seed failed", ret);
            return;
        }
        ret = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, 2048, 65537);
        if (ret != 0) {
            print_mbedtls_error("mbedtls_rsa_gen_key failed", ret);
            return;
        }
    
        Serial.println("RSA Key Generation Successful");
    }

    ~RSAEncryptor() {
        mbedtls_rsa_free(&rsa);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
    }

    // A enlever apres 
    /*String mpiToString(mbedtls_mpi *x) {
        char buf[1024]; // Assurez-vous que le buffer est assez grand
        size_t olen = 0;
        mbedtls_mpi_write_string(x, 16, buf, sizeof(buf), &olen); // Convertit en base 16 (hexadécimal)
        return String(buf);
    }*/

    void ExportPublicKey(unsigned char buf[512], unsigned char hash[32], unsigned char signature[256]) {
        //size_t olen;
        //unsigned char buf[512];
        //unsigned char hash[32];
        //unsigned char signature[256];
        //size_t sig_len;

        // A enlever apres 

        /*unsigned char buf1[512];
        size_t olen1;

        // Exporter le module et l'exposant
        mbedtls_mpi_write_binary(&rsa.N, buf1, 256); // Exporte le module N
        mbedtls_mpi_write_binary(&rsa.E, buf1 + 256, 256); // Exporte l'exposant E

        // Afficher le module N et l'exposant E
        Serial.println("Module N (hex): " + mpiToString(&rsa.N));
        Serial.println("Exposant E (hex): " + mpiToString(&rsa.E));*/

        if (mbedtls_rsa_export_raw(&rsa, buf, 256, buf + 256, 256, NULL, 0, NULL, 0, NULL, 0) != 0) {
            Serial.println("Failed to export keys!");
            return;
        }

        mbedtls_md_init(&md_ctx);
        mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
        mbedtls_md_starts(&md_ctx);
        mbedtls_md_update(&md_ctx, buf, 512);
        mbedtls_md_finish(&md_ctx, hash);
        mbedtls_md_free(&md_ctx);

        mbedtls_rsa_pkcs1_sign(&rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, 0, hash, signature);
    }

    void encrypt(const unsigned char *input, size_t input_len, unsigned char *output) {
        int ret = mbedtls_rsa_rsaes_oaep_encrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC,
                                                   NULL, 0, input_len, input, output);
        if (ret != 0) {
            print_mbedtls_error("mbedtls_rsa_rsaes_oaep_encrypt failed", ret);
            return;
        }

        Serial.println("Encrypted: " + String((char*)output));
    }

    void decrypt(const unsigned char *input, unsigned char *output, size_t output_size) {
        size_t decrypted_length;
        int ret = mbedtls_rsa_rsaes_oaep_decrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE,
                                                 NULL, 0, &decrypted_length, input, output, output_size);
        if (ret != 0) {
            print_mbedtls_error("mbedtls_rsa_rsaes_oaep_decrypt failed", ret);
            return;
        }

        Serial.println("Decryption successful: ");
        Serial.println(String((char*)output));
    }
    private:
        mbedtls_md_context_t md_ctx;
        mbedtls_rsa_context rsa;
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;

        void print_mbedtls_error(const char *desc, int err) {
            char error_buf[1024];
            mbedtls_strerror(err, error_buf, 1024);
            Serial.println(String(desc) + ": " + error_buf);
        }
};
