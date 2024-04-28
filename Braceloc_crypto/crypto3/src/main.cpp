#include "RSA.h"

RSAEncryptor *encryptor;

void setup() {
Serial.begin(9600);
encryptor = new RSAEncryptor();
}

void loop() {
    unsigned char input[150] = "Example AES key"; // Input data
    unsigned char output[512]; // Buffer for the encrypted data
    unsigned char decrypt_output[512]; // Buffer for the decrypted data
    unsigned char buf[512];
    unsigned char hash[32];
    unsigned char signature[256];
    encryptor->encrypt(input, strlen((char*)input), output);
    encryptor->decrypt(output, decrypt_output, sizeof(decrypt_output));
    encryptor->ExportPublicKey(buf, hash, signature); // Ligne ajouté

    delay(5000);  // Pause for 5 seconds between each execution
}

void free_resources() {
delete encryptor;
}
