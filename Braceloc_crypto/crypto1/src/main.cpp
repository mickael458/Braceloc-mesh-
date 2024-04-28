#include "AES.h"
#include "RSA.h"

RSAEncryptor *encryptor;


// Variable pour stocker la clé AES
byte aesKey[16];

// Fonction pour convertir deux caractères hexadécimaux en un octet
byte hexCharToByte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    return 0; // En cas de caractère non hexadécimal
}

// Fonction pour lire une clé AES de l'utilisateur
int readAESKey(byte* key) {
    char hexKey[32]; // 16 octets x 2 caractères par octet
    int index = 0;

    while (index < 32) {
        if (Serial.available() > 0) {
            char c = Serial.read();
            if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
                Serial.print(c); // Écho des caractères valides
                hexKey[index++] = c;
            }
        }
    }

    // Convertir la chaîne hexadécimale en octets
    for (int i = 0; i < 16; i++) {
        key[i] = hexCharToByte(hexKey[2*i]) * 16 + hexCharToByte(hexKey[2*i + 1]);
    }

    Serial.println("\nClé AES lue avec succès.");
    return 1; 
}





void setup() {
    Serial.begin(9600);
    encryptor = new RSAEncryptor();
    while (!Serial);
    int a = 0; 
    Serial.println("Veuillez entrer la clé AES (16 octets en hexadécimal):");
    a = readAESKey(aesKey); // Lire la clé AES de l'utilisateur

    // Afficher la clé lue pour vérification
    while (!a)
    {
       Serial.print("Clé AES saisie: ");
        for (int i = 0; i < 16; i++) {
            if (aesKey[i] < 16) Serial.print('0'); // Ajouter un zéro devant pour les nombres < 16
            Serial.print(aesKey[i], HEX);
            Serial.print(" ");
        }
        Serial.println();
  
        delay(10000); // Attendre 10 secondes avant de demander à nouveau     /* code */
    }


    AESManager aesManager;
    //unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x00, 0x01, 0x03, 0x45, 0x35, 0xBB, 0xAD, 0xEF};
    unsigned char text[64] = "Hello World! This is a test.";
    unsigned char enc_out[96]; // Increased buffer size to account for IV

    aesManager.encryptCBC(text, strlen((char *)text), aesKey, enc_out);
    Serial.print("Encrypted text with IV: ");
    for (int i = 0; i < sizeof(enc_out); i++) {
        Serial.print(enc_out[i], HEX);
        Serial.print(" ");
    }
    Serial.println();

    unsigned char dec_out[80];
    aesManager.decryptCBC(enc_out, sizeof(enc_out), aesKey, dec_out);
    dec_out[strlen((char *)text)] = '\0';

    Serial.print("Decrypted text: ");
    Serial.println((char *)dec_out);
    Serial.println();
}

void loop() {
    /*unsigned char output[512]; // Buffer for the encrypted data
    unsigned char decrypt_output[512]; // Buffer for the decrypted data
    unsigned char buf[512];
    unsigned char hash[32];
    unsigned char signature[256];
    encryptor->encrypt(aesKey, strlen((char*)aesKey), output);
    encryptor->decrypt(output, decrypt_output, sizeof(decrypt_output));
    encryptor->ExportPublicKey(buf, hash, signature); // Ligne ajouté

    delay(5000);  // Pause for 5 seconds between each execution*/
}

/*void free_resources() {
    delete encryptor;
}*/
