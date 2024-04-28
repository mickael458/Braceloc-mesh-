#include "AES.h"
// Function to initialize LoRa
void initLoRa() {
    LoRa.begin(866E6); // Initialize LoRa at 915 MHz, change according to your region
    Serial.println("LoRa initialized");
}

// Function to securely get an encryption key and IV from the user
/*void getUserKeyAndIV(unsigned char *key, size_t key_len, unsigned char *iv, size_t iv_len) {
    Serial.println("Enter your encryption key (16 characters): ");
    int count = 0;
    while (count < key_len) {
        if (Serial.available()) {
            char c = Serial.read();
            if (c == '\n') break;
            key[count] = c;
            count++;
        }
    }
    Serial.println("Enter IV (16 characters for CBC):");
    count = 0;
    while (count < iv_len) {
        if (Serial.available()) {
            char c = Serial.read();
            if (c == '\n') break;
            iv[count] = c;
            count++;
        }
    }
}

void setup() {
    Serial.begin(9600);
    while (!Serial);

    initLoRa();

    AESManager aesManager;
    unsigned char key[16];
    unsigned char iv[16];
    unsigned char text[64];
    unsigned char enc_out[64];
    unsigned char dec_out[64];

    memset(text, 0, sizeof(text));

    getUserKeyAndIV(key, sizeof(key), iv, sizeof(iv));

    Serial.println("Enter text to encrypt: ");
    int count = 0;
    while (count < sizeof(text) - 1) {
        if (Serial.available()) {
            char c = Serial.read();
            if (c == '\n') break;
            text[count] = c;
            count++;
        }
    }
    text[count] = '\0';

    aesManager.encryptCBC(text, strlen((char *)text), key, iv, enc_out);

    Serial.print("Encrypted text: ");
    for (int i = 0; i < sizeof(enc_out); i++) {
        Serial.print(enc_out[i], HEX);
        Serial.print(" ");
    }
    Serial.println();

    aesManager.decryptCBC(enc_out, sizeof(enc_out), key, iv, dec_out);
    dec_out[sizeof(dec_out) - 1] = '\0';

    Serial.print("Decrypted text: ");
    Serial.print((char *)dec_out);

    LoRa.beginPacket();
    LoRa.write(enc_out, sizeof(enc_out));
    LoRa.endPacket();
    Serial.println("Encrypted text sent over LoRa");
}

void loop() {
    // Nothing to do here
}*/
void setup() {
    Serial.begin(9600);
    while (!Serial);

    AESManager aesManager;
    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x00, 0x01, 0x03, 0x45, 0x35, 0xBB, 0xAD, 0xEF}; // Example key
    unsigned char iv[16] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}; // Example IV
    unsigned char text[64] = "Hello World! This is a test.";  // Example text
    unsigned char enc_out[80];  // Buffer size includes potential padding
    unsigned char dec_out[80];


    aesManager.encryptCBC(text, strlen((char *)text), key, iv, enc_out);

    Serial.print("Encrypted text: ");
    for (int i = 0; i < sizeof(enc_out); i++) {
        Serial.print(enc_out[i], HEX);
        Serial.print(" ");
    }
    Serial.println();

    // Ajoutez des logs pour vérifier la clé et l'IV
    Serial.print("Clé utilisée: ");
    for (int i = 0; i < 16; i++) {
        Serial.print(key[i], HEX);
        Serial.print(" ");
    }
    Serial.println();

    Serial.print("IV utilisé: ");
    for (int i = 0; i < 16; i++) {
        Serial.print(iv[i], HEX);
        Serial.print(" ");
    }
    Serial.println();

    aesManager.decryptCBC(enc_out, sizeof(enc_out), key, iv, dec_out);
    //dec_out[strlen((char *)text)] = '\0'; // Assuming no padding removal needed

    Serial.print("Decrypted text: ");
    /*for (size_t i = 0; i < strlen((char *)text); i++) {
        Serial.print(dec_out[i]);
        Serial.print(" ");
    }*/
    Serial.println((char *)dec_out); // Affichage en tant que caractères ASCII
    Serial.println();
}

void loop() {
  // Nothing to do here
}