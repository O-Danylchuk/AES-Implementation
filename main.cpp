#include <iostream>
#include <vector>
#include <iomanip>
#include <cstring>
#include <cstdint>
#include "AES-CBC.cpp"
#include "AES-ECB.cpp"
#include "AES-CFB.cpp"

void print_hex(const std::vector<uint8_t>& data) {
    for (size_t i = 0; i < data.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    }
    std::cout << std::endl;
}

int main() {

    AES_CBC aes_cbc;
    AES_ECB aes_ecb;
    AES_CFB aes_cfb;

    // Example plaintext block (128-bit / 16 bytes)
    uint8_t plaintext[4][4] = {
        {0x32, 0x88, 0x31, 0xe0},
        {0x43, 0x5a, 0x31, 0x37},
        {0xf6, 0x30, 0x98, 0x07},
        {0xa8, 0x8d, 0xa2, 0x34}
    };

    std::cout << "Original plaintext: " << std::endl;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)plaintext[i][j] << " ";
        }
        std::cout << std::endl;
    }

    // Convert 2D array to vector
    std::vector<uint8_t> plaintext_vec;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            plaintext_vec.push_back(plaintext[i][j]);
        }
    }

    // CBC Mode
    std::cout << "\nTesting AES-CBC Mode:" << std::endl;
    std::vector<uint8_t> ciphertext_cbc = aes_cbc.encrypt(plaintext_vec);
    std::cout << "Encrypted ciphertext (CBC): " << std::endl;
    print_hex(ciphertext_cbc);

    std::vector<uint8_t> deciphertext_cbc = aes_cbc.decrypt(ciphertext_cbc);
    std::cout << "Decrypted plaintext (CBC): " << std::endl;
    print_hex(deciphertext_cbc);

    // ECB Mode
    std::cout << "\nTesting AES-ECB Mode:" << std::endl;
    std::vector<uint8_t> ciphertext_ecb = aes_ecb.encrypt(plaintext_vec);
    std::cout << "Encrypted ciphertext (ECB): " << std::endl;
    print_hex(ciphertext_ecb);

    std::vector<uint8_t> deciphertext_ecb = aes_ecb.decrypt(ciphertext_ecb);
    std::cout << "Decrypted plaintext (ECB): " << std::endl;
    print_hex(deciphertext_ecb);

    // CFB Mode
    std::cout << "\nTesting AES-CFB Mode:" << std::endl;
    std::vector<uint8_t> ciphertext_cfb = aes_cfb.encrypt(plaintext_vec);
    std::cout << "Encrypted ciphertext (CFB): " << std::endl;
    print_hex(ciphertext_cfb);

    std::vector<uint8_t> deciphertext_cfb = aes_cfb.decrypt(ciphertext_cfb);
    std::cout << "Decrypted plaintext (CFB): " << std::endl;
    print_hex(deciphertext_cfb);

    return 0;
}
