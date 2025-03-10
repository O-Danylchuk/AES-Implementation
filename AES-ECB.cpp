#include "AES.h"
#include <vector>
#include <random>

class AES_ECB : public AES {
public:
    AES_ECB() = default;

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) {
        std::vector<uint8_t> encryptedData(plaintext.size());

        for (size_t i = 0; i < plaintext.size(); i += 16) {
            uint8_t block[4][4];
            copyToBlock(plaintext.data() + i, block);

            aesEncryptBlock(block, AES::getRoundKeys());

            std::vector<uint8_t> encryptedBlock = blockToVector(block);
            std::copy(encryptedBlock.begin(), encryptedBlock.end(), encryptedData.begin() + i);
        }

        return encryptedData;
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext) {
        std::vector<uint8_t> decryptedData(ciphertext.size());

        for (size_t i = 0; i < ciphertext.size(); i += 16) {
            uint8_t block[4][4];
            copyToBlock(ciphertext.data() + i, block);

            aesDecryptBlock(block, AES::getRoundKeys()); 

            std::vector<uint8_t> decryptedBlock = blockToVector(block);
            std::copy(decryptedBlock.begin(), decryptedBlock.end(), decryptedData.begin() + i);
        }

        return decryptedData;
    }

    void setKey(const std::vector<uint8_t>& key) {
        AES::keyExpansion(key);
    }

private:
    void copyToBlock(const uint8_t* data, uint8_t block[4][4]) {
        for (size_t i = 0; i < 16; ++i) {
            block[i / 4][i % 4] = data[i];
        }
    }

    std::vector<uint8_t> blockToVector(uint8_t block[4][4]) {
        std::vector<uint8_t> vec(16);
        for (size_t i = 0; i < 16; ++i) {
            vec[i] = block[i / 4][i % 4];
        }
        return vec;
    }
};
