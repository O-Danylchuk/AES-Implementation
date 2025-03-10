#include "AES.h"
#include <vector>
#include <random>

class AES_CFB : public AES {
public:
    AES_CFB() {
        m_iv = generateIV();
    }

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> encryptedData(data.size());
        std::vector<uint8_t> iv = m_iv;

        uint8_t block[4][4];
        std::vector<uint8_t> xorBlock(16);

        for (size_t i = 0; i < data.size(); i += 16) {
            uint8_t block[4][4];

            copyToBlock(iv, block);
            aesEncryptBlock(block, AES::getRoundKeys());

            std::vector<uint8_t> keystream = blockToVector(block);
            
            for (size_t j = 0; j < 16 && (i + j) < data.size(); ++j) {
                encryptedData[i + j] = data[i + j] ^ keystream[j];
            }
            
            iv.assign(encryptedData.begin() + i, encryptedData.begin() + std::min(i + 16, data.size()));
        }

        return encryptedData;
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> decryptedData(data.size());
        std::vector<uint8_t> iv = m_iv;

        uint8_t block[4][4];
        std::vector<uint8_t> xorBlock(16);

        for (size_t i = 0; i < data.size(); i += 16) {
            uint8_t block[4][4];

            copyToBlock(iv, block);
            aesEncryptBlock(block, AES::getRoundKeys());

            std::vector<uint8_t> keystream = blockToVector(block);
            
            for (size_t j = 0; j < 16 && (i + j) < data.size(); ++j) {
                decryptedData[i + j] = data[i + j] ^ keystream[j];
            }
            
            iv.assign(data.begin() + i, data.begin() + std::min(i + 16, data.size()));
        }

        return decryptedData;

    }

    void setKey(const std::vector<uint8_t>& key) {
        AES::keyExpansion(key);
    }

private:
    std::vector<uint8_t> m_iv;
    std::vector<uint8_t> generateIV() {
        std::vector<uint8_t> iv(16);
        std::random_device rd;

        for (size_t i = 0; i < 16; ++i) {
            iv[i] = rd() % 256;
        }

        return iv;
    }

    void copyToBlock(const std::vector<uint8_t>& data, uint8_t block[4][4]) {
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
