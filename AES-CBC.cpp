#include "AES.h"
#include <vector>
#include <cstdint>
#include <random>

class AES_CBC : public AES {
public:
    AES_CBC() {
        m_iv = generateIV();
    }

    AES_CBC(const size_t keyLen) {
        setKey(AES::generateKey(keyLen));
        m_iv = generateIV();
    }

    AES_CBC(const std::vector<uint8_t>& key) {
        setKey(key);
        m_iv = generateIV();
    }

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> paddedData = addPadding(data);
        std::vector<uint8_t> encryptedData(paddedData.size());
        std::vector<uint8_t> iv = m_iv;

        uint8_t block[4][4];
        for (size_t i = 0; i < paddedData.size(); i += 16) {
            for (size_t j = 0; j < 16; ++j) {
                block[j / 4][j % 4] = paddedData[i + j] ^ iv[j];
            }
            aesEncryptBlock(block, AES::getRoundKeys());
            for (size_t j = 0; j < 16; ++j) {
                iv[j] = block[j / 4][j % 4];
                encryptedData[i + j] = iv[j];
            }
        }
        return encryptedData;
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> decryptedData(data.size());
        std::vector<uint8_t> iv = m_iv;
        uint8_t block[4][4];

        for (size_t i = 0; i < data.size(); i += 16) {
            for (size_t j = 0; j < 16; ++j) {
                block[j / 4][j % 4] = data[i + j];
            }
            aesDecryptBlock(block, AES::getRoundKeys());
            for (size_t j = 0; j < 16; ++j) {
                decryptedData[i + j] = block[j / 4][j % 4] ^ iv[j];
                iv[j] = data[i + j];
            }
        }
        return removePadding(decryptedData);
    }

    void setKey(const std::vector<uint8_t>& key) {
        AES::keyExpansion(key);
    }

    std::vector<uint8_t> generateIV() {
        std::vector<uint8_t> iv(16);
        std::random_device rd; 

        for (auto& byte : iv) {
            byte = rd() % 256;
      }

        return iv;
    }

private:
    std::vector<uint8_t> m_iv;
};  
