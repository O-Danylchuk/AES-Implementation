#include "BASE-AES.h"

class AES_CFB : public BaseAES {
public:
    AES_CFB() = default;

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data) override;

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data) override;

    void setKey(const std::vector<uint8_t>& key) override;
};  
