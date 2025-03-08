#pragma once

#include <vector>
#include <cstdint>

class BaseAES {
public:
    virtual ~BaseAES() = default;

    virtual std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data) = 0;

    virtual std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data) = 0;

    virtual void setKey(const std::vector<uint8_t>& key) = 0;

protected:
    std::vector<uint8_t> key;
};
