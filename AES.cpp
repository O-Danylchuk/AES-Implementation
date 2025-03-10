#include "AES.h"
#include <random>

std::vector<uint8_t> AES::generateKey()
{
    std::vector<uint8_t> key(16);
    std::random_device rd;

    for (size_t i = 0; i < 16; ++i) {
        key[i] = rd() % 256;
    }

    return key;
}

AES::AES()
{
    keyExpansion(generateKey());
}

AES::AES(const std::vector<uint8_t> &key)
{
    keyExpansion(key);
}

void AES::keyExpansion(const std::vector<uint8_t> &key)
{
    size_t keySize = key.size();
    size_t expandedKeySize = 0;
    size_t numRounds = 0;

    if (keySize == 16) {        // AES-128
        expandedKeySize = 176;
        numRounds = 10;
    } else if (keySize == 24) { // AES-192
        expandedKeySize = 208;
        numRounds = 12;
    } else if (keySize == 32) { // AES-256
        expandedKeySize = 240;
        numRounds = 14;
    } else {
        std::cerr << "Invalid key size. Supported sizes: 128, 192, 256 bits." << std::endl;
        return;
    }

    roundKeys.resize(expandedKeySize);

    for (size_t i = 0; i < keySize; ++i) {
        roundKeys[i] = key[i];
    }

    uint8_t temp[4];
    size_t bytesGenerated = keySize;
    int rcon = 1;

    while (bytesGenerated < expandedKeySize)
    {
        for (uint8_t i = 0; i < 4; ++i) {
            temp[i] = roundKeys[bytesGenerated - 4 + i];
        }

        if (bytesGenerated % keySize == 0) {
            // RotWord
            uint8_t t = temp[0];
            temp[0] = sbox[temp[1]] ^ rcon;
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[t];

            rcon = (rcon << 1) ^ (rcon & 0x80 ? 0x1B : 0x00); // GF(2⁸) multiplication
        }
        else if (keySize == 32 && bytesGenerated % keySize == 16) {
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
        }

        for (uint8_t i = 0; i < 4; ++i) {
            roundKeys[bytesGenerated] = roundKeys[bytesGenerated - keySize] ^ temp[i];
            bytesGenerated++;
        }
    }
}

void AES::printRoundKeys() {
    for (size_t i = 0; i < roundKeys.size(); i++) {
        printf("%02X ", roundKeys[i]);
        if ((i + 1) % 16 == 0) std::cout << std::endl;
    }
}

void AES::addRoundKey(uint8_t state[4][4], const uint8_t* roundKey) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] ^= roundKey[i * 4 + j];
        }
    }
}

void AES::subBytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = sbox[state[i][j]];
        }
    }
}

void AES::shiftRows(uint8_t state[4][4]) {
    uint8_t temp[4][4];

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            temp[i][j] = state[i][j];
        }
    }

    for (int i = 1; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = temp[i][(j + i) % 4];
        }
    }
}

uint8_t AES::gmul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) result ^= a;
        bool highBit = a & 0x80;
        a <<= 1;
        if (highBit) a ^= 0x1B;
        b >>= 1;
    }
    return result;
}

void AES::mixColumns(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
        uint8_t a = state[0][i], b = state[1][i], c = state[2][i], d = state[3][i];
        state[0][i] = gmul(a, 2) ^ gmul(b, 3) ^ c ^ d;
        state[1][i] = a ^ gmul(b, 2) ^ gmul(c, 3) ^ d;
        state[2][i] = a ^ b ^ gmul(c, 2) ^ gmul(d, 3);
        state[3][i] = gmul(a, 3) ^ b ^ c ^ gmul(d, 2);
    }
}

void AES::invSubBytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = invSbox[state[i][j]];
        }
    }
}

void AES::invShiftRows(uint8_t state[4][4]) {
    uint8_t temp[4][4];

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            temp[i][j] = state[i][j];
        }
    }

    for (int i = 1; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = temp[i][(j - i + 4) % 4];
        }
    }
}

void AES::invMixColumns(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
        uint8_t a = state[0][i], b = state[1][i], c = state[2][i], d = state[3][i];
        state[0][i] = gmul(a, 0x0E) ^ gmul(b, 0x0B) ^ gmul(c, 0x0D) ^ gmul(d, 0x09);
        state[1][i] = gmul(a, 0x09) ^ gmul(b, 0x0E) ^ gmul(c, 0x0B) ^ gmul(d, 0x0D);
        state[2][i] = gmul(a, 0x0D) ^ gmul(b, 0x09) ^ gmul(c, 0x0E) ^ gmul(d, 0x0B);
        state[3][i] = gmul(a, 0x0B) ^ gmul(b, 0x0D) ^ gmul(c, 0x09) ^ gmul(d, 0x0E);
    }
}

void AES::aesDecryptBlock(uint8_t state[4][4], const std::vector<uint8_t>& roundKeys) {
    // Add the round key for the last round (round 10)
    addRoundKey(state, &roundKeys[160]);

    // Perform rounds 9 through 1
    for (int round = 9; round > 0; --round) {
        invSubBytes(state);
        invShiftRows(state);
        addRoundKey(state, &roundKeys[round * 16]); 
        invMixColumns(state);
    }

    invSubBytes(state);
    invShiftRows(state);
    addRoundKey(state, roundKeys.data());  // Use the first round key (index 0)
}

void AES::aesEncryptBlock(uint8_t state[4][4], const std::vector<uint8_t>& roundKeys) {
    // Add the round key for the first round (round 1)
    addRoundKey(state, roundKeys.data());

    for (int round = 0; round < 9; ++round) {
        subBytes(state);      
        shiftRows(state);     
        mixColumns(state);   
        addRoundKey(state, &roundKeys[(round + 1) * 16]);
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, &roundKeys[160]);  // Use the last round key (round 10)
}
