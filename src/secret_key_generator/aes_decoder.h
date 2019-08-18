#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "openssl/aes.h"
#include "openssl/evp.h"

class AesDecoder {
public:
    AesDecoder(const std::string& key, const std::string& iv);
    ~AesDecoder();
    std::vector<char> DecryptData(uint8_t* buffer, uint32_t len);

    void ResetIv();

private:
    int Decrypt(uint8_t* src, uint32_t len);

private:
    std::string key_{};
    std::string iv_{};
    std::string initial_iv_{};
    std::vector<char> decrypt_data_{};
    AES_KEY de_key_;
};
