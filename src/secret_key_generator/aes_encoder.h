#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "openssl/aes.h"
#include "openssl/evp.h"

class AesEncoder {
public:
    AesEncoder(const std::string& key, const std::string& iv);
    ~AesEncoder();

    std::vector<char> EncryptData(uint8_t* buffer, uint32_t len);

    void ResetIv();

private:
    int Encrypt(uint8_t* src, uint32_t len);

private:
    std::string key_{};
    std::string iv_{};
    std::string initial_iv_{};
    AES_KEY en_key_;
    std::vector<char> encrypt_data_{};
};
