#include "aes_encoder.h"

namespace {
const uint32_t kBufferSize = 16;
const uint32_t kAesBits = 128;  // 128 bits == 16Byte
}  // namespace

AesEncoder::AesEncoder(const std::string& key, const std::string& iv)
        : key_(key), iv_(iv), initial_iv_(iv) {
    OPENSSL_cleanse(NULL, 0);
    AES_set_encrypt_key((uint8_t*)key_.c_str(), kAesBits, &en_key_);
}

AesEncoder::~AesEncoder() {}

void AesEncoder::ResetIv() { iv_ = initial_iv_; }

std::vector<char> AesEncoder::EncryptData(uint8_t* buffer, uint32_t len) {
    std::vector<char>().swap(encrypt_data_);
    int encrypt_size = len - (len % kBufferSize);
    if (encrypt_size > 0) { Encrypt(buffer, encrypt_size); }
    encrypt_data_.insert(encrypt_data_.end(), buffer + encrypt_size,
                         buffer + len);
    return encrypt_data_;
}

int AesEncoder::Encrypt(uint8_t* src, uint32_t len) {
    if (len < 1) { return -1; }
    uint8_t* buffer = new uint8_t[len];
    AES_cbc_encrypt((uint8_t*)src, (uint8_t*)buffer, (size_t)len, &en_key_,
                    (uint8_t*)iv_.c_str(), AES_ENCRYPT);
    encrypt_data_.insert(encrypt_data_.end(), buffer, buffer + len);
    delete[] buffer;
    buffer = nullptr;
    return 1;
}
