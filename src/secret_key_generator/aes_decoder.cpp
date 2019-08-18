#include "aes_decoder.h"

namespace {
const uint32_t kBufferSize = 16;
const uint32_t kAesBits = 128;  // 128 bits == 16Byte
}  // namespace

AesDecoder::AesDecoder(const std::string& key, const std::string& iv)
        : key_(key), iv_(iv), initial_iv_(iv) {
    OPENSSL_cleanse(NULL, 0);
    AES_set_decrypt_key((uint8_t*)key_.c_str(), kAesBits, &de_key_);
}

AesDecoder::~AesDecoder() {}

void AesDecoder::ResetIv() { iv_ = initial_iv_; }

std::vector<char> AesDecoder::DecryptData(uint8_t* buffer, uint32_t len) {
    std::vector<char>().swap(decrypt_data_);
    int decrypt_size = len - (len % kBufferSize);
    if (decrypt_size > 0) { Decrypt(buffer, decrypt_size); }
    decrypt_data_.insert(decrypt_data_.end(), buffer + decrypt_size,
                         buffer + len);
    return decrypt_data_;
}

int AesDecoder::Decrypt(uint8_t* src, uint32_t len) {
    if (len < 1) { return -1; }
    uint8_t* buffer = new uint8_t[len];

    AES_cbc_encrypt((uint8_t*)src, (uint8_t*)buffer, (size_t)len, &de_key_,
                    (uint8_t*)iv_.c_str(), AES_DECRYPT);
    decrypt_data_.insert(decrypt_data_.end(), buffer, buffer + len);
    delete[] buffer;
    buffer = nullptr;
    return 1;
}
