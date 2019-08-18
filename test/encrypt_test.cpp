#include "catch.hpp"

#include <iostream>
#include <memory>
#include <string>

#include "aes_decoder.h"
#include "aes_encoder.h"

TEST_CASE("data encrypt and decrypt", "[encrypt]") {
    std::string key = "helloworld123456";
    std::string iv = "c++processinghao";
    std::shared_ptr<AesEncoder> aes_encoder =
        std::make_shared<AesEncoder>(key, iv);
    std::shared_ptr<AesDecoder> aes_decoder =
        std::make_shared<AesDecoder>(key, iv);

    std::string test_data = "study hard and make progress every day";

    std::vector<char> encrypt_data = aes_encoder->EncryptData(
        (uint8_t*)test_data.c_str(), test_data.length());
    std::vector<char> decrypt_data = aes_decoder->DecryptData(
        (uint8_t*)encrypt_data.data(), encrypt_data.size());
    std::string data((char*)decrypt_data.data(),
                     (char*)decrypt_data.data() + decrypt_data.size());

    REQUIRE(test_data == data);
}
