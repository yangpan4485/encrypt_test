#pragma once

#include <cstdint>
#include <string>

struct SecretKeyContext {
    uint8_t public_key[32];
    uint8_t private_key[64];
    uint8_t adverse_public_key[32];
    uint8_t shared_key[32];
};

class SecretKeyGenerator {
   public:
    SecretKeyGenerator();

    ~SecretKeyGenerator();

    bool Init(const std::string& salt_one, const std::string& salt_two);

    std::string GetPublicKey();

    bool GenerateSharedKey(const std::string& adverse_public_key);

    std::string GetClientSign();

    std::string GetServerSign();

    bool VerifyClientSign(const std::string& client_sign);

    bool VerifyServerSign(const std::string& client_sign);

    std::string GetKey();

    std::string GetIv();

   private:
    bool GenerateClientSign();

    bool GenerateServerSign();

    bool GenerateSecretMsg(uint8_t secret_msg[64], uint8_t* salt_msg,
                           uint32_t salt_msg_len, const std::string& salt);

   private:
    std::unique_ptr<SecretKeyContext> context_ = nullptr;
    std::string salt_one_;
    std::string salt_two_;
    std::string sign_;
};
