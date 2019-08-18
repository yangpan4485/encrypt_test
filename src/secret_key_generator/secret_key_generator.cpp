#include "secret_key_generator.h"

#include <iostream>

extern "C" {
#include "ed25519.h"
#include "ge.h"
#include "sc.h"
#include "sha512.h"
}

SecretKeyGenerator::SecretKeyGenerator() {}

SecretKeyGenerator::~SecretKeyGenerator() {}

bool SecretKeyGenerator::Init(const std::string& salt_one,
                              const std::string& salt_two) {
    // 首先先把两个盐串保存起来
    // 盐串1给client使用，盐串2给server使用
    salt_one_ = salt_one;
    salt_two_ = salt_two;
    context_.reset(new SecretKeyContext());
    // 创建32字节的随机数种子
    uint8_t seed[32] = "";
    if (ed25519_create_seed(seed) != 0) {
        return false;
    }
    // 生成密钥对，public_key：32字节，private_key：64字节
    ed25519_create_keypair(context_->public_key, context_->private_key, seed);
    // 到这里公钥和私钥已经生成完成了
    return true;
}

std::string SecretKeyGenerator::GetPublicKey() {
    if (context_ == nullptr) {
        return "";
    }
    std::string public_key((char*)context_->public_key,
                           (char*)context_->public_key + 32);
    return public_key;
}

bool SecretKeyGenerator::GenerateSharedKey(
    const std::string& adverse_public_key) {
    if (context_ == nullptr || adverse_public_key.length() != 32) {
        return false;
    }

    ed25519_key_exchange(context_->shared_key,
                         (uint8_t*)adverse_public_key.c_str(),
                         context_->private_key);

    return true;
}

std::string SecretKeyGenerator::GetClientSign() {
    if (!GenerateClientSign()) {
        return "";
    }
    return sign_;
}

std::string SecretKeyGenerator::GetServerSign() {
    if (!GenerateServerSign()) {
        return "";
    }
    return sign_;
}

bool SecretKeyGenerator::VerifyClientSign(const std::string& client_sign) {
    if (context_ == nullptr || client_sign.length() != 64) {
        return false;
    }
    // 验证client的签名
    // 1、先生成client的msg
    uint8_t client_msg[64];
    GenerateSecretMsg(client_msg, context_->adverse_public_key, 32, salt_one_);
    // 2、验证client的签名
    if (ed25519_verify((uint8_t*)client_sign.c_str(), client_msg,
                       sizeof(client_msg), context_->adverse_public_key) != 1) {
        return false;
    }
    return true;
}

bool SecretKeyGenerator::VerifyServerSign(const std::string& server_sign) {
    if (context_ == nullptr || server_sign.length() != 64) {
        return false;
    }
    // 验证server的签名
    // 1、先生成server的msg
    uint8_t server_msg[64];
    GenerateSecretMsg(server_msg, context_->adverse_public_key, 32, salt_two_);
    // 2、验证server的签名
    if (ed25519_verify((uint8_t*)server_sign.c_str(), server_msg,
                       sizeof(server_msg), context_->adverse_public_key) != 1) {
        return false;
    }
    return true;
}

std::string SecretKeyGenerator::GetKey() {
    if (context_ == nullptr) {
        return "";
    }
    // 生成key
    // 使用shared_key和盐串1生成key
    // key的最大长度可以是64位，根据需求自己截断
    uint8_t secret_msg[64] = "";
    // 现在就是生成secret_msg了
    if (!GenerateSecretMsg(secret_msg, context_->shared_key, 32, salt_one_)) {
        return "";
    }
    std::string key((char*)secret_msg, (char*)secret_msg + 16);

    return key;
}

std::string SecretKeyGenerator::GetIv() {
    if (context_ == nullptr) {
        return "";
    }
    // 生成向量iv
    // 使用shared_key和盐串2生成向量iv
    // iv的最大长度也可以是64位，根据自己需求进行截断
    uint8_t secret_msg[64] = "";
    // 现在就是生成secret_msg了
    if (!GenerateSecretMsg(secret_msg, context_->shared_key, 32, salt_two_)) {
        return "";
    }
    std::string iv((char*)secret_msg, (char*)secret_msg + 16);

    return iv;
}

bool SecretKeyGenerator::GenerateClientSign() {
    if (context_ == nullptr) {
        return false;
    }
    uint8_t signature[64] = "";
    uint8_t secret_msg[64] = "";
    // 现在就是生成secret_msg了
    if (!GenerateSecretMsg(secret_msg, context_->public_key, 32, salt_one_)) {
        return false;
    }
    // 生成签名
    ed25519_sign(signature, secret_msg, sizeof(secret_msg),
                 context_->public_key, context_->private_key);
    sign_ = std::string((char*)signature, (char*)signature + 64);
    return true;
}

bool SecretKeyGenerator::GenerateServerSign() {
    if (context_ == nullptr) {
        return false;
    }
    uint8_t signature[64] = "";
    uint8_t secret_msg[64] = "";
    // 现在就是生成secret_msg了，只要盐串固定，那么生成的msg就是固定的
    if (!GenerateSecretMsg(secret_msg, context_->public_key, 32, salt_two_)) {
        return false;
    }
    // 生成签名
    // 通过msg和公钥，私钥生成属于自己的签名，只要公钥，私钥，message固定，那么生成的签名也是固定的
    ed25519_sign(signature, secret_msg, sizeof(secret_msg),
                 context_->public_key, context_->private_key);
    sign_ = std::string((char*)signature, (char*)signature + 64);
    return true;
}

bool SecretKeyGenerator::GenerateSecretMsg(uint8_t secret_msg[64],
                                           uint8_t* salt_msg,
                                           uint32_t salt_msg_len,
                                           const std::string& salt) {
    if (context_ == nullptr || secret_msg == nullptr || salt.empty()) {
        return false;
    }
    sha512_context hash;
    // 初始化
    sha512_init(&hash);
    // 计算hash，多次hash更加安全，可以使用更加复杂的盐串
    sha512_update(&hash, (uint8_t*)salt.c_str(), salt.length());
    sha512_update(&hash, salt_msg, salt_msg_len);
    // 取结果
    sha512_final(&hash, secret_msg);
    return true;
}
