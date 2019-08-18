#include <iostream>
#include <memory>
#include <string>

#include "aes_decoder.h"
#include "aes_encoder.h"
#include "secret_key_generator.h"

int main(void) {
    std::string salt_one = "client-salt";
    std::string salt_two = "server-salt.";
    SecretKeyGenerator client_generator;
    client_generator.Init(salt_one, salt_two);
    std::string client_public_key = client_generator.GetPublicKey();

    SecretKeyGenerator server_generator;
    server_generator.Init(salt_one, salt_two);
    std::string server_public_key = server_generator.GetPublicKey();

    // 互换public_key，生成共享密钥
    server_generator.GenerateSharedKey(client_public_key);
    client_generator.GenerateSharedKey(server_public_key);

    std::string client_sign = client_generator.GetClientSign();
    std::string server_sign = server_generator.GetServerSign();

    // 互换签名，接下来验证签名
    server_generator.VerifyClientSign(client_sign);
    client_generator.VerifyServerSign(server_sign);

    // 生成各自的key和iv
    std::string server_key = server_generator.GetKey();
    std::string server_iv = server_generator.GetIv();

    // 打印key和iv
    for (int i = 0; i < 16; ++i) { std::cout << (int)server_key[i] << " "; }
    std::cout << std::endl;
    for (int i = 0; i < 16; ++i) { std::cout << (int)server_iv[i] << " "; }
    std::cout << std::endl;

    std::string client_key = client_generator.GetKey();
    std::string client_iv = client_generator.GetIv();
    // 打印key和iv
    for (int i = 0; i < 16; ++i) { std::cout << (int)client_key[i] << " "; }
    std::cout << std::endl;
    for (int i = 0; i < 16; ++i) { std::cout << (int)client_iv[i] << " "; }
    std::cout << std::endl;

    // std::vector<char> EncryptData(uint8_t* buffer, uint32_t len);
    std::string val = "abcdefghijklmnhelloworld!";
    AesEncoder encoder(client_key, client_iv);
    auto encrypt_data =
            encoder.EncryptData((uint8_t*)val.c_str(), val.length());
    std::string encrypt_val((char*)encrypt_data.data(),
                            (char*)encrypt_data.data() + encrypt_data.size());
    std::cout << encrypt_val << std::endl;

    AesDecoder decoder(server_key, server_iv);
    auto decrypt_data = decoder.DecryptData((uint8_t*)encrypt_data.data(),
                                            encrypt_data.size());
    std::string decrypt_val((char*)decrypt_data.data(),
                            (char*)decrypt_data.data() + decrypt_data.size());
    std::cout << decrypt_val << std::endl;

    // 接下来就可以使用加密算法进行加密解密了

    return 0;
}
