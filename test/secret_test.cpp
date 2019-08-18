#include "catch.hpp"

#include <iostream>
#include <memory>
#include <string>

#include "secret_key_generator.h"

TEST_CASE("exchange secret key and iv", "[secret_key][secret_iv]") {
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

    std::string client_key = client_generator.GetKey();
    std::string client_iv = client_generator.GetIv();

    REQUIRE(client_key == server_key);
    REQUIRE(client_iv == server_iv);
}
