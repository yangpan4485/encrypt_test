本项目使用ed25519公钥签名系统生成签名，密钥，向量iv，然后使用openssl中AES-CBC进行加解密
需要提前安装好conan的环境（或者安装Openssl，然后修改CMakeLists.txt文件）
选用canch作为单元测试工具
编译运行步骤
1、mkdir build
2、cd build
3、conan remote add conan-center "https://conan.bintray.com"
4、conan install .. -r conan-center
5、cmake ..
6、make
7、./bin/encrypt_test 或者 ./bin/catch_test
