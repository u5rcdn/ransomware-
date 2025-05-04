#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>

namespace fs = std::filesystem;
using namespace CryptoPP;

void decrypt_file(const std::string& filepath, const SecByteBlock& key, const byte iv[AES::BLOCKSIZE]) {
    try {
        std::ifstream in(filepath, std::ios::binary);
        std::string encrypted((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();

        std::string decrypted;
        CBC_Mode<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(key, key.size(), iv);

        StringSource ss(encrypted, true,
            new StreamTransformationFilter(decryptor,
                new StringSink(decrypted)
            )
        );

        std::string originalPath = filepath.substr(0, filepath.find_last_of("."));
        std::ofstream out(originalPath, std::ios::binary);
        out.write(decrypted.data(), decrypted.size());
        out.close();
        fs::remove(filepath);
        std::cout << "[+] Decrypted: " << originalPath << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "[-] Failed to decrypt " << filepath << ": " << e.what() << std::endl;
    }
}

int main() {
    std::string home = getenv("HOME");
    std::string targetDir = home + "/Desktop/test";

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    byte iv[AES::BLOCKSIZE];

    std::ifstream keyFile("aes.key", std::ios::binary);
    if (!keyFile) {
        std::cerr << "[-] Kalit fayli 'aes.key' topilmadi!" << std::endl;
        return 1;
    }

    keyFile.read(reinterpret_cast<char*>(&key[0]), key.size());
    keyFile.read(reinterpret_cast<char*>(&iv[0]), AES::BLOCKSIZE);
    keyFile.close();

    for (const auto& entry : fs::directory_iterator(targetDir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".enc") {
            decrypt_file(entry.path().string(), key, iv);
        }
    }

    std::cout << "all files encoded ! " << std::endl;
    return 0;
}
