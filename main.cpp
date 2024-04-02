//#include <algorithm>
//#include <cstring>
#include <fstream>
#include <iostream>
#include <openssl/rsa.h>
#include <string>
//#include <vector>
//#include <iterator>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

void OnError(const char* msg){
    std::cerr << "[ ERROR ] " << msg << std::endl;
}

bool GenKeyFormPASSWD(const std::string& pwd, unsigned char* key, unsigned char* ivec){
    if(EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), nullptr, reinterpret_cast<const unsigned char*>(pwd.c_str()), pwd.length(), 1, key, ivec) != static_cast<int>(EVP_CIPHER_key_length(EVP_aes_256_cbc()))){
        OnError("Failed to derive key from password!");
        return false;
    }

    return true;
}

void Encrypt(const std::string& inFile, const std::string& outFile, const std::string& passwd){
    std::ifstream ifs(inFile, std::ios::binary);
    if(!ifs){
        OnError("Could not open target file for encryption");
        return;
    }

    std::ofstream ofs(outFile, std::ios::binary);
    if(!ofs){
        OnError("Could not create or open output file for encryption");
        ifs.close();
        return;
    }

    // Generate encryption key based on password
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char ivec[EVP_MAX_IV_LENGTH];
    if(!GenKeyFormPASSWD(passwd, key, ivec)){
        ifs.close();
        ofs.close();
        return;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx){
        OnError("Failed to create encryptions context");
        ifs.close();
        ofs.close();
        return;
    }

    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, ivec) != 1){
        OnError("Failed encryption initialization");
        ifs.close();
        ofs.close();
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    unsigned char inBuf[1024], outBuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int outLen, totalLen = 0;
    while(ifs.good()){
        ifs.read(reinterpret_cast<char*>(inBuf), sizeof(inBuf));
        int bytesRead = static_cast<int>(ifs.gcount());

        if(EVP_EncryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead) != 1){ // encrypts a block of data
            OnError("Encryption error");
            EVP_CIPHER_CTX_free(ctx);
            return;
        }

        totalLen += outLen;
        ofs.write(reinterpret_cast<const char*>(outBuf), outLen);
    }

    ifs.close();

    if(EVP_EncryptFinal_ex(ctx, outBuf, &outLen) != 1){
        OnError("Encryption finalization error");
        EVP_CIPHER_CTX_free(ctx);
        ofs.close();
        return;
    }

    totalLen += outLen;
    ofs.write(reinterpret_cast<const char*>(outBuf), outLen);
    ofs.close();

    EVP_CIPHER_CTX_free(ctx);

    std::cout << "Encryption success. Total bytes encrypted: " << totalLen << std::endl;
}

void Decrypt(const std::string& inFile, const std::string& outFile, const std::string& passwd){
    std::ifstream ifs(inFile, std::ios::binary);
    if(!ifs){
        OnError("Could not open target file for decryption");
        return;
    }

    std::ofstream ofs(outFile, std::ios::binary);
    if(!ofs){
        OnError("Could not create or open output file for decryption");
        ifs.close();
        return;
    }

    // Generate encryption key based on password
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char ivec[EVP_MAX_IV_LENGTH];
    if(!GenKeyFormPASSWD(passwd, key, ivec)){
        ifs.close();
        ofs.close();
        return;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx){
        OnError("Failed to create decryption context");
        ifs.close();
        ofs.close();
        return;
    }

    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, ivec) != 1){
        OnError("Failed to initialize decryption");
        EVP_CIPHER_CTX_free(ctx);
        ifs.close();
        ofs.close();
        return;
    }

    unsigned char inBuf[1024 + EVP_MAX_BLOCK_LENGTH], outBuf[1024];
    int outLen, totalLen = 0;
    while(ifs.good()){
        ifs.read(reinterpret_cast<char*>(inBuf), sizeof(inBuf));
        int bytesRead = static_cast<int>(ifs.gcount());

        if(EVP_DecryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead) != 1){
            OnError("Decryption Error");
            EVP_CIPHER_CTX_free(ctx);
            return;
        }

        totalLen += outLen;
        ofs.write(reinterpret_cast<const char*>(outBuf), outLen);
    }

    ifs.close();

    if(EVP_DecryptFinal_ex(ctx, outBuf, &outLen) != 1){
        OnError("Decryption finalization error");
        EVP_CIPHER_CTX_free(ctx);
        ofs.close();
        return;
    }

    totalLen += outLen;
    ofs.write(reinterpret_cast<const char*>(outBuf), outLen);
    ofs.close();

    EVP_CIPHER_CTX_free(ctx);

    std::cout << "Decryption success. Total decrypted bytes: " << totalLen << std::endl;
}

int main(void){
    std::string pw = "password";
    Encrypt("Helo.test", "Helo.encr", pw);
    Decrypt("Helo.encr", "Helo.decr", pw);
    return 0;
}