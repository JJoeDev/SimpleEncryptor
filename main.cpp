#include <fstream>
#include <iostream>
#include <openssl/rsa.h>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

void OnError(const char* msg, EVP_CIPHER_CTX* ctx = nullptr, std::ifstream* ifs = nullptr, std::ofstream* ofs = nullptr){
    std::cerr << "[ ERROR ] " << msg << std::endl;
    if(ctx) EVP_CIPHER_CTX_free(ctx);
    if(ifs) ifs->close();
    if(ofs) ofs->close();
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
        OnError("Could not create or open output file for encryption", nullptr, &ifs);
        return;
    }

    // Generate encryption key based on password
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char ivec[EVP_MAX_IV_LENGTH];
    if(!GenKeyFormPASSWD(passwd, key, ivec)){
        OnError("No Key generated. Exiting", nullptr, &ifs, &ofs);
        return;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx){
        OnError("Failed to create encryptions context", nullptr, &ifs, &ofs);
        return;
    }

    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, ivec) != 1){
        OnError("Failed encryption initialization", ctx, &ifs, &ofs);
        return;
    }

    unsigned char inBuf[1024], outBuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int outLen, totalLen = 0;
    while(ifs.good()){
        ifs.read(reinterpret_cast<char*>(inBuf), sizeof(inBuf));
        int bytesRead = static_cast<int>(ifs.gcount());

        if(EVP_EncryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead) != 1){ // encrypts a block of data
            OnError("Encryption error", ctx, &ifs, &ofs);
            return;
        }

        totalLen += outLen;
        ofs.write(reinterpret_cast<const char*>(outBuf), outLen);
    }

    ifs.close();

    if(EVP_EncryptFinal_ex(ctx, outBuf, &outLen) != 1){
        OnError("Encryption finalization error", ctx, nullptr, &ofs);
        return;
    }

    totalLen += outLen;
    ofs.write(reinterpret_cast<const char*>(outBuf), outLen);
    ofs.close();

    EVP_CIPHER_CTX_free(ctx);

    std::cout << "Encryption success. Total bytes encrypted: " << totalLen << std::endl;
}

void Decrypt(const std::string& inFile, const std::string& outFile, const std::string& passwd, bool print = false){
    std::cout << "\nBeginning decryption of " << inFile << "\n\n";

    std::ifstream ifs(inFile, std::ios::binary);
    std::ofstream ofs;
    if(!ifs){
        OnError("Could not open target file for decryption");
        return;
    }

    if(!print){
        ofs.open(outFile, std::ios::binary);
        if(!ofs){
            OnError("Could not create or open output file for decryption", nullptr, &ifs);
            return;
        }
    }

    // Generate encryption key based on password
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char ivec[EVP_MAX_IV_LENGTH];
    if(!GenKeyFormPASSWD(passwd, key, ivec)){
        OnError("No Key generated. Exiting", nullptr, &ifs, &ofs);
        return;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx){
        OnError("Failed to create decryption context", nullptr, &ifs, &ofs);
        return;
    }

    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, ivec) != 1){
        OnError("Failed to initialize decryption", ctx, &ifs, &ofs);
        return;
    }

    unsigned char inBuf[1024 + EVP_MAX_BLOCK_LENGTH], outBuf[1024];
    int outLen, totalLen = 0;
    while(ifs.good()){
        ifs.read(reinterpret_cast<char*>(inBuf), sizeof(inBuf));
        int bytesRead = static_cast<int>(ifs.gcount());

        if(EVP_DecryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead) != 1){
            OnError("Decryption Error", ctx, &ifs, &ofs);
            return;
        }

        totalLen += outLen;

        if(!print)
            ofs.write(reinterpret_cast<const char*>(outBuf), outLen);
        else
            std::cout.write(reinterpret_cast<const char*>(outBuf), outLen);
    }

    ifs.close();

    if(EVP_DecryptFinal_ex(ctx, outBuf, &outLen) != 1){
        OnError("Decryption finalization error", ctx, nullptr, &ofs);
        return;
    }

    totalLen += outLen;

    if(!print){
        ofs.write(reinterpret_cast<const char*>(outBuf), outLen);
        ofs.close();
    }
    else
        std::cout.write(reinterpret_cast<const char*>(outBuf), outLen);

    EVP_CIPHER_CTX_free(ctx);

    std::cout << "\n\nDecryption success. Total decrypted bytes: " << totalLen << std::endl;
}

void UserInput(){
    std::string pw;
    std::string targetFile;
    std::string outputFile;
    char operation;

    std::cout << "What operation are we doing today?\n"\
                    "1: Encryption\n"\
                    "2: Decryption to file\n"\
                    "3: Decryption to terminal\n ~ ";
    std::cin >> operation;
    std::cin.ignore();

    std::cout << " ~ Name of target file: ";
    std::cin >> targetFile;
    std::cout << " ~ (ignore if option 3) Name of output file: ";
    std::cin >> outputFile;

    std::cout << " ~ Password: ";
    std::cin >> pw;
    std::cin.ignore();

    switch(operation){
    case '1':
        Encrypt(targetFile, outputFile, pw);
        break;
    case '2':
        Decrypt(targetFile, outputFile, pw);
        break;
    case '3':
        Decrypt(targetFile, outputFile, pw, true);
        break;
    default:
        OnError("The option choosen in the beginning is not a valid option. Valid options include 1 and 2");
    }
}

int main(void){
    UserInput();

    return 0;
}