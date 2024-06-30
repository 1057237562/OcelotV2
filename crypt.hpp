#ifndef _CRYPT_HPP_
#define _CRYPT_HPP_
#include <functional>
#include <openssl/aes.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace crypto {
typedef unsigned char byte;
inline std::string sha256_string(std::string in)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX* sha256 = EVP_MD_CTX_create();
    EVP_DigestInit_ex(sha256, EVP_sha256(), NULL);
    EVP_DigestUpdate(sha256, in.data(), in.size());
    unsigned int len = 0;
    EVP_DigestFinal_ex(sha256, hash, &len);
    EVP_MD_CTX_destroy(sha256);
    return std::string(hash, hash + SHA256_DIGEST_LENGTH);
}

inline std::string random_string(size_t length, unsigned int seed = 0)
{
    std::default_random_engine engine;
    if (seed)
        engine.seed(seed);
    std::uniform_int_distribution<int> dist(0, 255);
    std::string str(length, 0);
    for (size_t i = 0; i < length; i++) {
        str[i] = dist(engine);
    }
    return str;
}
class Crypto {
public:
    virtual std::string encrypt(std::string& in) = 0;
    virtual std::string decrypt(std::string& in) = 0;
};

class SymmetricCrypto : public Crypto {
public:
    virtual void setKey(std::string& key) = 0;
};

class AsymmetricCrypto : public Crypto {
public:
    virtual void generateKey() = 0;
    virtual void fromPublicKey(std::string& key) = 0;
    virtual std::string getPublicKey() = 0;
    virtual std::string getPrivateKey() = 0;
};

class ChaCha20 : public SymmetricCrypto {
protected:
    byte key[256];
    byte iv[128];

public:
    ChaCha20() { }
    ChaCha20(char KEY[256], char IV[128])
    {
        memcpy(key, KEY, sizeof(key));
        memcpy(iv, IV, sizeof(iv));
    }
    void setKey(std::string& key) override
    {
        std::default_random_engine engine;
        std::hash<std::string> hash_fn;
        engine.seed(hash_fn(key));
        std::uniform_int_distribution<int> dist(0, 255);
        for (int i = 0; i < 256; i++) {
            this->key[i] = dist(engine);
        }
        for (int i = 0; i < 128; i++) {
            this->iv[i] = dist(engine);
        }
    }
    std::string encrypt(std::string& in) override
    {
        std::string ciphertext;
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }
        byte tkey[256];
        byte tiv[128];

        memcpy(tkey, key, sizeof(key));
        memcpy(tiv, iv, sizeof(iv));
        if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, tkey, tiv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize encryption");
        }
        int len;
        ciphertext.resize(in.size() + EVP_CIPHER_block_size(EVP_chacha20()));
        if (EVP_EncryptUpdate(ctx, (byte*)ciphertext.data(), &len, reinterpret_cast<byte*>(in.data()), in.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to encrypt data");
        }

        int padding_len;
        if (EVP_EncryptFinal_ex(ctx, (byte*)ciphertext.data() + len, &padding_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize encryption");
        }

        ciphertext.resize(len + padding_len);
        EVP_CIPHER_CTX_free(ctx);
        return ciphertext;
    }

    std::string decrypt(std::string& in) override
    {
        std::string plaintext;
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }
        byte tkey[256];
        byte tiv[128];

        memcpy(tkey, key, sizeof(key));
        memcpy(tiv, iv, sizeof(iv));
        if (EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, tkey, tiv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize decryption");
        }

        int len;
        plaintext.resize(in.size());
        if (EVP_DecryptUpdate(ctx, (byte*)plaintext.data(), &len, (byte*)in.data(), in.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to decrypt data");
        }

        int padding_len;
        if (EVP_DecryptFinal_ex(ctx, (byte*)plaintext.data() + len, &padding_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize decryption");
        }

        plaintext.resize(len + padding_len);
        EVP_CIPHER_CTX_free(ctx);
        return plaintext;
    }
};

class AES_CBC : public SymmetricCrypto {
protected:
    std::string key;
    std::string iv;

public:
    AES_CBC() { }
    AES_CBC(std::string KEY, std::string IV)
    {
        key = KEY;
        iv = IV;
    }
    void setKey(std::string& key) override
    {
        std::default_random_engine engine;
        std::hash<std::string> hash_fn;
        engine.seed(hash_fn(key));
        std::uniform_int_distribution<int> dist(0, 255);
        this->key.resize(32);
        this->iv.resize(16);
        for (int i = 0; i < 32; i++) {
            this->key[i] = dist(engine);
        }
        for (int i = 0; i < 16; i++) {
            this->iv[i] = dist(engine);
        }
    }
    std::string encrypt(std::string& in) override
    {
        std::string ciphertext;
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }
        std::string tkey = key;
        std::string tiv = iv;
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (byte*)tkey.data(), (byte*)tiv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize encryption");
        }

        EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);
        int len;
        ciphertext.resize(in.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
        if (EVP_EncryptUpdate(ctx, (byte*)ciphertext.data(), &len, reinterpret_cast<byte*>(in.data()), in.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to encrypt data");
        }

        int padding_len;
        if (EVP_EncryptFinal_ex(ctx, (byte*)ciphertext.data() + len, &padding_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize encryption");
        }

        ciphertext.resize(len + padding_len);
        EVP_CIPHER_CTX_free(ctx);
        return ciphertext;
    }

    std::string decrypt(std::string& in) override
    {
        std::string plaintext;
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }
        std::string tkey = key;
        std::string tiv = iv;
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (byte*)tkey.data(), (byte*)tiv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize decryption");
        }

        EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

        int len;
        plaintext.resize(in.size());
        if (EVP_DecryptUpdate(ctx, (byte*)plaintext.data(), &len, (byte*)in.data(), in.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to decrypt data");
        }

        int padding_len;
        if (EVP_DecryptFinal_ex(ctx, (byte*)plaintext.data() + len, &padding_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize decryption");
        }

        plaintext.resize(len + padding_len);
        EVP_CIPHER_CTX_free(ctx);
        return plaintext;
    }
};

class RSA_PKCS1_OAEP : public AsymmetricCrypto {
protected:
    EVP_PKEY* rsa;

public:
    RSA_PKCS1_OAEP() { }

    void generateKey() override
    {
        rsa = EVP_RSA_gen(1024);
        if (!rsa) {
            throw std::runtime_error("Failed to generate RSA key");
        }
    }

    void fromPublicKey(std::string& key) override
    {
        rsa = nullptr;
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throw std::runtime_error("Failed to create BIO");
        }
        if (BIO_write(bio, key.data(), key.size()) != key.size()) {
            BIO_free(bio);
            throw std::runtime_error("Failed to load public key");
        }
        rsa = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        if (!rsa) {
            BIO_free(bio);
            throw std::runtime_error("Failed to read public key");
        }
        BIO_free(bio);
    }

    void fromX509PublicKey(std::string& key)
    {
        rsa = nullptr;
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throw std::runtime_error("Failed to create BIO");
        }
        if (BIO_write(bio, key.data(), key.size()) != key.size()) {
            BIO_free(bio);
            throw std::runtime_error("Failed to load public key");
        }
        rsa = d2i_PUBKEY_bio(bio, NULL);
        if (!rsa) {
            BIO_free(bio);
            throw std::runtime_error("Failed to read public key");
        }
        BIO_free(bio);
    }

    std::string getPublicKey() override
    {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throw std::runtime_error("Failed to create BIO");
        }
        if (PEM_write_bio_PUBKEY(bio, rsa) != 1) {
            BIO_free(bio);
            throw std::runtime_error("Failed to write public key");
        }
        char* key;
        size_t len = BIO_get_mem_data(bio, &key);
        std::string pubkey(key, len);
        BIO_free(bio);
        return pubkey;
    }

    std::string getX509PublicKey()
    {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throw std::runtime_error("Failed to create BIO");
        }
        if (i2d_PUBKEY_bio(bio, rsa) != 1) {
            BIO_free(bio);
            throw std::runtime_error("Failed to write public key");
        }
        char* key;
        size_t len = BIO_get_mem_data(bio, &key);
        std::string pubkey(key, len);
        BIO_free(bio);
        return pubkey;
    }

    std::string getPrivateKey() override
    {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throw std::runtime_error("Failed to create BIO");
        }
        if (PEM_write_bio_PrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL) != 1) {
            BIO_free(bio);
            throw std::runtime_error("Failed to write private key");
        }
        char* key;
        size_t len = BIO_get_mem_data(bio, &key);
        std::string privkey(key, len);
        BIO_free(bio);
        return privkey;
    }

    std::string encrypt(std::string& in) override
    {
        std::string cipher;
        size_t outlen;

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(rsa, NULL);
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }
        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize encryption");
        }
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to set rsa padding");
        }
        if (EVP_PKEY_encrypt(ctx, NULL, &outlen, (byte*)in.data(), in.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to determine buffer length");
        }

        cipher.resize(outlen);

        if (EVP_PKEY_encrypt(ctx, (byte*)cipher.data(), &outlen, (byte*)in.data(), in.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to encrypt data");
        }
        EVP_PKEY_CTX_free(ctx);
        return cipher;
    }

    std::string decrypt(std::string& in) override
    {
        std::string plaintext;
        size_t outlen;

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(rsa, NULL);
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }
        if (EVP_PKEY_decrypt_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize decryption");
        }
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to set rsa padding");
        }
        if (EVP_PKEY_decrypt(ctx, NULL, &outlen, (byte*)in.data(), in.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to determine buffer length");
        }

        plaintext.resize(outlen);

        if (EVP_PKEY_decrypt(ctx, (byte*)plaintext.data(), &outlen, (byte*)in.data(), in.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to decrypt data");
        }
        EVP_PKEY_CTX_free(ctx);
        return plaintext;
    }
};
}

#endif