#ifndef _CRYPTO_HPP_
#define _CRYPTO_HPP_
#include <functional>
#include <memory>
#include <openssl/aes.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>

namespace crypto {
    typedef unsigned char byte;

    struct X509PublicKey {
        char data[162]{};

        X509PublicKey() = default;

        X509PublicKey(const std::string &key) { memcpy(data, key.data(), 162); }
    };

    struct SHA256Digest {
        char data[32]{};

        SHA256Digest(const std::string &md) { memcpy(data, md.data(), 32); }
    };

    inline std::string sha256_string(const std::string &in) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        EVP_MD_CTX *sha256 = EVP_MD_CTX_create();
        EVP_DigestInit_ex(sha256, EVP_sha256(), nullptr);
        EVP_DigestUpdate(sha256, in.data(), in.size());
        unsigned int len = 0;
        EVP_DigestFinal_ex(sha256, hash, &len);
        EVP_MD_CTX_destroy(sha256);
        return std::string(hash, hash + SHA256_DIGEST_LENGTH);
    }

    static std::mt19937 engine(time(nullptr));

    inline std::string random_string(const size_t length) {
        std::uniform_int_distribution<char> dist;
        std::string str(length, 0);
        for (size_t i = 0; i < length; i++) {
            str[i] = dist(engine);
        }
        return str;
    }

    class Crypto {
    public:
        virtual ~Crypto() = default;

        virtual std::string encrypt(std::string &in) const = 0;

        virtual std::string decrypt(std::string &in) const = 0;
    };

    class SymmetricCrypto : public Crypto {
    public:
        virtual void setKey(std::string &key) = 0;
    };

    class AsymmetricCrypto : public Crypto {
    public:
        virtual void generateKey() = 0;

        virtual void fromPublicKey(std::string &key) = 0;

        virtual std::string getPublicKey() const = 0;

        virtual std::string getPrivateKey() const = 0;
    };

    class ChaCha20 final : public SymmetricCrypto {
    protected:
        byte key[256]{};
        byte iv[128]{};

    public:
        ChaCha20() = default;

        ChaCha20(const ChaCha20 &) = delete;

        ChaCha20(char KEY[256], char IV[128]) {
            memcpy(key, KEY, sizeof(key));
            memcpy(iv, IV, sizeof(iv));
        }

        void setKey(std::string &key) override {
            std::hash<std::string> hash_fn;
            engine.seed(hash_fn(key));
            std::uniform_int_distribution<byte> dist;
            for (byte &i: this->key) {
                i = dist(engine);
            }
            for (byte &i: this->iv) {
                i = dist(engine);
            }
        }

        std::string encrypt(std::string &in) const override {
            std::string ciphertext;
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx) {
                throw std::runtime_error("Failed to create cipher context");
            }
            byte tkey[256];
            byte tiv[128];

            memcpy(tkey, key, sizeof(key));
            memcpy(tiv, iv, sizeof(iv));
            if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), nullptr, tkey, tiv) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to initialize encryption");
            }
            int len;
            ciphertext.resize(in.size() + EVP_CIPHER_block_size(EVP_chacha20()));
            if (EVP_EncryptUpdate(ctx, const_cast<byte *>(reinterpret_cast<const byte *>(ciphertext.data())), &len,
                                  reinterpret_cast<const byte *>(in.data()),
                                  in.size()) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to encrypt data");
            }

            int padding_len;
            if (EVP_EncryptFinal_ex(
                    ctx, const_cast<byte *>(reinterpret_cast<const byte *>(ciphertext.data() + len)),
                    &padding_len) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to finalize encryption");
            }

            ciphertext.resize(len + padding_len);
            EVP_CIPHER_CTX_free(ctx);
            return ciphertext;
        }

        std::string decrypt(std::string &in) const override {
            std::string plaintext;
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx) {
                throw std::runtime_error("Failed to create cipher context");
            }
            byte tkey[256];
            byte tiv[128];

            memcpy(tkey, key, sizeof(key));
            memcpy(tiv, iv, sizeof(iv));
            if (EVP_DecryptInit_ex(ctx, EVP_chacha20(), nullptr, tkey, tiv) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to initialize decryption");
            }

            int len;
            plaintext.resize(in.size());
            if (EVP_DecryptUpdate(ctx, (byte *) plaintext.data(), &len, (byte *) in.data(), in.size()) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to decrypt data");
            }

            int padding_len;
            if (EVP_DecryptFinal_ex(ctx, (byte *) plaintext.data() + len, &padding_len) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to finalize decryption");
            }

            plaintext.resize(len + padding_len);
            EVP_CIPHER_CTX_free(ctx);
            return plaintext;
        }
    };

    class AES_CBC final : public SymmetricCrypto {
    protected:
        std::string key;
        std::string iv;

    public:
        AES_CBC() = default;

        AES_CBC(const AES_CBC &) = delete;

        AES_CBC(std::string KEY, std::string IV) : key(std::move(KEY)), iv(std::move(IV)) {}

        void setKey(std::string &key) override {
            constexpr std::hash<std::string> hash_fn;
            std::mt19937 engine(hash_fn(key));
            std::uniform_int_distribution<char> dist;
            this->key.resize(32);
            this->iv.resize(16);
            for (int i = 0; i < 32; i++) {
                this->key[i] = dist(engine);
            }
            for (int i = 0; i < 16; i++) {
                this->iv[i] = dist(engine);
            }
        }

        std::string encrypt(std::string &in) const override {
            std::string ciphertext;
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx) {
                throw std::runtime_error("Failed to create cipher context");
            }
            std::string tkey = key;
            std::string tiv = iv;
            if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (byte *) tkey.data(), (byte *) tiv.data()) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to initialize encryption");
            }

            EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);
            int len;
            ciphertext.resize(in.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
            if (EVP_EncryptUpdate(ctx, (byte *) ciphertext.data(), &len, reinterpret_cast<const byte *>(in.data()),
                                  in.size()) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to encrypt data");
            }

            int padding_len;
            if (EVP_EncryptFinal_ex(ctx, (byte *) ciphertext.data() + len, &padding_len) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to finalize encryption");
            }

            ciphertext.resize(len + padding_len);
            EVP_CIPHER_CTX_free(ctx);
            return ciphertext;
        }

        std::string decrypt(std::string &in) const override {
            std::string plaintext;
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx) {
                throw std::runtime_error("Failed to create cipher context");
            }
            std::string tkey = key;
            std::string tiv = iv;
            if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (byte *) tkey.data(), (byte *) tiv.data()) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to initialize decryption");
            }

            EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

            int len;
            plaintext.resize(in.size());
            if (EVP_DecryptUpdate(ctx, (byte *) plaintext.data(), &len, (byte *) in.data(), in.size()) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to decrypt data");
            }

            int padding_len;
            if (EVP_DecryptFinal_ex(ctx, (byte *) plaintext.data() + len, &padding_len) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("Failed to finalize decryption");
            }

            plaintext.resize(len + padding_len);
            EVP_CIPHER_CTX_free(ctx);
            return plaintext;
        }
    };

    class RSA_PKCS1_OAEP final : public AsymmetricCrypto {
    protected:
        EVP_PKEY *rsa = nullptr;

    public:
        RSA_PKCS1_OAEP() = default;

        RSA_PKCS1_OAEP(const RSA_PKCS1_OAEP &) = delete;

        void generateKey() override {
            release();
            rsa = EVP_RSA_gen(1024);
            if (!rsa) {
                throw std::runtime_error("Failed to generate RSA key");
            }
        }

        ~RSA_PKCS1_OAEP() override {
            release();
        }

        void release() {
            if (rsa != nullptr) {
                EVP_PKEY_free(rsa);
                rsa = nullptr;
            }
        }

        void fromPublicKey(std::string &key) override {
            release();
            BIO *bio = BIO_new(BIO_s_mem());
            if (!bio) {
                throw std::runtime_error("Failed to create BIO");
            }
            if (BIO_write(bio, key.data(), key.size()) != key.size()) {
                BIO_free(bio);
                throw std::runtime_error("Failed to load public key");
            }
            rsa = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
            if (!rsa) {
                BIO_free(bio);
                throw std::runtime_error("Failed to read public key");
            }
            BIO_free(bio);
        }

        void fromX509PublicKey(std::string &key) {
            release();
            BIO *bio = BIO_new(BIO_s_mem());
            if (!bio) {
                throw std::runtime_error("Failed to create BIO");
            }
            if (BIO_write(bio, key.data(), key.size()) != key.size()) {
                BIO_free(bio);
                throw std::runtime_error("Failed to load public key");
            }
            rsa = d2i_PUBKEY_bio(bio, nullptr);
            if (!rsa) {
                BIO_free(bio);
                throw std::runtime_error("Failed to read public key");
            }
            BIO_free(bio);
        }

        void fromX509PublicKey(X509PublicKey &key) {
            std::string str(key.data, 162);
            fromX509PublicKey(str);
        }

        std::string getPublicKey() const override {
            BIO *bio = BIO_new(BIO_s_mem());
            if (!bio) {
                throw std::runtime_error("Failed to create BIO");
            }
            if (PEM_write_bio_PUBKEY(bio, rsa) != 1) {
                BIO_free(bio);
                throw std::runtime_error("Failed to write public key");
            }
            char *key;
            size_t len = BIO_get_mem_data(bio, &key);
            std::string pubkey(key, len);
            BIO_free(bio);
            return pubkey;
        }

        std::string getX509PublicKey() const {
            BIO *bio = BIO_new(BIO_s_mem());
            if (!bio) {
                throw std::runtime_error("Failed to create BIO");
            }
            if (i2d_PUBKEY_bio(bio, rsa) != 1) {
                BIO_free(bio);
                throw std::runtime_error("Failed to write public key");
            }
            char *key;
            size_t len = BIO_get_mem_data(bio, &key);
            std::string pubkey(key, len);
            BIO_free(bio);
            return pubkey;
        }

        std::string getPrivateKey() const override {
            BIO *bio = BIO_new(BIO_s_mem());
            if (!bio) {
                throw std::runtime_error("Failed to create BIO");
            }
            if (PEM_write_bio_PrivateKey(bio, rsa, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
                BIO_free(bio);
                throw std::runtime_error("Failed to write private key");
            }
            char *key;
            size_t len = BIO_get_mem_data(bio, &key);
            std::string privkey(key, len);
            BIO_free(bio);
            return privkey;
        }

        std::string encrypt(std::string &in) const override {
            std::string cipher;
            size_t outlen;

            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(rsa, nullptr);
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
            if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, (byte *) in.data(), in.size()) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                throw std::runtime_error("Failed to determine buffer length");
            }

            cipher.resize(outlen);

            if (EVP_PKEY_encrypt(ctx, reinterpret_cast<byte *>(cipher.data()), &outlen,
                                 reinterpret_cast<byte *>(in.data()), in.size()) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                throw std::runtime_error("Failed to encrypt data");
            }
            EVP_PKEY_CTX_free(ctx);
            return cipher;
        }

        std::string decrypt(std::string &in) const override {
            std::string plaintext;
            size_t outlen;

            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(rsa, nullptr);
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
            if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, reinterpret_cast<byte *>(in.data()), in.size()) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                throw std::runtime_error("Failed to determine buffer length");
            }

            plaintext.resize(outlen);

            if (EVP_PKEY_decrypt(ctx, reinterpret_cast<byte *>(plaintext.data()), &outlen,
                                 reinterpret_cast<byte *>(in.data()), in.size()) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                throw std::runtime_error("Failed to decrypt data");
            }
            EVP_PKEY_CTX_free(ctx);
            return plaintext;
        }
    };
}

#endif
