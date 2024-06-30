#include "crypt"
#include <iostream>
#include <string>
unsigned char fixed_key[32] = { 0x71, 0x02, 0x03, 0x04, 0x05, 0x06, 0x17, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x4A, 0x0F, 0x10,
    0x11, 0x12, 0x53, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0xFC, 0x10, 0x1E, 0x1F, 0x20 };
unsigned char fixed_iv[16] = { 0x21, 0x02, 0x03, 0xA4, 0x05, 0x06, 0x23, 0x08, 0x09, 0x0A, 0x1B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };

int main(void)
{
    using namespace std;
    using namespace crypto;
    // string plaintext = "Testing data";
    // ChaCha20 chacha20;
    // string key = "randomkey";
    // chacha20.setKey(key);
    // auto cipher = chacha20.encrypt(plaintext);
    // cout << cipher << endl;
    // auto decrypted = chacha20.decrypt(cipher);
    // cout << decrypted << endl;
    // string key2 = "randomkey2";
    // chacha20.setKey(key2);
    // auto cipher2 = chacha20.encrypt(plaintext);
    // cout << cipher2 << endl;
    // auto decrypted2 = chacha20.decrypt(cipher2);
    // cout << decrypted2 << endl;

    int len = 765;
    string slen = string((char*)&len, 4);
    AES_CBC aes = AES_CBC((char*)fixed_key, (char*)fixed_iv);
    string encrypted = aes.encrypt(slen);
    for (auto b : encrypted) {
        cout << (int)(unsigned char)b << endl;
    }
    // cout << encrypted.length() << endl;
    // string decrypted = aes.decrypt(encrypted);
    // cout << decrypted << endl;
    // int out;
    // memcpy(&out, decrypted.c_str(), 4);
    // cout << out << endl;

    // AES aes = AES((char*)fixed_key, (char*)fixed_iv);
    // RSA_PKCS1_OAEP rsa = RSA_PKCS1_OAEP();
    // rsa.generateKey();
    // string pubkey = rsa.getPublicKey();
    // RSA_PKCS1_OAEP rsa2 = RSA_PKCS1_OAEP();
    // rsa2.fromPublicKey(pubkey);
    // cout << rsa.getPublicKey() << endl;
    // cout << rsa.getPrivateKey() << endl;
    // auto cipher = rsa2.encrypt(plaintext);
    // cout << cipher << endl;
    // auto decrypted = rsa.decrypt(cipher);
    // cout << decrypted << endl;
    // cout << sha256_string(plaintext) << endl;
}