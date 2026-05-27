// ==========================================================
// RSA_Core.cpp
// DLL RSA OpenSSL tương thích hoàn toàn với C# (.NET)
// Đã FIX lỗi: "Keyset does not exist"
// ==========================================================

// Tắt warning OpenSSL deprecated
#define _CRT_SECURE_NO_WARNINGS
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include <iostream>
#include <string>
#include <cstring>

#define EXPORT __declspec(dllexport)

extern "C"
{

    // ==========================================================
    // Base64 Encode
    // ==========================================================
    std::string Base64Encode(const unsigned char* buffer, size_t length)
    {
        BIO* bio = BIO_new(BIO_s_mem());
        BIO* b64 = BIO_new(BIO_f_base64());

        bio = BIO_push(b64, bio);

        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

        BIO_write(bio, buffer, (int)length);
        BIO_flush(bio);

        BUF_MEM* memPtr;
        BIO_get_mem_ptr(bio, &memPtr);

        std::string result(memPtr->data, memPtr->length);

        BIO_free_all(bio);

        return result;
    }

    // ==========================================================
    // Base64 Decode
    // ==========================================================
    std::string Base64Decode(const std::string& input)
    {
        BIO* bio = BIO_new_mem_buf(input.data(), (int)input.size());
        BIO* b64 = BIO_new(BIO_f_base64());

        bio = BIO_push(b64, bio);

        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

        char buffer[4096];
        int decodedLength = BIO_read(bio, buffer, sizeof(buffer));

        BIO_free_all(bio);

        return std::string(buffer, decodedLength);
    }

    // ==========================================================
    // Convert BIGNUM -> Base64
    // ==========================================================
    std::string BN_To_Base64(const BIGNUM* bn)
    {
        int len = BN_num_bytes(bn);

        unsigned char* bytes = (unsigned char*)malloc(len);

        BN_bn2bin(bn, bytes);

        std::string result = Base64Encode(bytes, len);

        free(bytes);

        return result;
    }

    // ==========================================================
    // Extract XML Tag
    // ==========================================================
    std::string GetXmlTagValue(const std::string& xml, const std::string& tag)
    {
        std::string openTag = "<" + tag + ">";
        std::string closeTag = "</" + tag + ">";

        size_t start = xml.find(openTag);
        size_t end = xml.find(closeTag);

        if (start == std::string::npos || end == std::string::npos)
            return "";

        start += openTag.length();

        return xml.substr(start, end - start);
    }

    // ==========================================================
    // Convert XML -> RSA
    // ==========================================================
    RSA* XML_To_RSA_Public(const char* xmlKey)
    {
        std::string xml(xmlKey);

        std::string modulus_b64 = GetXmlTagValue(xml, "Modulus");
        std::string exponent_b64 = GetXmlTagValue(xml, "Exponent");

        std::string modulus_bin = Base64Decode(modulus_b64);
        std::string exponent_bin = Base64Decode(exponent_b64);

        BIGNUM* n = BN_bin2bn(
            (const unsigned char*)modulus_bin.data(),
            (int)modulus_bin.size(),
            NULL);

        BIGNUM* e = BN_bin2bn(
            (const unsigned char*)exponent_bin.data(),
            (int)exponent_bin.size(),
            NULL);

        RSA* rsa = RSA_new();

        RSA_set0_key(rsa, n, e, NULL);

        return rsa;
    }

    // ==========================================================
    // Convert XML -> RSA PRIVATE
    // ==========================================================
    RSA* XML_To_RSA_Private(const char* xmlKey)
    {
        std::string xml(xmlKey);

        std::string modulus_b64 = GetXmlTagValue(xml, "Modulus");
        std::string exponent_b64 = GetXmlTagValue(xml, "Exponent");
        std::string d_b64 = GetXmlTagValue(xml, "D");

        std::string p_b64 = GetXmlTagValue(xml, "P");
        std::string q_b64 = GetXmlTagValue(xml, "Q");

        std::string dp_b64 = GetXmlTagValue(xml, "DP");
        std::string dq_b64 = GetXmlTagValue(xml, "DQ");

        std::string iq_b64 = GetXmlTagValue(xml, "InverseQ");

        std::string modulus_bin = Base64Decode(modulus_b64);
        std::string exponent_bin = Base64Decode(exponent_b64);
        std::string d_bin = Base64Decode(d_b64);

        std::string p_bin = Base64Decode(p_b64);
        std::string q_bin = Base64Decode(q_b64);

        std::string dp_bin = Base64Decode(dp_b64);
        std::string dq_bin = Base64Decode(dq_b64);

        std::string iq_bin = Base64Decode(iq_b64);

        BIGNUM* n = BN_bin2bn(
            (const unsigned char*)modulus_bin.data(),
            (int)modulus_bin.size(),
            NULL);

        BIGNUM* e = BN_bin2bn(
            (const unsigned char*)exponent_bin.data(),
            (int)exponent_bin.size(),
            NULL);

        BIGNUM* d = BN_bin2bn(
            (const unsigned char*)d_bin.data(),
            (int)d_bin.size(),
            NULL);

        BIGNUM* p = BN_bin2bn(
            (const unsigned char*)p_bin.data(),
            (int)p_bin.size(),
            NULL);

        BIGNUM* q = BN_bin2bn(
            (const unsigned char*)q_bin.data(),
            (int)q_bin.size(),
            NULL);

        BIGNUM* dp = BN_bin2bn(
            (const unsigned char*)dp_bin.data(),
            (int)dp_bin.size(),
            NULL);

        BIGNUM* dq = BN_bin2bn(
            (const unsigned char*)dq_bin.data(),
            (int)dq_bin.size(),
            NULL);

        BIGNUM* iq = BN_bin2bn(
            (const unsigned char*)iq_bin.data(),
            (int)iq_bin.size(),
            NULL);

        RSA* rsa = RSA_new();

        RSA_set0_key(rsa, n, e, d);

        RSA_set0_factors(rsa, p, q);

        RSA_set0_crt_params(rsa, dp, dq, iq);

        return rsa;
    }

    // ==========================================================
    // Convert RSA -> XML
    // FIX FULL .NET RSA XML
    // ==========================================================
    void RSA_To_XML(RSA* rsa, bool isPrivateKey, char* output)
    {
        const BIGNUM* n = nullptr;
        const BIGNUM* e = nullptr;
        const BIGNUM* d = nullptr;

        const BIGNUM* p = nullptr;
        const BIGNUM* q = nullptr;

        const BIGNUM* dp = nullptr;
        const BIGNUM* dq = nullptr;
        const BIGNUM* iqmp = nullptr;

        RSA_get0_key(rsa, &n, &e, &d);

        if (isPrivateKey)
        {
            RSA_get0_factors(rsa, &p, &q);

            RSA_get0_crt_params(rsa, &dp, &dq, &iqmp);
        }

        std::string xml = "<RSAKeyValue>";

        xml += "<Modulus>" + BN_To_Base64(n) + "</Modulus>";
        xml += "<Exponent>" + BN_To_Base64(e) + "</Exponent>";

        if (isPrivateKey)
        {
            xml += "<P>" + BN_To_Base64(p) + "</P>";
            xml += "<Q>" + BN_To_Base64(q) + "</Q>";

            xml += "<DP>" + BN_To_Base64(dp) + "</DP>";
            xml += "<DQ>" + BN_To_Base64(dq) + "</DQ>";

            xml += "<InverseQ>" + BN_To_Base64(iqmp) + "</InverseQ>";

            xml += "<D>" + BN_To_Base64(d) + "</D>";
        }

        xml += "</RSAKeyValue>";

        strcpy(output, xml.c_str());
    }

    // ==========================================================
    // Generate Key Pair
    // ==========================================================
    EXPORT void GenerateKeyPair_CPP(
        int keySize,
        char* pubKeyRes,
        char* privKeyRes)
    {
        BIGNUM* bne = BN_new();

        BN_set_word(bne, RSA_F4);

        RSA* rsa = RSA_new();

        if (RSA_generate_key_ex(rsa, keySize, bne, NULL) == 1)
        {
            RSA_To_XML(rsa, false, pubKeyRes);

            RSA_To_XML(rsa, true, privKeyRes);
        }

        BN_free(bne);

        RSA_free(rsa);
    }

    // ==========================================================
    // Encrypt
    // ==========================================================
    EXPORT void Encrypt_CPP(
        const char* plainText,
        const char* xmlPubKey,
        char* cipherTextRes)
    {
        RSA* rsa = XML_To_RSA_Public(xmlPubKey);

        unsigned char encrypted[4096];

        int result = RSA_public_encrypt(
            (int)strlen(plainText),
            (const unsigned char*)plainText,
            encrypted,
            rsa,
            RSA_PKCS1_PADDING);

        if (result == -1)
        {
            strcpy(cipherTextRes, "RSA Encrypt Failed");
        }
        else
        {
            std::string cipher = Base64Encode(encrypted, result);

            strcpy(cipherTextRes, cipher.c_str());
        }

        RSA_free(rsa);
    }

    // ==========================================================
    // Decrypt
    // ==========================================================
    EXPORT void Decrypt_CPP(
        const char* cipherText,
        const char* xmlPrivKey,
        char* plainTextRes)
    {
        RSA* rsa = XML_To_RSA_Private(xmlPrivKey);

        std::string decoded = Base64Decode(cipherText);

        unsigned char decrypted[4096];

        int result = RSA_private_decrypt(
            (int)decoded.size(),
            (const unsigned char*)decoded.data(),
            decrypted,
            rsa,
            RSA_PKCS1_PADDING);

        if (result == -1)
        {
            strcpy(plainTextRes, "RSA Decrypt Failed");
        }
        else
        {
            decrypted[result] = '\0';

            strcpy(plainTextRes, (char*)decrypted);
        }

        RSA_free(rsa);
    }

}