// ==========================================================
// RSA_Core.cpp
// DLL RSA OpenSSL tương thích hoàn toàn với C# (.NET)
// Đã SỬA: Lỗi sập bộ nhớ AccessViolationException & Sạch Warning C4190
// Chỉ giữ lại tính năng: Tạo khóa, Ký số và Xác thực dữ liệu/file
// ==========================================================

#define _CRT_SECURE_NO_WARNINGS
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <iostream>
#include <string>
#include <cstring>
#include <fstream>
#include <vector>
#include <combaseapi.h> // Bắt buộc để dùng CoTaskMemAlloc chuyển chuỗi sang C# an toàn

#define EXPORT __declspec(dllexport)

// ==========================================================
// CÁC HÀM TRỢ GIÚP NỘI BỘ (Dùng thuần C++ nên ĐỂ NGOÀI extern "C")
// ==========================================================

// Helper chuyển đổi chuỗi std::string sang vùng nhớ dùng chung để C# tự giải phóng
const char* ToCoTaskMemString(const std::string& str) {
    if (str.empty()) return nullptr;
    size_t size = str.size() + 1;
    char* coMem = (char*)CoTaskMemAlloc(size);
    if (coMem) {
        strcpy_s(coMem, size, str.c_str());
    }
    return coMem;
}

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

std::string Base64Decode(const std::string& input)
{
    BIO* bio = BIO_new_mem_buf(input.data(), (int)input.size());
    BIO* b64 = BIO_new(BIO_f_base64());

    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    std::vector<unsigned char> buffer(input.size());
    int decodedLength = BIO_read(bio, buffer.data(), (int)buffer.size());

    BIO_free_all(bio);

    return std::string((char*)buffer.data(), decodedLength);
}

std::string BN_To_Base64(const BIGNUM* bn)
{
    // SỬA: Nếu con trỏ BN bị NULL (do khóa thiếu thành phần), trả về chuỗi rỗng thay vì sập app
    if (!bn) return "";

    int len = BN_num_bytes(bn);
    if (len <= 0) return "";

    unsigned char* bytes = (unsigned char*)malloc(len);
    if (!bytes) return "";

    BN_bn2bin(bn, bytes);
    std::string result = Base64Encode(bytes, len);
    free(bytes);

    return result;
}

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

RSA* XML_To_RSA_Public(const char* xmlKey)
{
    std::string xml(xmlKey);

    std::string modulus_b64 = GetXmlTagValue(xml, "Modulus");
    std::string exponent_b64 = GetXmlTagValue(xml, "Exponent");

    std::string modulus_bin = Base64Decode(modulus_b64);
    std::string exponent_bin = Base64Decode(exponent_b64);

    BIGNUM* n = BN_bin2bn((const unsigned char*)modulus_bin.data(), (int)modulus_bin.size(), NULL);
    BIGNUM* e = BN_bin2bn((const unsigned char*)exponent_bin.data(), (int)exponent_bin.size(), NULL);

    RSA* rsa = RSA_new();
    RSA_set0_key(rsa, n, e, NULL);

    return rsa;
}

RSA* XML_To_RSA_Private(const char* xmlKey)
{
    if (!xmlKey || strlen(xmlKey) == 0) return nullptr; // Kiểm tra chuỗi rỗng

    std::string xml(xmlKey);

    std::string modulus_b64 = GetXmlTagValue(xml, "Modulus");
    std::string exponent_b64 = GetXmlTagValue(xml, "Exponent");
    std::string d_b64 = GetXmlTagValue(xml, "D");
    std::string p_b64 = GetXmlTagValue(xml, "P");
    std::string q_b64 = GetXmlTagValue(xml, "Q");
    std::string dp_b64 = GetXmlTagValue(xml, "DP");
    std::string dq_b64 = GetXmlTagValue(xml, "DQ");
    std::string iq_b64 = GetXmlTagValue(xml, "InverseQ");

    // Nếu thiếu các thành phần cốt lõi của Private Key, trả về nullptr ngay
    if (modulus_b64.empty() || exponent_b64.empty() || d_b64.empty()) {
        return nullptr;
    }

    std::string modulus_bin = Base64Decode(modulus_b64);
    std::string exponent_bin = Base64Decode(exponent_b64);
    std::string d_bin = Base64Decode(d_b64);
    std::string p_bin = Base64Decode(p_b64);
    std::string q_bin = Base64Decode(q_b64);
    std::string dp_bin = Base64Decode(dp_b64);
    std::string dq_bin = Base64Decode(dq_b64);
    std::string iq_bin = Base64Decode(iq_b64);

    BIGNUM* n = BN_bin2bn((const unsigned char*)modulus_bin.data(), (int)modulus_bin.size(), NULL);
    BIGNUM* e = BN_bin2bn((const unsigned char*)exponent_bin.data(), (int)exponent_bin.size(), NULL);
    BIGNUM* d = BN_bin2bn((const unsigned char*)d_bin.data(), (int)d_bin.size(), NULL);

    // Các tham số phụ có thể NULL nếu là khóa thu gọn, nhưng nếu có dữ liệu thì chuyển đổi
    BIGNUM* p = p_bin.empty() ? NULL : BN_bin2bn((const unsigned char*)p_bin.data(), (int)p_bin.size(), NULL);
    BIGNUM* q = q_bin.empty() ? NULL : BN_bin2bn((const unsigned char*)q_bin.data(), (int)q_bin.size(), NULL);
    BIGNUM* dp = dp_bin.empty() ? NULL : BN_bin2bn((const unsigned char*)dp_bin.data(), (int)dp_bin.size(), NULL);
    BIGNUM* dq = dq_bin.empty() ? NULL : BN_bin2bn((const unsigned char*)dq_bin.data(), (int)dq_bin.size(), NULL);
    BIGNUM* iq = iq_bin.empty() ? NULL : BN_bin2bn((const unsigned char*)iq_bin.data(), (int)iq_bin.size(), NULL);

    RSA* rsa = RSA_new();
    if (!rsa) return nullptr;

    RSA_set0_key(rsa, n, e, d);
    RSA_set0_factors(rsa, p, q);
    RSA_set0_crt_params(rsa, dp, dq, iq);

    return rsa;
}

std::string RSA_To_XML_String(RSA* rsa, bool isPrivateKey)
{
    const BIGNUM* n = nullptr; const BIGNUM* e = nullptr; const BIGNUM* d = nullptr;
    const BIGNUM* p = nullptr; const BIGNUM* q = nullptr;
    const BIGNUM* dp = nullptr; const BIGNUM* dq = nullptr; const BIGNUM* iqmp = nullptr;

    RSA_get0_key(rsa, &n, &e, &d);
    if (isPrivateKey) {
        RSA_get0_factors(rsa, &p, &q);
        RSA_get0_crt_params(rsa, &dp, &dq, &iqmp);
    }

    std::string xml = "<RSAKeyValue>";
    xml += "<Modulus>" + BN_To_Base64(n) + "</Modulus>";
    xml += "<Exponent>" + BN_To_Base64(e) + "</Exponent>";

    if (isPrivateKey) {
        xml += "<P>" + BN_To_Base64(p) + "</P>";
        xml += "<Q>" + BN_To_Base64(q) + "</Q>";
        xml += "<DP>" + BN_To_Base64(dp) + "</DP>";
        xml += "<DQ>" + BN_To_Base64(dq) + "</DQ>";
        xml += "<InverseQ>" + BN_To_Base64(iqmp) + "</InverseQ>";
        xml += "<D>" + BN_To_Base64(d) + "</D>";
    }
    xml += "</RSAKeyValue>";
    return xml;
}

bool ReadAllBytes(const char* filePath, std::vector<unsigned char>& buffer) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    buffer.resize(size);
    if (file.read((char*)buffer.data(), size)) return true;
    return false;
}

// ==========================================================
// CÁC HÀM GIAO TIẾP CHÍNH VỚI C# (Bắt buộc nằm trong extern "C")
// ==========================================================
extern "C"
{
    // 1. Generate Key Pair (Đã sửa trả về const char* độc lập, sạch lỗi)
    EXPORT const char* GenerateKeyPair_CPP(int keySize, bool getPrivateKey)
    {
        BIGNUM* bne = BN_new();
        BN_set_word(bne, RSA_F4);
        RSA* rsa = RSA_new();
        std::string resultXml = "";

        if (RSA_generate_key_ex(rsa, keySize, bne, NULL) == 1) {
            resultXml = RSA_To_XML_String(rsa, getPrivateKey);
        }

        BN_free(bne);
        RSA_free(rsa);
        return ToCoTaskMemString(resultXml);
    }

    // 2. Sign Data (Text) - Trả trực tiếp chuỗi ký, không cần StringBuilder
    EXPORT const char* SignData_CPP(const char* text, const char* xmlPrivKey)
    {
        // 1. Kiểm tra tham số đầu vào
        if (!text || !xmlPrivKey || strlen(xmlPrivKey) == 0) {
            return ToCoTaskMemString("Error: Input data or Private Key is empty!");
        }

        // 2. Chuyển đổi khóa XML sang cấu trúc OpenSSL RSA
        RSA* rsa = XML_To_RSA_Private(xmlPrivKey);
        if (!rsa) {
            return ToCoTaskMemString("Error: Invalid XML Private Key format!");
        }

        // 3. Tiến hành băm SHA256
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((const unsigned char*)text, strlen(text), hash);

        std::vector<unsigned char> signature(RSA_size(rsa));
        unsigned int sigLen = 0;

        // 4. Thực hiện ký dữ liệu
        int result = RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature.data(), &sigLen, rsa);
        RSA_free(rsa); // Giải phóng vùng nhớ RSA luôn

        if (result != 1) {
            return ToCoTaskMemString("Error: RSA Signature Generation Failed!");
        }

        // 5. Trả về chữ ký Base64 thành công
        std::string sigBase64 = Base64Encode(signature.data(), sigLen);
        return ToCoTaskMemString(sigBase64);
    }

    // 3. Verify Data (Text)
    EXPORT bool VerifyData_CPP(const char* text, const char* signature, const char* xmlPubKey)
    {
        RSA* rsa = XML_To_RSA_Public(xmlPubKey);
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((const unsigned char*)text, strlen(text), hash);

        std::string sigBin = Base64Decode(signature);
        int result = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, (const unsigned char*)sigBin.data(), (unsigned int)sigBin.size(), rsa);

        RSA_free(rsa);
        return (result == 1);
    }

    // 4. Sign File
    EXPORT const char* SignFile_CPP(const char* filePath, const char* xmlPrivKey)
    {
        std::vector<unsigned char> fileData;
        if (!ReadAllBytes(filePath, fileData)) {
            return ToCoTaskMemString("Read File Failed");
        }

        RSA* rsa = XML_To_RSA_Private(xmlPrivKey);
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(fileData.data(), fileData.size(), hash);

        std::vector<unsigned char> signature(RSA_size(rsa));
        unsigned int sigLen = 0;

        int result = RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature.data(), &sigLen, rsa);
        RSA_free(rsa);

        if (result != 1) {
            return ToCoTaskMemString("RSA Sign File Failed");
        }

        std::string sigBase64 = Base64Encode(signature.data(), sigLen);
        return ToCoTaskMemString(sigBase64);
    }

    // 5. Verify File
    EXPORT bool VerifyFile_CPP(const char* filePath, const char* signature, const char* xmlPubKey)
    {
        std::vector<unsigned char> fileData;
        if (!ReadAllBytes(filePath, fileData)) return false;

        RSA* rsa = XML_To_RSA_Public(xmlPubKey);
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(fileData.data(), fileData.size(), hash);

        std::string sigBin = Base64Decode(signature);
        int result = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, (const unsigned char*)sigBin.data(), (unsigned int)sigBin.size(), rsa);

        RSA_free(rsa);
        return (result == 1);
    }
}