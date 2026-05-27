using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace UI_CSharp
{
    public class RSAService
    {
        public string XmlPublicKey { get; set; }

        public string XmlPrivateKey { get; set; }

        public string SelectedModule { get; set; }

        // =====================================================
        // GENERATE KEY
        // =====================================================

        public void GenerateKeyPair(int keySize)
        {
            using (RSA rsa = RSA.Create(keySize))
            {
                XmlPublicKey = rsa.ToXmlString(false);

                XmlPrivateKey = rsa.ToXmlString(true);
            }
        }

        // =====================================================
        // ENCRYPT TEXT
        // =====================================================

        public string Encrypt(string plainText)
        {
            byte[] data =
                Encoding.UTF8.GetBytes(plainText);

            using (RSA rsa = RSA.Create())
            {
                rsa.FromXmlString(XmlPublicKey);

                byte[] encrypted =
                    rsa.Encrypt(
                        data,
                        RSAEncryptionPadding.Pkcs1);

                return Convert.ToBase64String(encrypted);
            }
        }

        // =====================================================
        // DECRYPT TEXT
        // =====================================================

        public string Decrypt(string cipherText)
        {
            byte[] data =
                Convert.FromBase64String(cipherText);

            using (RSA rsa = RSA.Create())
            {
                rsa.FromXmlString(XmlPrivateKey);

                byte[] decrypted =
                    rsa.Decrypt(
                        data,
                        RSAEncryptionPadding.Pkcs1);

                return Encoding.UTF8.GetString(decrypted);
            }
        }

        // =====================================================
        // SIGN TEXT
        // =====================================================

        public string SignData(string text)
        {
            byte[] data =
                Encoding.UTF8.GetBytes(text);

            using (RSA rsa = RSA.Create())
            {
                rsa.FromXmlString(XmlPrivateKey);

                byte[] signature =
                    rsa.SignData(
                        data,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1);

                return Convert.ToBase64String(signature);
            }
        }

        // =====================================================
        // VERIFY TEXT
        // =====================================================

        public bool VerifyData(
            string text,
            string signature)
        {
            byte[] data =
                Encoding.UTF8.GetBytes(text);

            byte[] sigBytes =
                Convert.FromBase64String(signature);

            using (RSA rsa = RSA.Create())
            {
                rsa.FromXmlString(XmlPublicKey);

                return rsa.VerifyData(
                    data,
                    sigBytes,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
            }
        }

        // =====================================================
        // ENCRYPT FILE
        // =====================================================

        public void EncryptFile(
            string inputFile,
            string outputFile)
        {
            byte[] fileData =
                File.ReadAllBytes(inputFile);

            using (RSA rsa = RSA.Create())
            {
                rsa.FromXmlString(XmlPublicKey);

                byte[] encryptedData =
                    rsa.Encrypt(
                        fileData,
                        RSAEncryptionPadding.Pkcs1);

                File.WriteAllBytes(
                    outputFile,
                    encryptedData);
            }
        }

        // =====================================================
        // DECRYPT FILE
        // =====================================================

        public void DecryptFile(
            string inputFile,
            string outputFile)
        {
            byte[] encryptedData =
                File.ReadAllBytes(inputFile);

            using (RSA rsa = RSA.Create())
            {
                rsa.FromXmlString(XmlPrivateKey);

                byte[] decryptedData =
                    rsa.Decrypt(
                        encryptedData,
                        RSAEncryptionPadding.Pkcs1);

                File.WriteAllBytes(
                    outputFile,
                    decryptedData);
            }
        }

        // =====================================================
        // SIGN FILE
        // =====================================================

        public string SignFile(string filePath)
        {
            byte[] fileData =
                File.ReadAllBytes(filePath);

            using (RSA rsa = RSA.Create())
            {
                rsa.FromXmlString(XmlPrivateKey);

                byte[] signature =
                    rsa.SignData(
                        fileData,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1);

                return Convert.ToBase64String(signature);
            }
        }

        // =====================================================
        // VERIFY FILE
        // =====================================================

        public bool VerifyFile(
            string filePath,
            string signature)
        {
            byte[] fileData =
                File.ReadAllBytes(filePath);

            byte[] sigBytes =
                Convert.FromBase64String(signature);

            using (RSA rsa = RSA.Create())
            {
                rsa.FromXmlString(XmlPublicKey);

                return rsa.VerifyData(
                    fileData,
                    sigBytes,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
            }
        }
    }
}