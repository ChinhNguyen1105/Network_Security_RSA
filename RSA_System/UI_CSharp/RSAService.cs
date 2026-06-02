using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace UI_CSharp
{
    public class RSAService
    {
        private const string DLL_PATH = "RSA_Core.dll";

        // =====================================================
        // IMPORT C++ DLL FUNCTIONS (Sử dụng IntPtr để quản lý bộ nhớ tuyệt đối an toàn)
        // =====================================================
        [DllImport(DLL_PATH, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern IntPtr GenerateKeyPair_CPP(int keySize, bool getPrivateKey);

        [DllImport(DLL_PATH, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern IntPtr SignData_CPP(string text, string xmlPrivKey);

        [DllImport(DLL_PATH, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern bool VerifyData_CPP(string text, string signature, string xmlPubKey);

        [DllImport(DLL_PATH, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern IntPtr SignFile_CPP(string filePath, string xmlPrivKey);

        [DllImport(DLL_PATH, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern bool VerifyFile_CPP(string filePath, string signature, string xmlPubKey);

        // Helper chuyển đổi vùng nhớ IntPtr từ CoTaskMemAlloc thành string và giải phóng nó
        private string MarshalPointerToString(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero) return string.Empty;
            try
            {
                string str = Marshal.PtrToStringAnsi(ptr);
                return str;
            }
            finally
            {
                // Giải phóng chính xác vùng nhớ CoTaskMemAlloc được cấp từ C++
                Marshal.FreeCoTaskMem(ptr);
            }
        }

        public string XmlPublicKey { get; set; }
        public string XmlPrivateKey { get; set; }
        public string SelectedModule { get; set; } = "CSharp";

        // =====================================================
        // GENERATE KEY
        // =====================================================
        public void GenerateKeyPair(int keySize)
        {
            if (SelectedModule == "OpenSSL")
            {
                IntPtr pubPtr = GenerateKeyPair_CPP(keySize, false);
                XmlPublicKey = MarshalPointerToString(pubPtr);

                IntPtr privPtr = GenerateKeyPair_CPP(keySize, true);
                XmlPrivateKey = MarshalPointerToString(privPtr);
            }
            else
            {
                using (RSA rsa = RSA.Create(keySize))
                {
                    XmlPublicKey = rsa.ToXmlString(false);
                    XmlPrivateKey = rsa.ToXmlString(true);
                }
            }
        }

        // =====================================================
        // SIGN TEXT
        // =====================================================
        public string SignData(string text)
        {
            if (SelectedModule == "OpenSSL")
            {
                IntPtr sigPtr = SignData_CPP(text, XmlPrivateKey);
                return MarshalPointerToString(sigPtr);
            }
            else
            {
                byte[] data = Encoding.UTF8.GetBytes(text);
                using (RSA rsa = RSA.Create())
                {
                    rsa.FromXmlString(XmlPrivateKey);
                    byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    return Convert.ToBase64String(signature);
                }
            }
        }

        // =====================================================
        // VERIFY TEXT
        // =====================================================
        public bool VerifyData(string text, string signature)
        {
            if (SelectedModule == "OpenSSL")
            {
                return VerifyData_CPP(text, signature, XmlPublicKey);
            }
            else
            {
                byte[] data = Encoding.UTF8.GetBytes(text);
                byte[] sigBytes = Convert.FromBase64String(signature);
                using (RSA rsa = RSA.Create())
                {
                    rsa.FromXmlString(XmlPublicKey);
                    return rsa.VerifyData(data, sigBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }
        }

        // =====================================================
        // SIGN FILE
        // =====================================================
        public string SignFile(string filePath)
        {
            if (SelectedModule == "OpenSSL")
            {
                IntPtr sigPtr = SignFile_CPP(filePath, XmlPrivateKey);
                return MarshalPointerToString(sigPtr);
            }
            else
            {
                byte[] fileData = File.ReadAllBytes(filePath);
                using (RSA rsa = RSA.Create())
                {
                    rsa.FromXmlString(XmlPrivateKey);
                    byte[] signature = rsa.SignData(fileData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    return Convert.ToBase64String(signature);
                }
            }
        }

        // =====================================================
        // VERIFY FILE
        // =====================================================
        public bool VerifyFile(string filePath, string signature)
        {
            if (SelectedModule == "OpenSSL")
            {
                return VerifyFile_CPP(filePath, signature, XmlPublicKey);
            }
            else
            {
                byte[] fileData = File.ReadAllBytes(filePath);
                byte[] sigBytes = Convert.FromBase64String(signature);
                using (RSA rsa = RSA.Create())
                {
                    rsa.FromXmlString(XmlPublicKey);
                    return rsa.VerifyData(fileData, sigBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }
        }
    }
}