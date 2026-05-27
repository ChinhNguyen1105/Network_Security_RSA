using System;
using System.Security.Cryptography;
using System.Text;

namespace UI_CSharp
{
    public static class SHAService
    {
        /// <summary>
        /// Tính toán mã băm SHA-256 của một chuỗi văn bản văn bản
        /// </summary>
        public static string ComputeSHA256(string text)
        {
            if (string.IsNullOrEmpty(text)) return string.Empty;

            byte[] documentBytes = Encoding.UTF8.GetBytes(text);
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(documentBytes);

                // Chuyển mảng byte sang chuỗi Hex viết hoa
                StringBuilder sb = new StringBuilder();
                foreach (byte b in hashBytes)
                {
                    sb.Append(b.ToString("X2"));
                }
                return sb.ToString();
            }
        }
    }
}