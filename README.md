# RSA Digital Signature System (C# + C++)

Hệ thống chữ ký số RSA sử dụng:

- C# WinForms UI
- C++ DLL xử lý RSA Core
- SHA-256 Hashing
- Xác thực tài liệu và file

---

# Công nghệ sử dụng

## Frontend / UI
- C#
- WinForms (.NET 8)

## Backend Logic
- C++ DLL
- OpenSSL

---

# Cấu trúc dự án

```text
D:.
├───CPP
│   │   CPP.sln
│   │
│   ├───CPP
│   │   │   CPP.vcxproj
│   │   │   dllmain.cpp
│   │   │   framework.h
│   │   │   pch.cpp
│   │   │   pch.h
│
└───RSA_System
    │   RSA_System.sln
    │
    └───UI_CSharp
        │   Form1.cs
        │   Form1.Designer.cs
        │   Program.cs
        │   RSAService.cs
        │   SHAService.cs
        │   UI_CSharp.csproj


Cài OpenSSL cho C++
Tải OpenSSL: https://slproweb.com/products/Win32OpenSSL.html
Sau khi cài:
Copy các file DLL:
libcrypto-4-x64.dll
libssl-4-x64.dll
vào: RSA_System/UI_CSharp/bin/Debug/net8.0-windows/

Build C++ DLL
Bước 1
Mở:
CPP/CPP.sln

Bước 2
Build project:
Build -> Build Solution
Sau khi build thành công sẽ tạo:
RSA_Core.dll

Bước 3
Copy file:
RSA_Core.dll
vào:
RSA_System/UI_CSharp/bin/Debug/net8.0-windows/

Chạy project C#
Bước 1
Mở:
RSA_System/RSA_System.sln

Bước 2
Set startup project:
UI_CSharp

Bước 3
Run project:
F5
