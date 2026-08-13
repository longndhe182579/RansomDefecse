/*
 * StaticAnalyzer.h — Phân tích tĩnh (F1, F2, F3, F5).
 *
 * F2 tính entropy riêng cho từng section PE, chỉ xét section THỰC THI — nếu
 * tính trên vùng đầu file (PE header + import table) thì entropy tự nhiên
 * thấp và không phản ánh được nội dung đã pack/encrypt.
 *
 * F5 parse trực tiếp IMAGE_IMPORT_DESCRIPTOR thay vì tìm chuỗi tên hàm
 * ("cryptencrypt"...) trong dữ liệu thô: file bị pack sẽ ẩn IAT khỏi kiểu
 * tìm chuỗi đó, và chuỗi trùng ngẫu nhiên có thể gây báo động giả.
 *
 * Toàn bộ hàm ở đây chạy NGOÀI mutex bảo vệ engine động: DIE có thể mất vài
 * giây, FLOSS mất hàng chục giây, giữ lock trong lúc đó sẽ đóng băng phần
 * giám sát runtime ngay khi ransomware đang hoạt động.
 */
#pragma once

#include "Util.h"
#include "Config.h"

#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <bcrypt.h>      /* BCRYPT_SHA256_ALGORITHM */

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "sfc.lib")
#include <sfc.h>        /* SfcIsFileProtected — fallback cho file he thong Windows */

namespace rw {

    struct StaticResult {
        bool unsignedImage = false;   // F1
        bool packed = false;   // F2
        bool suspStrings = false;   // F3
        bool cryptoApi = false;   // F5
        bool safeModeStr = false;   // F6 (tín hiệu phụ; nguồn chính là cmdline)
        std::string imageSha256;
    };

    /*
     * F1 — Chữ ký số.
     *
     * Chỉ gọi WinVerifyTrust với WTD_CHOICE_FILE là không đủ: cách đó chỉ đọc
     * chữ ký NHÚNG TRONG FILE. Phần lớn file hệ thống Windows (conhost.exe,
     * svchost.exe, dllhost.exe, đa số System32) được ký qua SECURITY CATALOG
     * (.cat trong C:\Windows\System32\CatRoot) chứ không nhúng chữ ký trực
     * tiếp, nên nếu chỉ kiểm tra embedded thì F1 sẽ bật nhầm cho gần như mọi
     * binary Microsoft. Vì vậy cần thử embedded trước, thất bại thì tra catalog.
     */

    inline bool VerifyEmbeddedSignature(const std::wstring& path) {
        WINTRUST_FILE_INFO fi{};
        fi.cbStruct = sizeof(fi);
        fi.pcwszFilePath = path.c_str();

        WINTRUST_DATA wd{};
        wd.cbStruct = sizeof(wd);
        wd.dwUIChoice = WTD_UI_NONE;
        wd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wd.dwUnionChoice = WTD_CHOICE_FILE;
        wd.dwStateAction = WTD_STATEACTION_VERIFY;
        wd.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;
        wd.pFile = &fi;

        GUID g = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG r = WinVerifyTrust(nullptr, &g, &wd);
        wd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &g, &wd);
        return r == ERROR_SUCCESS;
    }

    /*
     * CryptCATAdminAcquireContext / CryptCATAdminCalcHashFromFileHandle (API
     * thế hệ 1) mặc định băm SHA-1. Nhưng catalog trong
     * C:\Windows\System32\CatRoot trên Windows 10/11 được ký bằng SHA-256,
     * nên hash SHA-1 không khớp entry nào, CryptCATAdminEnumCatalogFromHash
     * trả NULL, và toàn bộ tiến trình xác minh catalog thất bại — kể cả với
     * binary hệ thống hợp lệ (cmd.exe, conhost.exe, vssadmin.exe...). Do đó
     * cần dùng API thế hệ 2 (từ Windows 8): CryptCATAdminAcquireContext2 /
     * CryptCATAdminCalcHashFromFileHandle2 với BCRYPT_SHA256_ALGORITHM, và
     * chỉ lùi về API SHA-1 khi thế hệ 2 không khả dụng (Windows 7 hoặc
     * catalog đời cũ).
     *
     * Về thuật ngữ: động cơ xác minh thật sự trong cả hai đường vẫn là
     * WinVerifyTrust. Nhóm CryptCATAdmin* không xác minh gì — chúng chỉ
     * (1) tính hash file và (2) tra xem hash đó nằm trong file .cat nào.
     * Có đường dẫn .cat rồi mới gọi WinVerifyTrust với WTD_CHOICE_CATALOG.
     */

       /* Xác minh một file dựa trên catalog đã định vị được */
    inline bool VerifyAgainstCatalog(HCATADMIN hCatAdmin, HCATINFO hCatInfo,
        HANDLE hFile, const std::wstring& path,
        std::vector<BYTE>& hash) {
        CATALOG_INFO ci{};
        ci.cbStruct = sizeof(ci);
        if (!CryptCATCatalogInfoFromContext(hCatInfo, &ci, 0)) return false;

        /* Member tag = hash dạng hex CHỮ HOA */
        std::wstring tag;
        static const wchar_t* k = L"0123456789ABCDEF";
        tag.reserve(hash.size() * 2);
        for (size_t i = 0; i < hash.size(); i++) {
            tag += k[hash[i] >> 4];
            tag += k[hash[i] & 0x0F];
        }

        WINTRUST_CATALOG_INFO wtc{};
        wtc.cbStruct = sizeof(wtc);
        wtc.pcwszCatalogFilePath = ci.wszCatalogFile;
        wtc.pcwszMemberTag = tag.c_str();
        wtc.pcwszMemberFilePath = path.c_str();
        wtc.hMemberFile = hFile;
        wtc.pbCalculatedFileHash = hash.data();
        wtc.cbCalculatedFileHash = (DWORD)hash.size();
        wtc.hCatAdmin = hCatAdmin;

        WINTRUST_DATA wd{};
        wd.cbStruct = sizeof(wd);
        wd.dwUIChoice = WTD_UI_NONE;
        wd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wd.dwUnionChoice = WTD_CHOICE_CATALOG;
        wd.dwStateAction = WTD_STATEACTION_VERIFY;
        wd.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;
        wd.pCatalog = &wtc;

        GUID g = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG r = WinVerifyTrust(nullptr, &g, &wd);      /* <<< XÁC MINH THẬT Ở ĐÂY */
        wd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &g, &wd);
        return r == ERROR_SUCCESS;
    }

    inline bool VerifyCatalogSignature(const std::wstring& path) {
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        bool ok = false;

        /*
         * pass 0: SHA-256 (Windows 8 trở lên — đây là đường đúng cho Win10/11)
         * pass 1: SHA-1   (đường lui cho Windows 7 hoặc catalog đời cũ)
         */
        for (int pass = 0; pass < 2 && !ok; pass++) {
            const bool useSha256 = (pass == 0);
            HCATADMIN hCatAdmin = nullptr;

            if (useSha256) {
                if (!CryptCATAdminAcquireContext2(&hCatAdmin, &action,
                    BCRYPT_SHA256_ALGORITHM, nullptr, 0)) continue;
            }
            else {
                if (!CryptCATAdminAcquireContext(&hCatAdmin, &action, 0)) continue;
            }

            /* Lấy độ dài hash */
            DWORD hashLen = 0;
            if (useSha256)
                CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, &hashLen, nullptr, 0);
            else
                CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, nullptr, 0);

            if (hashLen == 0) { CryptCATAdminReleaseContext(hCatAdmin, 0); continue; }

            /* Con trỏ file phải về đầu trước mỗi lần băm */
            SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);

            std::vector<BYTE> hash(hashLen);
            BOOL okHash = useSha256
                ? CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, &hashLen, hash.data(), 0)
                : CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, hash.data(), 0);

            if (!okHash) { CryptCATAdminReleaseContext(hCatAdmin, 0); continue; }
            hash.resize(hashLen);

            /* Tra catalog chứa hash này. Một file có thể nằm trong nhiều catalog
               (ví dụ sau Windows Update) -> duyệt hết cho tới khi có cái hợp lệ. */
            HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(
                hCatAdmin, hash.data(), hashLen, 0, nullptr);

            while (hCatInfo && !ok) {
                SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
                ok = VerifyAgainstCatalog(hCatAdmin, hCatInfo, hFile, path, hash);

                HCATINFO hPrev = hCatInfo;
                if (!ok) {
                    hCatInfo = CryptCATAdminEnumCatalogFromHash(
                        hCatAdmin, hash.data(), hashLen, 0, &hPrev);
                    /* hPrev đã được API giải phóng khi truyền vào làm prev */
                }
                else {
                    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                    hCatInfo = nullptr;
                }
            }

            CryptCATAdminReleaseContext(hCatAdmin, 0);
        }

        CloseHandle(hFile);
        return ok;
    }

    /*
     * VerifySignature — F1.
     *
     * Hai chế độ của WinVerifyTrust:
     *   WTD_CHOICE_FILE    — chữ ký NHÚNG trong PE (Chrome, 7-Zip, Git, phần
     *                        mềm thương mại nói chung)
     *   WTD_CHOICE_CATALOG — chữ ký trong file .cat (phần lớn binary Windows:
     *                        cmd.exe, conhost.exe, svchost.exe... KHÔNG nhúng
     *                        chữ ký, Microsoft ký gộp trong catalog)
     *
     * Thiếu chế độ thứ hai = F1 bật cho mọi binary Microsoft.
     */
    inline bool VerifySignature(const std::wstring& path) {
        /* Buoc 1: Chu ky nhung trong PE (Chrome, 7-Zip, Git, phan mem thuong mai) */
        if (VerifyEmbeddedSignature(path)) return true;

        /* Buoc 2: Chu ky qua catalog Windows (.cat files) */
        if (VerifyCatalogSignature(path)) return true;

        /* Buoc 3: SfcIsFileProtected — Windows File Protection (WFP).
           Fallback cho cac file he thong ma CryptCATAdminEnumCatalogFromHash
           van tra ve NULL (certutil.exe, conhost.exe, SearchFilterHost.exe,...).
           Neu WFP bao ve file nay thi no chac chan la binary Microsoft hop le. */
        if (SfcIsFileProtected(nullptr, path.c_str())) return true;

        return false;
    }

    /* ---- PE MAPPER — đọc file vào RAM, cung cấp RVA->offset ---- */
    class PeImage {
    public:
        bool Load(const std::wstring& path) {
            buf_ = ReadAll(path);
            if (buf_.size() < sizeof(IMAGE_DOS_HEADER)) return false;

            auto* dos = (IMAGE_DOS_HEADER*)buf_.data();
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
            if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > buf_.size()) return false;

            nt_ = (IMAGE_NT_HEADERS32*)(buf_.data() + dos->e_lfanew);
            if (nt_->Signature != IMAGE_NT_SIGNATURE) return false;

            is64_ = (nt_->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
            sec_ = IMAGE_FIRST_SECTION(nt_);
            nsec_ = nt_->FileHeader.NumberOfSections;
            if (nsec_ == 0 || nsec_ > 96) return false;
            return true;
        }

        DWORD RvaToOffset(DWORD rva) const {
            for (WORD i = 0; i < nsec_; i++) {
                DWORD start = sec_[i].VirtualAddress;
                DWORD size = (std::max)(sec_[i].Misc.VirtualSize, sec_[i].SizeOfRawData);
                if (rva >= start && rva < start + size)
                    return sec_[i].PointerToRawData + (rva - start);
            }
            return 0;
        }
        template<typename T> const T* At(DWORD off) const {
            if (off == 0 || off + sizeof(T) > buf_.size()) return nullptr;
            return (const T*)(buf_.data() + off);
        }
        const char* StrAt(DWORD off) const {
            if (off == 0 || off >= buf_.size()) return nullptr;
            return (const char*)(buf_.data() + off);
        }
        DWORD DirRva(int idx) const {
            if (is64_) {
                auto* n64 = (IMAGE_NT_HEADERS64*)nt_;
                if (idx >= (int)n64->OptionalHeader.NumberOfRvaAndSizes) return 0;
                return n64->OptionalHeader.DataDirectory[idx].VirtualAddress;
            }
            if (idx >= (int)nt_->OptionalHeader.NumberOfRvaAndSizes) return 0;
            return nt_->OptionalHeader.DataDirectory[idx].VirtualAddress;
        }
        bool Is64() const { return is64_; }
        WORD SectionCount() const { return nsec_; }
        const IMAGE_SECTION_HEADER* Sections() const { return sec_; }
        const std::vector<uint8_t>& Buf() const { return buf_; }

    private:
        std::vector<uint8_t>   buf_;
        IMAGE_NT_HEADERS32* nt_ = nullptr;
        IMAGE_SECTION_HEADER* sec_ = nullptr;
        WORD                   nsec_ = 0;
        bool                   is64_ = false;

        static std::vector<uint8_t> ReadAll(const std::wstring& p) {
            std::vector<uint8_t> v;
            HANDLE h = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if (h == INVALID_HANDLE_VALUE) return v;
            LARGE_INTEGER sz{}; GetFileSizeEx(h, &sz);
            if (sz.QuadPart > 0 && sz.QuadPart < 128ll * 1024 * 1024) {
                v.resize((size_t)sz.QuadPart);
                DWORD got = 0;
                if (!ReadFile(h, v.data(), (DWORD)v.size(), &got, nullptr)) v.clear();
                else v.resize(got);
            }
            CloseHandle(h);
            return v;
        }
    };

    /* ---- F2 — Packer/Cryptor: entropy theo SECTION THỰC THI ---- */
    inline bool DetectPackedBySection(const PeImage& pe) {
        auto* sec = pe.Sections();
        for (WORD i = 0; i < pe.SectionCount(); i++) {
            if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            if (sec[i].SizeOfRawData == 0) continue;

            size_t off = sec[i].PointerToRawData;
            size_t len = (std::min)((size_t)sec[i].SizeOfRawData, pe.Buf().size() - off);
            if (off >= pe.Buf().size() || len < 1024) continue;

            double h = CalculateEntropy(pe.Buf().data() + off, len);

            char nm[9] = {};
            memcpy(nm, sec[i].Name, 8);
            LOG_D("      section %-8s  H=%.2f  (exec)", nm, h);

            if (h > cfg::ENTROPY_PACKED_SECTION) {
                LOG_I("      -> section '%s' entropy %.2f > %.1f  => PACKED",
                    nm, h, cfg::ENTROPY_PACKED_SECTION);
                return true;
            }
        }
        return false;
    }

    /* Section name lạ = dấu hiệu packer đã biết */
    inline bool DetectPackedBySectionName(const PeImage& pe) {
        static const char* kPackerSecs[] = {
            "UPX0", "UPX1", "UPX2", ".aspack", ".adata", "ASPack",
            ".nsp0", ".nsp1", "PEC2", "PELOCKnt", ".petite", ".Themida",
            ".vmp0", ".vmp1", ".enigma1", "MPRESS1", "MPRESS2",
        };
        auto* sec = pe.Sections();
        for (WORD i = 0; i < pe.SectionCount(); i++) {
            char nm[9] = {}; memcpy(nm, sec[i].Name, 8);
            for (auto* k : kPackerSecs)
                if (_stricmp(nm, k) == 0) {
                    LOG_I("      -> section name '%s' => PACKER da biet", nm);
                    return true;
                }
        }
        return false;
    }

    /* Duyệt một bảng thunk (IAT/INT) tại thunkRva, so tên hàm với danh sách
       fns. Dùng chung cho cả import thường và delay-import — cả hai đều
       lưu thunk theo cùng format IMAGE_THUNK_DATA. */
    inline bool ScanThunkNames(const PeImage& pe, DWORD thunkRva,
        const char* const* fns, size_t nFns, const char** hitOut = nullptr) {
        DWORD thunkOff = pe.RvaToOffset(thunkRva);
        if (!thunkOff) return false;

        for (int t = 0; t < 4096; t++) {
            DWORD nameRva = 0;
            if (pe.Is64()) {
                auto* th = pe.At<ULONGLONG>(thunkOff + t * sizeof(ULONGLONG));
                if (!th || *th == 0) break;
                if (*th & IMAGE_ORDINAL_FLAG64) continue;      // import theo ordinal
                nameRva = (DWORD)*th;
            }
            else {
                auto* th = pe.At<DWORD>(thunkOff + t * sizeof(DWORD));
                if (!th || *th == 0) break;
                if (*th & IMAGE_ORDINAL_FLAG32) continue;
                nameRva = *th;
            }
            DWORD nameOff = pe.RvaToOffset(nameRva);
            if (!nameOff) continue;
            const char* fn = pe.StrAt(nameOff + 2);   // bỏ WORD Hint
            if (!fn) continue;

            for (size_t i = 0; i < nFns; i++)
                if (_stricmp(fn, fns[i]) == 0) {
                    if (hitOut) *hitOut = fn;
                    return true;
                }
        }
        return false;
    }

    /* Layout ổn định của IMAGE_DELAYLOAD_DESCRIPTOR, định nghĩa lại tại chỗ
       để không phụ thuộc <delayimp.h> — chỉ đọc offset, không gọi API
       delay-load nào. */
    struct RwDelayDesc {
        DWORD Attributes, DllNameRVA, ModuleHandleRVA, ImportAddressTableRVA,
            ImportNameTableRVA, BoundImportAddressTableRVA,
            UnloadInformationTableRVA, TimeDateStamp;
    };

    /*
     * F5 — Crypto API: parse cả IMPORT thường lẫn DELAY-IMPORT.
     *
     * Binary build với /DELAYLOAD (nạp bcrypt.dll/advapi32.dll trễ lúc cần)
     * lưu tên hàm ở IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, KHÔNG nằm trong
     * IMAGE_DIRECTORY_ENTRY_IMPORT — chỉ quét import thường sẽ bỏ sót,
     * trong khi đây vẫn là thông tin tĩnh 100%, không cần resolve API lúc
     * chạy để né.
     */
    inline bool DetectCryptoImports(const PeImage& pe) {
        static const char* kCryptoFns[] = {
            "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptImportKey",
            "CryptAcquireContextA", "CryptAcquireContextW", "CryptDeriveKey",
            "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey",
            "BCryptImportKey", "BCryptOpenAlgorithmProvider",
            "NCryptEncrypt", "NCryptDecrypt", "RtlEncryptMemory",
        };
        const size_t nFns = ARRAYSIZE(kCryptoFns);
        const char* hit = nullptr;

        DWORD impRva = pe.DirRva(IMAGE_DIRECTORY_ENTRY_IMPORT);
        if (!impRva) {
            LOG_D("      Khong co import directory (co the da bi pack)");
        }
        else {
            DWORD impOff = pe.RvaToOffset(impRva);
            for (int d = 0; impOff && d < 256; d++) {
                auto* desc = pe.At<IMAGE_IMPORT_DESCRIPTOR>(impOff + d * sizeof(IMAGE_IMPORT_DESCRIPTOR));
                if (!desc || desc->Name == 0) break;

                DWORD thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
                if (thunkRva && ScanThunkNames(pe, thunkRva, kCryptoFns, nFns, &hit)) {
                    LOG_I("      -> import Crypto API: %s", hit);
                    return true;
                }
            }
        }

        DWORD delayRva = pe.DirRva(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
        if (delayRva) {
            DWORD delayOff = pe.RvaToOffset(delayRva);
            for (int d = 0; delayOff && d < 256; d++) {
                auto* desc = pe.At<RwDelayDesc>(delayOff + d * sizeof(RwDelayDesc));
                if (!desc || desc->DllNameRVA == 0) break;

                if (desc->ImportNameTableRVA &&
                    ScanThunkNames(pe, desc->ImportNameTableRVA, kCryptoFns, nFns, &hit)) {
                    LOG_I("      -> delay-import Crypto API: %s", hit);
                    return true;
                }
            }
        }

        return false;
    }

    /*
     * F3 / F6 — Quét chuỗi.
     *
     * Dùng find() substring thuần cho mọi từ khoá là không an toàn: "conti"
     * khớp cả "continue" (floss.exe, diec.exe, mọi binary có thông báo lỗi
     * tiếng Anh), "hive" khớp "archive", "decrypt" khớp cả thư viện crypto
     * hợp lệ. Vì vậy tách hai loại từ khoá:
     *   - PHRASE: cụm dài, đặc trưng -> substring là đủ, 1 hit = bật cờ
     *   - WORD:   tên họ ngắn -> phải khớp BIÊN TỪ, và cần >= 2 từ khác nhau
     */

       /* Khớp needle như một TỪ RIÊNG, không phải substring */
    inline bool ContainsWord(const std::string& hay, const std::string& needle) {
        if (needle.empty()) return false;
        size_t pos = 0;
        while ((pos = hay.find(needle, pos)) != std::string::npos) {
            bool leftOk = (pos == 0) || !isalnum((unsigned char)hay[pos - 1]);
            size_t end = pos + needle.size();
            bool rightOk = (end >= hay.size()) || !isalnum((unsigned char)hay[end]);
            if (leftOk && rightOk) return true;
            pos = end;
        }
        return false;
    }

    /*
     * Cụm dài, đặc trưng — không thể trùng ngẫu nhiên. Danh sách gộp từ
     * corpus ransom note thực tế (140 mục đầu) cộng thêm các mục cũ của
     * RansomDefense (đuôi file/tên riêng đặc trưng — Dharma, LockBit,
     * Stop/DJVU, Ryuk...) chưa có trong corpus.
     */
    inline const std::vector<std::string>& RansomPhrases() {
        static const std::vector<std::string> k = {
            "all leaked data",
            "are encrypted backups",
            "backups were either encrypted",
            "choose mode for",
            "damage encrypted data",
            "data after payment",
            "data and are ready to publish",
            "data are stolen",
            "data has been encrypted",
            "data has been stolen",
            "data is encrypted",
            "data is stolen",
            "data leak from your company",
            "data was encrypted",
            "data was leaked",
            "data we usually steal",
            "data were encrypted",
            "data will be leaked",
            "data will be published",
            "decrypt all your files",
            "decrypt one file",
            "decrypt software to restore",
            "decrypt some files",
            "decrypt the files",
            "decrypt two random files",
            "decrypt using third party software",
            "decrypt without the key",
            "decrypt your data",
            "decrypt your files",
            "decrypting of your files",
            "decrypting your servers",
            "decryption help programs",
            "decryption key will be deleted",
            "decryption keys will be permanently",
            "decryption of your files",
            "decryption software for your situation",
            "decryption software is available",
            "decryption software is perfectly",
            "decryption tool and the how",
            "decryption tool will make",
            "decryptor key that only",
            "download the tor browser",
            "download tor browser",
            "encrypted and readme files",
            "encrypted backups are deleted",
            "encrypted data but not recover",
            "encrypted file will be corrupted",
            "encrypted files have new",
            "encrypted files may",
            "encrypted files yourself",
            "encrypted or deleted or backup",
            "encrypted your files",
            "encrypted your workstations and servers",
            "enter safe mode",
            "every encrypted file",
            "file to confirm that our decryptor",
            "files and we will decrypt",
            "files are currently encrypted",
            "files are encrypted",
            "files for free decryption",
            "files has been encrypted",
            "files have been encrypted",
            "files have been stolen",
            "files our decrypt",
            "files that were stolen",
            "files were encrypted",
            "files were stolen",
            "files will be published",
            "files will remain encrypted",
            "find command for",
            "get decryption software",
            "have decryption software",
            "install the tor browser",
            "install tor browser",
            "key and decrypt",
            "key our decrypt",
            "leaked data is disclosed",
            "leaked data samples",
            "leaked data will be disclosed",
            "link for tor browser",
            "link in tor browser",
            "modify encrypted files",
            "network and encrypted",
            "network has been encrypted",
            "network have been encrypted",
            "network is encrypted",
            "no decryption software",
            "not get sfx",
            "not read sfx",
            "not write sfx",
            "open the tor browser",
            "open tor browser",
            "our decrypt software",
            "our decryption software",
            "our decryption tool",
            "pay the ransom",
            "pay we will release your data",
            "programs for decryption",
            "public decryption software",
            "publishing your data",
            "publishing your files",
            "ransom the data",
            "ransom we will attack",
            "rename encrypted files",
            "review leaked data",
            "run tor browser",
            "servers and hosts were completely encrypted",
            "servers are encrypted",
            "site you will need tor browser",
            "software to decrypt",
            "special decryption software",
            "stolen from your network",
            "system was encrypted",
            "systems are encrypted",
            "the data leak",
            "the decryption keys",
            "the decryption software",
            "the decryption tool",
            "the encrypted files",
            "the leaked data",
            "the ransom amount",
            "tool and decrypt",
            "tool will make decryption",
            "tor browser and visit",
            "tor browser bundle install",
            "tor browser from this site",
            "tor browser open",
            "tor browser to access",
            "tor browser to open",
            "tor browser using",
            "unique decryption key",
            "use tor browser",
            "using tor browser",
            "via tor browser",
            "website in the tor browser",
            "windows for workgroups",
            "working decryption tool",
            "your decryption keys",
            "your encrypted files",
            "your leaked data",
        };
        return k;
    }

    /*
     * TÊN HỌ RANSOMWARE — MỘT hit là ĐỦ.
     *
     * Không được gộp chung tên họ với nhóm "từ chung chung" rồi bắt buộc
     * >= 2 hit: mẫu WannaCry thật chỉ chứa đúng một token đặc trưng là
     * "wncry", nên yêu cầu >= 2 sẽ khiến F3 miss chính ransomware nổi tiếng
     * nhất lịch sử. Nhờ ContainsWord khớp theo biên từ (không phải
     * substring), "conti" đứng riêng không còn khớp nhầm "continue" nữa, nên
     * tên họ đứng một mình là đủ đặc trưng để chỉ cần 1 hit.
     *
     * Danh sách gộp từ corpus thực tế (133 mục đầu) cộng thêm các họ cũ của
     * RansomDefense còn thiếu trong corpus — trong đó có akira và sodinokibi,
     * hai họ chiếm 101/476 mẫu trong tập dữ liệu thực nghiệm của đồ án
     * (Bảng 3.2.3): bỏ hai tên này sẽ làm F3 mất khả năng nhận theo tên cho
     * đúng phần lớn dataset đang dùng để train/test.
     */
    inline const std::vector<std::string>& RansomFamilies() {
        static const std::vector<std::string> k = {
            "abysslocker",
            "ailock",
            "alphv",
            "antefrigus",
            "atomsilo",
            "auditteam",
            "avaddon",
            "avoslocker",
            "bianlian",
            "biglock",
            "bitpaymer",
            "bitransomware",
            "blackbasta",
            "blackbyte",
            "blackfield",
            "blackhunt",
            "blacklock",
            "blackmatter",
            "blacksuit",
            "blackwater",
            "bluesky",
            "bluewindgroup",
            "booba",
            "braincipher",
            "bytesfromheaven",
            "cerber",
            "chilelocker",
            "cicada3301",
            "ciphbit",
            "conti",
            "crypto24",
            "cryptomix",
            "cryptxxx",
            "crytox",
            "ctblocker",
            "cyberex",
            "dagonlocker",
            "darkangels",
            "darkbit",
            "darkpower",
            "darkside",
            "datacarry",
            "deadbydawn",
            "dennisthehitman",
            "devman",
            "diavol",
            "direwolf",
            "doppelpaymer",
            "dragonforce",
            "ech0raix",
            "esxiargs",
            "exitium",
            "ftcode",
            "gandcrab",
            "gr33nbl00d",
            "gunra",
            "gwisinlocker",
            "h0lygh0st",
            "helldown",
            "hellokitty",
            "icefire",
            "industrialspy",
            "kairos",
            "karakurt",
            "kawalocker",
            "killada",
            "krybit",
            "krypt",
            "kuiper",
            "lamashtu",
            "lapiovra",
            "leaknet",
            "lockbit",
            "luckbit",
            "m3rx",
            "magniber",
            "makop",
            "mallox",
            "medusa",
            "medusalocker",
            "moneymessage",
            "nefilim",
            "nemty",
            "netrunner",
            "netwalker",
            "nightspire",
            "nokoyawa",
            "novagroup",
            "nullbulge",
            "obscura",
            "osiris_project",
            "payoutsking",
            "prolock",
            "qilin",
            "qlocker",
            "quantumlocker",
            "quicklock",
            "ragnarlocker",
            "ragnarok",
            "ralord",
            "rancoz",
            "ransomexx",
            "ransomhouse",
            "ransomhub",
            "ranzy",
            "raworld",
            "redalert",
            "revil",
            "rhysida",
            "rtmlocker",
            "ryuk",
            "safepay",
            "satancd",
            "scarecrow",
            "sensayq",
            "sinobi",
            "suncrypt",
            "targetcompany",
            "tengu",
            "teslacrypt",
            "thegentlemen",
            "tommyleaks",
            "trigona",
            "u-bomb",
            "vanhelsing",
            "vicesociety",
            "vohuk",
            "wastedlocker",
            "weaxor",
            "whitelock",
            "xleaks",
            "xorist",
            "yanluowang",
            "wncry",
            "wanacry",
            "wannacry",
            "wanacrypt",
            "wncryt",
            "sodinokibi",
            "blackcat",
            "locky",
            "cryptolocker",
            "cryptowall",
            "petya",
            "notpetya",
            "maze",
            "egregor",
            "clop",
            "dharma",
            "phobos",
            "stop_djvu",
            "royalransom",
            "akira",
            "8base",
            "royal",
            "play",
            "meow",
            "hunters",
            "scattered",
            "snatch",
            "monti",
            "arrow",
            "bip",
            "combo",
            "gamma",
            "djvu",
            "neer",
            "nook",
            "maas",
            "kuus",
            "topi",
            "koom",
        };
        return k;
    }

    /* Từ CHUNG CHUNG — cần >= 2 từ khác nhau (một mình quá dễ trùng) */
    inline const std::vector<std::string>& RansomGeneric() {
        static const std::vector<std::string> k = {
            "ransom", "bitcoin", "monero", "decryptor", "encrypter",
            "ransomware", "extortion", "payload",
        };
        return k;
    }

    /*
     * F6 — mảnh LỆNH, không phải từ đơn.
     *
     * Không dùng từ đơn như "safeboot" đứng một mình: đó là thuật ngữ Windows
     * bình thường và khớp cả api-ms-win-core-sysinfo-l1-2-0.dll (DLL
     * Microsoft hợp lệ), gây dương tính giả. Nguồn CHÍNH của F6 là command
     * line tiến trình con (HandleProcessCreate); quét chuỗi ở đây chỉ là tín
     * hiệu phụ nên phải dùng cụm lệnh đặc trưng, không dùng từ đơn.
     */
    inline const std::vector<std::string>& SafeModePhrases() {
        static const std::vector<std::string> k = {
            "bcdedit /set",
            "bcdedit.exe",
            "safeboot minimal",
            "safeboot network",
            "recoveryenabled no",
            "bootstatuspolicy ignoreallfailures",
            "vssadmin delete shadows",
            "vssadmin.exe delete",
            "wbadmin delete catalog",
            "wbadmin.exe delete",
            "shadowcopy delete",
            "win32_shadowcopy",
            "delete shadows /all",
            "set-mppreference -disablerealtimemonitoring",
        };
        return k;
    }

    /* Trích văn bản in được: ASCII + UTF-16LE */
    inline void ExtractText(const std::vector<uint8_t>& buf,
        std::string& ascii, std::string& wide)
    {
        size_t n = (std::min)(buf.size(), (size_t)8 * 1024 * 1024);
        ascii.assign((const char*)buf.data(), n);
        ascii = ToLowerA(ascii);

        wide.reserve(n / 2);
        for (size_t i = 0; i + 1 < n; i += 2)
            if (buf[i + 1] == 0 && buf[i] >= 0x20 && buf[i] < 0x7F)
                wide += (char)::tolower(buf[i]);
    }

    /*
     * Quét ransom — ba tầng:
     *   1. Cụm dài đặc trưng     -> 1 hit đủ
     *   2. Tên họ (biên từ)      -> 1 hit đủ   <<< bắt được WannaCry
     *   3. Từ chung chung        -> cần >= 2
     */
    inline bool ScanRansomText(const std::string& ascii, const std::string& wide) {
        for (const auto& p : RansomPhrases()) {
            if (ascii.find(p) != std::string::npos || wide.find(p) != std::string::npos) {
                LOG_I("      -> F3 phrase: \"%s\"", p.c_str());
                return true;
            }
        }
        for (const auto& f : RansomFamilies()) {
            if (ContainsWord(ascii, f) || ContainsWord(wide, f)) {
                LOG_I("      -> F3 ho ransomware: \"%s\"", f.c_str());
                return true;
            }
        }
        std::vector<std::string> hits;
        for (const auto& w : RansomGeneric()) {
            if (ContainsWord(ascii, w) || ContainsWord(wide, w)) {
                hits.push_back(w);
                if (hits.size() >= 2) {
                    LOG_I("      -> F3 tu chung chung: \"%s\" + \"%s\"",
                        hits[0].c_str(), hits[1].c_str());
                    return true;
                }
            }
        }
        if (hits.size() == 1)
            LOG_D("      (F3: chi 1 tu chung chung \"%s\" — chua du)", hits[0].c_str());
        return false;
    }

    inline bool ScanSafeModeText(const std::string& ascii, const std::string& wide) {
        for (const auto& p : SafeModePhrases())
            if (ascii.find(p) != std::string::npos || wide.find(p) != std::string::npos) {
                LOG_I("      -> F6 string: \"%s\"", p.c_str());
                return true;
            }
        return false;
    }

    /*
     * CHẠY CÔNG CỤ NGOÀI — có timeout THẬT.
     *
     * Không được đọc pipe bằng ReadFile trong vòng lặp rồi chờ
     * WaitForSingleObject(timeout) sau đó: ReadFile CHẶN cho tới khi pipe
     * đóng, nên nếu tool con treo thì ReadFile treo mãi mãi và
     * WaitForSingleObject không bao giờ được chạy tới — "timeout" kiểu đó là
     * ảo, thực tế treo vô hạn. Phải dùng PeekNamedPipe để kiểm tra dữ liệu
     * sẵn có trước khi đọc, kết hợp deadline theo GetTickCount64 và
     * TerminateProcess khi hết hạn.
     */
    inline std::wstring GetModuleDir() {
        wchar_t buf[MAX_PATH * 2] = {};
        GetModuleFileNameW(nullptr, buf, MAX_PATH * 2);
        std::wstring p(buf);
        size_t s = p.find_last_of(L"\\/");
        return (s == std::wstring::npos) ? L"" : p.substr(0, s);
    }

    inline std::string ExecuteAndCapture(const std::wstring& cmdLine, DWORD timeoutMs) {
        SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
        HANDLE rd = nullptr, wr = nullptr;
        if (!CreatePipe(&rd, &wr, &sa, 0)) return {};
        SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);   /* đầu đọc không kế thừa */

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        si.hStdOutput = wr;
        si.hStdError = wr;
        PROCESS_INFORMATION pi{};

        std::vector<wchar_t> cmd(cmdLine.begin(), cmdLine.end());
        cmd.push_back(L'\0');

        if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE,
            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            CloseHandle(rd); CloseHandle(wr);
            return {};
        }
        CloseHandle(wr);   /* BẮT BUỘC: cha phải đóng đầu ghi, không thì pipe không bao giờ EOF */

        std::string out;
        ULONGLONG deadline = GetTickCount64() + timeoutMs;
        char chunk[8192];
        bool timedOut = false;

        for (;;) {
            DWORD avail = 0;
            if (!PeekNamedPipe(rd, nullptr, 0, nullptr, &avail, nullptr)) break;

            if (avail > 0) {
                DWORD want = (DWORD)(std::min)((size_t)sizeof(chunk), (size_t)avail);
                DWORD got = 0;
                if (!ReadFile(rd, chunk, want, &got, nullptr) || got == 0) break;
                if (out.size() + got > cfg::TOOL_MAX_OUTPUT) {
                    LOG_W("      Tool xuat qua %zu MB -> cat bot",
                        cfg::TOOL_MAX_OUTPUT / 1048576);
                    break;
                }
                out.append(chunk, got);
                continue;
            }
            /* Không có dữ liệu — tiến trình xong chưa? */
            if (WaitForSingleObject(pi.hProcess, 20) == WAIT_OBJECT_0) {
                DWORD left = 0;
                if (PeekNamedPipe(rd, nullptr, 0, nullptr, &left, nullptr) && left > 0) continue;
                break;
            }
            if (GetTickCount64() > deadline) { timedOut = true; break; }
        }

        if (timedOut) {
            TerminateProcess(pi.hProcess, 1);
            LOG_W("      Tool timeout sau %lums -> da kill", timeoutMs);
        }
        CloseHandle(rd);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return out;
    }

    /* ---- DIE (Detect It Easy) — TUỲ CHỌN. Trả về: -1 không có tool | 0 không packed | 1 packed ---- */
    inline int RunDIE(const std::wstring& filePath) {
        std::wstring dir = GetModuleDir();
        std::wstring die = dir + cfg::DIE_REL_PATH;
        if (!fs::exists(die)) return -1;

        std::wstring cmd = L"\"" + die + L"\" -p \"" + filePath +
            L"\" -D \"" + dir + cfg::DIE_DB_REL_PATH + L"\"";

        std::string out = ToLowerA(ExecuteAndCapture(cmd, cfg::DIE_TIMEOUT_MS));
        if (out.empty()) return 0;

        /*
         * DIE có 2 format output tuỳ flag:
         *   Text (-p):   "PE64 | packer: UPX 3.96"
         *   CSV (--csv): "PE64,packer,UPX(3.96)[NRV,best]"
         *
         * kHits bắt cả 2 format — "packer," khớp CSV, "packer:" khớp text.
         */
        static const char* kHits[] = {
            "packer:", "packer,",          // F2 chính
            "protector:", "protector,",    // protector = dạng pack đặc biệt
            "encrypted,", "encrypted:",    // file bị encrypt toàn bộ
            "obfuscator:", "obfuscator,",  // obfuscator
            "crypter:", "crypter,",        // crypter thường dùng bởi ransomware
        };
        for (auto* h : kHits)
            if (out.find(h) != std::string::npos) {
                size_t p = out.find(h);
                LOG_I("      -> DIE: %s", out.substr(p, std::min((size_t)80, out.size() - p)).c_str());
                return 1;
            }
        LOG_D("      -> DIE: khong phat hien packer (%zu bytes output)", out.size());
        return 0;
    }

    /*
     * FLOSS — TUỲ CHỌN nhưng QUAN TRỌNG.
     *
     * Ransomware hiện đại dựng chuỗi ransom note trên STACK lúc chạy để né
     * quét chuỗi tĩnh: trong file .exe không hề có chuỗi "your files have
     * been encrypted", chỉ có một loạt lệnh kiểu
     * mov byte [rsp+N], 'y' / mov byte [rsp+N+1], 'o' ... FLOSS mô phỏng
     * thực thi để tái tạo các chuỗi đó; quét chuỗi tĩnh thông thường không
     * làm được việc này nên sẽ miss đúng những mẫu tinh vi nhất.
     */
    inline std::string RunFLOSS(const std::wstring& filePath) {
        std::wstring floss = GetModuleDir() + cfg::FLOSS_REL_PATH;
        if (!fs::exists(floss)) return "\x01NOTOOL";   /* sentinel: phân biệt "không có tool" vs "không thấy gì" */

        std::wstring cmd = L"\"" + floss + L"\" --only stack tight decoded -- \"" + filePath + L"\"";
        return ToLowerA(ExecuteAndCapture(cmd, cfg::FLOSS_TIMEOUT_MS));
    }

    /*
     * ĐIỂM VÀO — chạy HOÀN TOÀN ngoài mutex.
     *
     * Chiến lược: NATIVE trước (rẻ, ~ms), EXTERNAL sau (đắt, giây) và chỉ
     * khi native miss. Native và external bù nhau: native entropy/section
     * bắt packer LẠ mà DIE chưa biết, DIE bắt packer ĐÃ BIẾT chính xác hơn
     * (database lớn), FLOSS bóc chuỗi trên stack mà native không làm được.
     */
    inline StaticResult AnalyzeStatic(const std::wstring& path) {
        StaticResult r;
        LOG_I("[STATIC] Phan tich: %s", ws2s(path).c_str());
        ULONGLONG t0 = GetTickCount64();

        r.imageSha256 = Sha256File(path);

        /* --- F1: embedded HOẶC catalog --- */
        r.unsignedImage = !VerifySignature(path);
        if (r.unsignedImage) LOG_D("      F1: khong co chu ky hop le (ca embedded lan catalog)");

        PeImage pe;
        bool peOk = pe.Load(path);
        if (!peOk) LOG_D("      Khong parse duoc PE (native F2/F5 bo qua)");

        /* --- NATIVE: nhanh (~ms), luôn chạy --- */
        if (peOk) {
            r.packed = DetectPackedBySectionName(pe) || DetectPackedBySection(pe);
            r.cryptoApi = DetectCryptoImports(pe);

            std::string ascii, wide;
            ExtractText(pe.Buf(), ascii, wide);
            r.suspStrings = ScanRansomText(ascii, wide);
            r.safeModeStr = ScanSafeModeText(ascii, wide);
        }

        /*
         * EXTERNAL: chậm (DIE 5s + FLOSS 20s) — CHỈ chạy khi đã có nghi ngờ.
         *
         * Không được chạy DIE/FLOSS cho mọi file: Windows tạo hàng chục tiến
         * trình mỗi phút (kể cả svchost.exe, RuntimeBroker.exe của Microsoft),
         * nên chạy vô điều kiện sẽ sinh hàng chục DIE/FLOSS song song. Trên
         * ARM64 hai tool này là binary x64 chạy qua emulation nên càng chậm,
         * dễ timeout liên tục. Vì vậy file có chữ ký hợp lệ và không có dấu
         * hiệu nghi ngờ nào thì bỏ qua bước external.
         */
        bool suspicious = r.unsignedImage || r.packed || r.cryptoApi || r.suspStrings;

        if (!suspicious) {
            LOG_I("[STATIC] %s -> sach (co chu ky, khong dau hieu) — bo qua DIE/FLOSS [%llums]",
                ws2s(GetFileNameOnly(path)).c_str(), GetTickCount64() - t0);
            return r;
        }

        /* --- F2: DIE chạy khi F1 bật hoặc đã có content hint
         * DIE phải chạy TRƯỚC mới biết packed — không thể chờ native detect xong
         * suspicious = true khi unsigned → DIE vẫn được gọi cho file không ký */
        if (!r.packed) {
            int die = RunDIE(path);
            if (die == 1)       r.packed = true;
            else if (die == -1) LOG_D("      (khong co diec.exe — chi dung native)");
        }

        /* --- F3: FLOSS chỉ khi đã có ít nhất 1 dấu hiệu (sau khi DIE chạy) --- */
        bool hasContentHint = r.packed || r.cryptoApi || r.suspStrings;
        if (!r.suspStrings && hasContentHint) {
            std::string fl = RunFLOSS(path);
            if (fl == "\x01NOTOOL") {
                LOG_D("      (khong co floss.exe — chuoi dung tren stack se BI MISS)");
            }
            else if (!fl.empty()) {
                r.suspStrings = ScanRansomText(fl, "");
                if (!r.safeModeStr) r.safeModeStr = ScanSafeModeText(fl, "");
            }
        }

        LOG_I("[STATIC] %s -> F1=%d F2=%d F3=%d F5=%d F6str=%d [%llums]",
            ws2s(GetFileNameOnly(path)).c_str(),
            r.unsignedImage, r.packed, r.suspStrings, r.cryptoApi, r.safeModeStr,
            GetTickCount64() - t0);
        return r;
    }

} // namespace rw