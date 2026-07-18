/*
 * StaticAnalyzer.h — Phân tích tĩnh (F1, F2, F3, F5).
 *
 * SỬA LỖI v3.0:
 *   F2: entropy fallback tính trên 64KB ĐẦU FILE — vùng đó là PE header +
 *       import table, entropy tự nhiên thấp -> fallback gần như không bao giờ bật.
 *       v4.0: parse section table, tính entropy RIÊNG từng section,
 *       chỉ quan tâm section THỰC THI.
 *
 *   F5: v3.0 dùng find() chuỗi "cryptencrypt" trên 4MB đầu.
 *       File bị pack -> IAT ẩn -> MISS. Chuỗi trùng ngẫu nhiên -> FALSE HIT.
 *       v4.0: parse IMAGE_IMPORT_DESCRIPTOR thật.
 *
 *   Toàn bộ hàm ở đây chạy NGOÀI mutex. v3.0 giữ lock suốt DIE 5s + FLOSS 15s
 *   -> đóng băng engine động 20 giây trong lúc ransomware đang chạy.
 */
#pragma once

#include "Util.h"
#include "Config.h"

#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace rw {

    struct StaticResult {
        bool unsignedImage = false;   // F1
        bool packed = false;   // F2
        bool suspStrings = false;   // F3
        bool cryptoApi = false;   // F5
        bool safeModeStr = false;   // F6 (tín hiệu phụ; nguồn chính là cmdline)
        std::string imageSha256;
    };

    /* ======================================================================
       F1 — Chữ ký số
       ======================================================================
       LỖI ĐÃ SỬA:
         Bản cũ chỉ gọi WinVerifyTrust với WTD_CHOICE_FILE -> chỉ đọc chữ ký
         NHÚNG TRONG FILE. Nhưng file hệ thống Windows (conhost.exe, svchost.exe,
         dllhost.exe, phần lớn System32) được ký qua SECURITY CATALOG (.cat trong
         C:\Windows\System32\CatRoot), KHÔNG nhúng chữ ký.

         Kết quả: F1 bật cho gần như MỌI binary Microsoft -> nhiễu + sai.

       Sửa: thử embedded trước, thất bại thì tra catalog.
       ====================================================================== */

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

    inline bool VerifyCatalogSignature(const std::wstring& path) {
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        HCATADMIN hCatAdmin = nullptr;
        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        if (!CryptCATAdminAcquireContext(&hCatAdmin, &action, 0)) {
            CloseHandle(hFile);
            return false;
        }

        DWORD hashLen = 0;
        CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, nullptr, 0);
        if (hashLen == 0) {
            CryptCATAdminReleaseContext(hCatAdmin, 0);
            CloseHandle(hFile);
            return false;
        }
        std::vector<BYTE> hash(hashLen);
        if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, hash.data(), 0)) {
            CryptCATAdminReleaseContext(hCatAdmin, 0);
            CloseHandle(hFile);
            return false;
        }

        /* Member tag = hash dạng hex HOA */
        std::wstring tag;
        {
            static const wchar_t* k = L"0123456789ABCDEF";
            tag.reserve(hashLen * 2);
            for (DWORD i = 0; i < hashLen; i++) {
                tag += k[hash[i] >> 4];
                tag += k[hash[i] & 0x0F];
            }
        }

        bool ok = false;
        HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(
            hCatAdmin, hash.data(), hashLen, 0, nullptr);

        if (hCatInfo) {
            CATALOG_INFO ci{};
            ci.cbStruct = sizeof(ci);
            if (CryptCATCatalogInfoFromContext(hCatInfo, &ci, 0)) {
                WINTRUST_CATALOG_INFO wtc{};
                wtc.cbStruct = sizeof(wtc);
                wtc.pcwszCatalogFilePath = ci.wszCatalogFile;
                wtc.pcwszMemberTag = tag.c_str();
                wtc.pcwszMemberFilePath = path.c_str();
                wtc.hMemberFile = hFile;
                wtc.pbCalculatedFileHash = hash.data();
                wtc.cbCalculatedFileHash = hashLen;
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
                LONG r = WinVerifyTrust(nullptr, &g, &wd);
                wd.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(nullptr, &g, &wd);
                ok = (r == ERROR_SUCCESS);
            }
            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
        }

        CryptCATAdminReleaseContext(hCatAdmin, 0);
        CloseHandle(hFile);
        return ok;
    }

    inline bool VerifySignature(const std::wstring& path) {
        if (VerifyEmbeddedSignature(path)) return true;
        return VerifyCatalogSignature(path);   /* <<< thiếu cái này = F1 sai với mọi file MS */
    }

    /* ======================================================================
       PE MAPPER — đọc file vào RAM, cung cấp RVA->offset
       ====================================================================== */
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

    /* ======================================================================
       F2 — Packer/Cryptor: entropy theo SECTION THỰC THI
       ====================================================================== */
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

    /* ======================================================================
       F5 — Crypto API: parse IMPORT ADDRESS TABLE thật
       ====================================================================== */
    inline bool DetectCryptoImports(const PeImage& pe) {
        static const char* kCryptoFns[] = {
            "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptImportKey",
            "CryptAcquireContextA", "CryptAcquireContextW", "CryptDeriveKey",
            "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey",
            "BCryptImportKey", "BCryptOpenAlgorithmProvider",
            "NCryptEncrypt", "NCryptDecrypt", "RtlEncryptMemory",
        };

        DWORD impRva = pe.DirRva(IMAGE_DIRECTORY_ENTRY_IMPORT);
        if (!impRva) {
            LOG_D("      Khong co import directory (co the da bi pack)");
            return false;
        }
        DWORD impOff = pe.RvaToOffset(impRva);
        if (!impOff) return false;

        for (int d = 0; d < 256; d++) {
            auto* desc = pe.At<IMAGE_IMPORT_DESCRIPTOR>(impOff + d * sizeof(IMAGE_IMPORT_DESCRIPTOR));
            if (!desc || desc->Name == 0) break;

            DWORD thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
            if (!thunkRva) continue;
            DWORD thunkOff = pe.RvaToOffset(thunkRva);
            if (!thunkOff) continue;

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

                for (auto* k : kCryptoFns)
                    if (_stricmp(fn, k) == 0) {
                        LOG_I("      -> import Crypto API: %s", fn);
                        return true;
                    }
            }
        }
        return false;
    }

    /* ======================================================================
       F3 / F6 — Quét chuỗi
       ======================================================================
       LỖI ĐÃ SỬA: dùng find() substring cho MỌI từ khoá.
         "conti" khớp "continue"   -> floss.exe, diec.exe, mọi binary có
                                      thông báo lỗi tiếng Anh đều dính
         "hive"  khớp "archive"    -> tương tự
         "decrypt" khớp mọi thư viện crypto hợp lệ

       Sửa:
         - PHRASE: cụm dài, đặc trưng -> substring là đủ, 1 hit = bật cờ
         - WORD:   tên họ ngắn -> phải khớp BIÊN TỪ, và cần >= 2 từ khác nhau
       ====================================================================== */

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

    /* Cụm dài, đặc trưng — không thể trùng ngẫu nhiên */
    inline const std::vector<std::string>& RansomPhrases() {
        static const std::vector<std::string> k = {
            "your files have been encrypted",
            "all your files are encrypted",
            "your files are encrypted",
            "files have been encrypted",
            "how to decrypt your files",
            "restore your files",
            "pay to recover",
            "decryption key",
            "decrypt your data",
            "bitcoin wallet",
            "btc wallet",
            "tor browser",
            ".onion",
            "readme_for_decrypt",
            "how_to_recover",
            "your network has been",
            "wanadecryptor",
            "@wanadecryptor@",
        };
        return k;
    }

    /*
     * TÊN HỌ RANSOMWARE — MỘT hit là ĐỦ.
     *
     * LỖI ĐÃ SỬA (F3 MISS WannaCry thật):
     *   Bản trước gộp chung tên họ với từ chung chung rồi bắt phải có >=2 từ.
     *   WannaCry thật chỉ có ĐÚNG MỘT token: "wncry"
     *   -> log: (F3: chi 1 tu "wncry" — chua du, can >=2)
     *   -> F3 = 0 cho ransomware nổi tiếng nhất lịch sử. Sửa quá tay.
     *
     * Sau khi có ContainsWord (khớp BIÊN TỪ), "conti" đứng riêng KHÔNG BAO GIỜ
     * khớp "continue" nữa -> tên họ đứng một mình đã đủ đặc trưng.
     */
    inline const std::vector<std::string>& RansomFamilies() {
        static const std::vector<std::string> k = {
            "wncry", "wanacry", "wannacry", "wanacrypt", "wncryt",
            "conti", "ryuk", "revil", "sodinokibi", "lockbit", "blackcat",
            "locky", "cerber", "darkside", "cryptolocker", "cryptowall",
            "teslacrypt", "petya", "notpetya", "maze", "egregor", "clop",
            "dharma", "phobos", "stop_djvu", "medusalocker", "avaddon",
            "blackbasta", "royalransom", "akira", "8base",
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
     * LỖI ĐÃ SỬA (dương tính giả trên DLL Microsoft đã ký):
     *   Bản trước có "safeboot" đứng một mình -> khớp
     *   api-ms-win-core-sysinfo-l1-2-0.dll (DLL Microsoft hợp lệ) -> F6 = 1.
     *   "safeboot" là thuật ngữ Windows bình thường.
     *
     * Nguồn CHÍNH của F6 là command line tiến trình con (HandleProcessCreate).
     * Quét chuỗi chỉ là tín hiệu phụ -> phải chặt.
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

    /* ======================================================================
       CHẠY CÔNG CỤ NGOÀI — có timeout THẬT
       ======================================================================
       LỖI v3.0:
           while (ReadFile(hRead, ...)) { ... }
           WaitForSingleObject(pi.hProcess, 5000);
       ReadFile CHẶN cho tới khi pipe đóng. Nếu tool treo, ReadFile treo mãi mãi
       và WaitForSingleObject(5000) không bao giờ được chạy tới.
       "Timeout 5s" đó là ảo — thực tế treo vô hạn.

       v4.0: PeekNamedPipe + deadline + TerminateProcess.
       ====================================================================== */
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

    /* ======================================================================
       DIE (Detect It Easy) — TUỲ CHỌN
       Trả về: -1 không có tool | 0 không packed | 1 packed
       ====================================================================== */
    inline int RunDIE(const std::wstring& filePath) {
        std::wstring dir = GetModuleDir();
        std::wstring die = dir + cfg::DIE_REL_PATH;
        if (!fs::exists(die)) return -1;

        std::wstring cmd = L"\"" + die + L"\" -p \"" + filePath +
            L"\" -D \"" + dir + cfg::DIE_DB_REL_PATH + L"\"";

        std::string out = ToLowerA(ExecuteAndCapture(cmd, cfg::DIE_TIMEOUT_MS));
        if (out.empty()) return 0;

        static const char* kHits[] = { "packer:", "protector:", "encrypted", "obfuscator:" };
        for (auto* h : kHits)
            if (out.find(h) != std::string::npos) {
                size_t p = out.find(h);
                LOG_I("      -> DIE: %s", out.substr(p, 60).c_str());
                return 1;
            }
        return 0;
    }

    /* ======================================================================
       FLOSS — TUỲ CHỌN nhưng QUAN TRỌNG
       ======================================================================
       Ransomware hiện đại DỰNG chuỗi ransom note TRÊN STACK lúc chạy —
       chính là để né quét chuỗi tĩnh. Trong file .exe không hề có chuỗi
       "your files have been encrypted", chỉ có một loạt lệnh
       mov byte [rsp+N], 'y'  /  mov byte [rsp+N+1], 'o' ...

       FLOSS mô phỏng thực thi để tái tạo chúng. ScanStrings native
       KHÔNG THỂ làm việc này -> F3 sẽ miss đúng những mẫu tinh vi nhất.
       ====================================================================== */
    inline std::string RunFLOSS(const std::wstring& filePath) {
        std::wstring floss = GetModuleDir() + cfg::FLOSS_REL_PATH;
        if (!fs::exists(floss)) return "\x01NOTOOL";   /* sentinel: phân biệt "không có tool" vs "không thấy gì" */

        std::wstring cmd = L"\"" + floss + L"\" --only stack tight decoded -- \"" + filePath + L"\"";
        return ToLowerA(ExecuteAndCapture(cmd, cfg::FLOSS_TIMEOUT_MS));
    }

    /* ======================================================================
       ĐIỂM VÀO — chạy HOÀN TOÀN ngoài mutex
       ======================================================================
       Chiến lược: NATIVE trước (rẻ, ~ms), EXTERNAL sau (đắt, giây)
       và CHỈ khi native miss. Native và external bù nhau:
         - Native entropy/section: bắt packer LẠ mà DIE chưa biết
         - DIE: bắt packer ĐÃ BIẾT chính xác hơn (database lớn)
         - FLOSS: bóc chuỗi stack — native không làm được
       ====================================================================== */
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

        /* ==================================================================
           EXTERNAL: chậm (DIE 5s + FLOSS 20s) — CHỈ chạy khi ĐÃ có nghi ngờ
           ==================================================================
           LỖI ĐÃ SỬA (máy lag): bản cũ chạy DIE/FLOSS cho MỌI file, kể cả
           svchost.exe/RuntimeBroker.exe của Microsoft. Windows đẻ hàng chục
           tiến trình mỗi phút -> hàng chục DIE/FLOSS song song.
           Trên ARM64 hai tool này là binary x64 chạy qua emulation -> càng chậm
           -> timeout liên tục (thấy rõ trong log).

           File có chữ ký hợp lệ và không có dấu hiệu nào -> bỏ qua external.
           ================================================================== */
        bool suspicious = r.unsignedImage || r.packed || r.cryptoApi || r.suspStrings;

        if (!suspicious) {
            LOG_I("[STATIC] %s -> sach (co chu ky, khong dau hieu) — bo qua DIE/FLOSS [%llums]",
                ws2s(GetFileNameOnly(path)).c_str(), GetTickCount64() - t0);
            return r;
        }

        /* --- F2: DIE chỉ khi native miss VÀ đã nghi ngờ --- */
        if (!r.packed) {
            int die = RunDIE(path);
            if (die == 1)       r.packed = true;
            else if (die == -1) LOG_D("      (khong co diec.exe — chi dung native)");
        }

        /* --- F3: FLOSS chỉ khi quét thô miss VÀ đã nghi ngờ --- */
        if (!r.suspStrings) {
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