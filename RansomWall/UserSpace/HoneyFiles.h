/*
 * HoneyFiles.h — Bẫy (F4).
 *
 * Honey file dùng FILE_ATTRIBUTE_HIDDEN để giảm khả năng người dùng thật vô
 * tình mở/sửa chúng. Đánh đổi đã biết (ghi nhận từ log thực nghiệm với mẫu
 * Chaos): một số họ ransomware bỏ qua file hidden/system khi enumerate mục
 * tiêu, nên F4 có thể không bắn với các họ đó — hệ thống vẫn phát hiện được
 * qua F9–F14 (hành vi duyệt/ghi/mã hoá hàng loạt), chỉ chậm hơn honey trap.
 * Tên vẫn bắt đầu bằng '!'/'_' thay vì '$' (trông như metadata NTFS,
 * $MFT/$Recycle.Bin, dễ bị bỏ qua) để không cộng thêm lý do bị lọc.
 * Chống dương tính giả dựa vào HONEY_WHITELIST (Config.h).
 */
#pragma once

#include "Util.h"
#include "Config.h"
#include <set>

namespace rw {

    class HoneyFiles {
    public:
        void Create() {
            std::vector<std::wstring> dirs;
            for (auto& d : { Desktop(), Downloads(), Documents(), Pictures(),
                             GetKnownFolder(FOLDERID_Music), GetKnownFolder(FOLDERID_Videos) })
                if (!d.empty()) dirs.push_back(d);

            std::wstring docs = Documents(), dl = Downloads();
            if (!docs.empty()) {
                for (auto sub : { L"\\Work", L"\\Finance", L"\\Personal" }) {
                    std::wstring p = docs + sub;
                    std::error_code ec; fs::create_directories(p, ec);
                    dirs.push_back(p);
                }
            }
            if (!dl.empty()) {
                std::wstring p = dl + L"\\Archives";
                std::error_code ec; fs::create_directories(p, ec);
                dirs.push_back(p);
            }

            /*
             * Tên bắt đầu bằng '!'/'_' và cả tên file bình thường: ransomware
             * duyệt thư mục theo thứ tự nào cũng chạm honey sớm.
             */
            const std::pair<const wchar_t*, const char*> files[] = {
                { L"\\!!_Important_Passwords.txt",  "Username: admin\nPassword: P@ssw0rd123\nBank PIN: 4471\n" },
                { L"\\!!_crypto_wallet_seed.txt",   "abandon ability able about above absent absorb abstract\n" },
                { L"\\_backup_keys.txt",            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET=wJalrXUtnFEMI\n" },
                { L"\\Financial_Report_2025.xlsx",  "FINANCIAL DATA 2025 Q1-Q4 CONFIDENTIAL REVENUE 4.2M" },
                { L"\\backup_database.sql",         "-- MySQL dump 10.13\nCREATE TABLE users (id INT, email VARCHAR(255));" },
                { L"\\salary_list_2026.docx",       "Employee Salary Confidential Document 2026" },
                { L"\\company_secrets.pdf",         "%PDF-1.4\nConfidential internal strategy document" },
                { L"\\tax_return_2025.pdf",         "%PDF-1.4\nTax return filing document" },
                { L"\\customer_data_export.csv",    "id,name,email,phone\n1,John Doe,john@test.com,555-0100" },
                { L"\\zz_archive_backup.zip",       "PK\x03\x04 archive placeholder content" },
                { L"\\zz_family_photos.jpg",        "\xFF\xD8\xFF\xE0 JFIF placeholder" },
            };

            for (const auto& dir : dirs) {
                for (const auto& [name, content] : files) {
                    std::wstring full = dir + name;

                    /* Hidden để tránh người dùng thật vô tình chạm vào —
                       xem đánh đổi ở đầu file. */
                    HANDLE h = CreateFileW(full.c_str(), GENERIC_WRITE, 0, nullptr,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
                    if (h == INVALID_HANDLE_VALUE) continue;
                    DWORD w = 0;
                    WriteFile(h, content, (DWORD)strlen(content), &w, nullptr);
                    CloseHandle(h);

                    /* Đẩy lùi CreationTime để honey không trông như file vừa tạo */
                    BackdateFile(full);
                    list_.insert(ToLower(full));
                }
            }
            LOG_I("[HONEY] Da tao %zu honey file (hidden) trong %zu thu muc.",
                list_.size(), dirs.size());
        }

        bool IsHoney(const std::wstring& path) const {
            return list_.count(ToLower(path)) > 0;
        }

        /* Tiến trình hệ thống (explorer, SearchIndexer, MsMpEng...) chạm
           honey file thì không bị tính điểm — chống dương tính giả. */
        static bool IsWhitelisted(DWORD pid) {
            std::wstring n = GetProcessName(pid);
            return cfg::HONEY_WHITELIST.count(n) > 0;
        }

        size_t Count() const { return list_.size(); }

    private:
        std::set<std::wstring> list_;

        static void BackdateFile(const std::wstring& path) {
            HANDLE h = CreateFileW(path.c_str(), FILE_WRITE_ATTRIBUTES, 0, nullptr,
                OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            if (h == INVALID_HANDLE_VALUE) return;
            SYSTEMTIME st{}; GetSystemTime(&st);
            st.wYear -= 2;
            FILETIME ft{};
            if (SystemTimeToFileTime(&st, &ft))
                SetFileTime(h, &ft, &ft, &ft);
            CloseHandle(h);
        }
    };

} // namespace rw