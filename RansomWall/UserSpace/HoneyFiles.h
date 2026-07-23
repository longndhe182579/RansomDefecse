/*
 * HoneyFiles.h — Bẫy (F4).  v4.3
 *
 * ===========================================================================
 * BẢN VÁ v4.3 — BỎ FILE_ATTRIBUTE_HIDDEN
 * ===========================================================================
 *   [FIX 9] F4 KHÔNG BAO GIỜ BẮN.
 *
 *           Log thực tế: 100 honey file được tạo, Chaos duyệt qua đúng
 *           Documents\Finance, Documents\Work, Downloads\Archives (có
 *           LEIA-ME.txt ở cả ba), mà honey_modified vẫn = 0.
 *
 *           Nguyên nhân: v4.0 thêm FILE_ATTRIBUTE_HIDDEN để chống dương tính
 *           giả. Nhưng RẤT NHIỀU họ ransomware lọc bỏ file hidden/system khi
 *           enumerate — chúng coi đó là file hệ thống, không đáng mã hoá.
 *           Kết quả: đánh đổi mất luôn feature NHANH NHẤT của cả hệ thống.
 *
 *           Chi phí của việc mất F4 (đo từ log):
 *             21:38:26  ransomware bat dau
 *             21:38:29  score 5  (F9 + F10)
 *             ...43 giay dung yen...
 *             21:39:12  score 6  (F7 — ransomware XOA shadow SAU khi ma hoa)
 *             -> kill MUON 46 giay, file da mat het
 *
 *           Với F4 hoạt động, score chạm 6 ngay giây đầu tiên.
 *
 *           Chống dương tính giả giờ CHỈ dựa vào HONEY_WHITELIST — và whitelist
 *           đang làm tốt việc đó: không có một FP honey nào trong toàn bộ log.
 *
 *   [FIX 9b] Bỏ tên bắt đầu bằng '$'. Ký tự '$' khiến file trông như metadata
 *            NTFS ($MFT, $Recycle.Bin) — thêm một lý do nữa để ransomware bỏ qua.
 *            Đổi sang '!' và '_': vẫn đứng đầu danh sách sắp xếp, nhưng trông
 *            như file người dùng bình thường.
 * ===========================================================================
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
             * [FIX 9b] Tên bắt đầu bằng '!' hoặc '_' và có cả tên bình thường:
             * ransomware duyệt thư mục theo thứ tự nào cũng chạm honey sớm.
             *
             * KHÔNG dùng '$' — trông như metadata NTFS ($MFT, $Recycle.Bin),
             * ransomware bỏ qua.
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

                    /*
                     * [FIX 9] FILE_ATTRIBUTE_NORMAL, KHÔNG PHẢI HIDDEN.
                     *
                     * Honey file PHẢI trông y hệt file thật thì ransomware mới
                     * chạm vào. Hidden = vô hình với chính kẻ ta muốn bẫy.
                     *
                     * Chống FP: HONEY_WHITELIST trong Config.h (explorer,
                     * SearchIndexer, MsMpEng...). Đó mới là hàng rào đúng chỗ.
                     */
                    HANDLE h = CreateFileW(full.c_str(), GENERIC_WRITE, 0, nullptr,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                    if (h == INVALID_HANDLE_VALUE) continue;
                    DWORD w = 0;
                    WriteFile(h, content, (DWORD)strlen(content), &w, nullptr);
                    CloseHandle(h);

                    /* Đẩy lùi CreationTime để honey không trông như file vừa tạo */
                    BackdateFile(full);
                    list_.insert(ToLower(full));
                }
            }
            LOG_I("[HONEY] Da tao %zu honey file trong %zu thu muc (KHONG hidden — "
                "de ransomware nhin thay).", list_.size(), dirs.size());
        }

        bool IsHoney(const std::wstring& path) const {
            return list_.count(ToLower(path)) > 0;
        }

        /*
         * Whitelist — tiến trình hệ thống chạm honey file KHÔNG bị tính điểm.
         *
         * ĐÂY là hàng rào chống dương tính giả DUY NHẤT kể từ v4.3 (không còn
         * dựa vào HIDDEN nữa). Log cho thấy nó làm tốt: không có FP honey nào.
         *
         * Nếu sau khi bỏ HIDDEN mà thấy FP, hãy THÊM tiến trình vào
         * cfg::HONEY_WHITELIST — ĐỪNG bật lại HIDDEN.
         */
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