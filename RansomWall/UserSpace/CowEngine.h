/*
 * CowEngine.h — Copy-on-Write engine.
 *
 * NGUYÊN LÝ 1: Backup từ file ĐẦU TIÊN bị chạm. Không chờ điểm, không chờ ML.
 * NGUYÊN LÝ 2: CoW không có nhánh nào đi xuống ML. Nó backup rồi KẾT THÚC.
 *
 * Khi GetFileAttributesExW trả về ERROR_FILE_NOT_FOUND lúc pend, không được
 * vội kết luận "file chưa tồn tại, không có gì để cứu": trên máy test luôn
 * được revert về snapshot sạch trước mỗi lần chạy, nên có trường hợp file
 * (ví dụ các file .7z/.zip/.csv/.db/.obj trong Downloads, Documents, Desktop)
 * ĐANG TỒN TẠI lúc ta pend nhưng getattr vẫn báo không thấy — đúng những file
 * này là file đã bị mã hoá, tức là một lỗ hổng thật khiến backup bị bỏ lọt.
 * Tương quan quan sát được: cùng một file, ở disposition=OVERWRITE_IF thì
 * backup thành công, còn ở disposition=CREATE thì getattr báo not-found —
 * cho thấy lỗi nằm ở phía xử lý đường dẫn/timing, không phải file thực sự
 * biến mất.
 *
 * Vì vậy khi gặp err=2, CoW chạy thêm PROBE (xem ProbeMissingFile) với ba
 * phép thử độc lập để xác nhận file có thật hay getattr chỉ báo sai:
 *   altPrefix : thử lại với \\?\  -> đường dẫn dài / ký tự lạ
 *   findFirst : FindFirstFileW    -> file có thật không
 *   rawLen    : độ dài chuỗi      -> có ký tự rác ở cuối không
 * Bảng đọc log [PROBE] để quyết định hướng sửa nằm ở cuối file.
 *
 * CopyFileShared thay hoàn toàn CopyFileW vì CopyFileW dùng share mode hạn
 * chế nên hay lỗi err=32 (sharing violation) khi tiến trình khác đang giữ
 * file mở; CopyFileSharedRetry retry thêm khi gặp khoá tạm thời; kích thước
 * backup tối đa được chia hai bậc theo điểm nghi ngờ của tiến trình.
 */
#pragma once

#include "Util.h"
#include "Config.h"
#include "Features.h"
#include <mutex>

namespace rw {

    /* ---- BAIL: LỖI THẬT — có dữ liệu bị đe doạ mà không cứu được ---- */
#define COW_BAIL(r) do { LOG_W("[COW-BAIL] %-16s %s", r, \
        ws2s(filePath).c_str()); return false; } while(0)

    /* ---- SKIP: KHÔNG PHẢI LỖI — không có gì để cứu ---- */
#define COW_SKIP(r) do { LOG_D("[COW-SKIP] %-16s %s", r, \
        ws2s(filePath).c_str()); return true;  } while(0)

    /* NT CREATE DISPOSITION — phân biệt "file mới" với "file phải tồn tại".
       Driver gửi lên qua RW_EVENT.DirEntryCount (mượn field). */
    enum : DWORD {
        RW_DISP_SUPERSEDE = 0,   /* thay thế — file có thể đã tồn tại */
        RW_DISP_OPEN = 1,   /* PHẢI tồn tại */
        RW_DISP_CREATE = 2,   /* PHẢI chưa tồn tại */
        RW_DISP_OPEN_IF = 3,   /* mở, không có thì tạo */
        RW_DISP_OVERWRITE = 4,   /* PHẢI tồn tại */
        RW_DISP_OVERWRITE_IF = 5,   /* ghi đè, không có thì tạo */
        RW_DISP_UNKNOWN = 0xFFFFFFFF,
    };

    /* Disposition này ngụ ý file ĐANG TỒN TẠI -> err=2 là ĐÁNG NGỜ */
    inline bool DispImpliesExisting(DWORD disp) {
        return disp == RW_DISP_OPEN || disp == RW_DISP_OVERWRITE ||
            disp == RW_DISP_OPEN_IF || disp == RW_DISP_SUPERSEDE;
    }

    inline const char* DispName(DWORD d) {
        switch (d) {
        case RW_DISP_SUPERSEDE:    return "SUPERSEDE";
        case RW_DISP_OPEN:         return "OPEN";
        case RW_DISP_CREATE:       return "CREATE";
        case RW_DISP_OPEN_IF:      return "OPEN_IF";
        case RW_DISP_OVERWRITE:    return "OVERWRITE";
        case RW_DISP_OVERWRITE_IF: return "OVERWRITE_IF";
        }
        return "?";
    }

    /* ---- Disk budget ---- */
    struct DiskBudget {
        uint64_t freeBytes = 0;
        uint64_t capacityBytes = 0;
        uint64_t reserveBytes = 0;
        uint64_t budgetBytes = 0;
        bool     belowReserve = false;

        static DiskBudget Measure(const std::wstring& root = L"C:\\") {
            DiskBudget d;
            ULARGE_INTEGER avail{}, total{}, freeTotal{};
            if (!GetDiskFreeSpaceExW(root.c_str(), &avail, &total, &freeTotal)) return d;

            d.freeBytes = avail.QuadPart;
            d.capacityBytes = total.QuadPart;
            d.reserveBytes = (std::max)(cfg::RESERVE_MIN_BYTES,
                (uint64_t)(d.capacityBytes * cfg::RESERVE_PCT_CAPACITY));

            if (d.freeBytes <= d.reserveBytes) {
                d.belowReserve = true;
                d.budgetBytes = 0;
            }
            else {
                d.budgetBytes = (uint64_t)((d.freeBytes - d.reserveBytes) * cfg::BUDGET_PCT_OF_FREE);
            }
            return d;
        }
    };

    /* ---- Copy với share mode đầy đủ, thay hoàn toàn CopyFileW ---- */
    inline bool CopyFileShared(const std::wstring& src, const std::wstring& dst,
        DWORD* lastErr = nullptr) {
        HANDLE hSrc = CreateFileW(
            src.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (hSrc == INVALID_HANDLE_VALUE) {
            if (lastErr) *lastErr = GetLastError();
            return false;
        }

        HANDLE hDst = CreateFileW(
            dst.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hDst == INVALID_HANDLE_VALUE) {
            if (lastErr) *lastErr = GetLastError();
            CloseHandle(hSrc);
            return false;
        }

        std::vector<uint8_t> buf(1 << 20);
        bool ok = true;
        for (;;) {
            DWORD got = 0;
            if (!ReadFile(hSrc, buf.data(), (DWORD)buf.size(), &got, nullptr)) {
                if (lastErr) *lastErr = GetLastError();
                ok = false; break;
            }
            if (got == 0) break;
            DWORD off = 0;
            while (off < got) {
                DWORD wrote = 0;
                if (!WriteFile(hDst, buf.data() + off, got - off, &wrote, nullptr) || wrote == 0) {
                    if (lastErr) *lastErr = GetLastError();
                    ok = false; break;
                }
                off += wrote;
            }
            if (!ok) break;
        }

        CloseHandle(hSrc);
        CloseHandle(hDst);
        if (!ok) { std::error_code ec; fs::remove(dst, ec); }   /* xoá bản dở */
        return ok;
    }

    /* CopyFileSharedRetry — vượt qua khoá tạm thời. Ngân sách thời gian:
       driver timeout 200ms, ở đây dùng tối đa 3 lần x 30ms = 90ms. */
    inline bool CopyFileSharedRetry(const std::wstring& src, const std::wstring& dst,
        DWORD* lastErr = nullptr) {
        DWORD err = 0;
        for (int attempt = 0; attempt < cfg::COW_COPY_RETRY_COUNT; attempt++) {
            if (CopyFileShared(src, dst, &err)) {
                if (lastErr) *lastErr = 0;
                return true;
            }
            if (err != ERROR_SHARING_VIOLATION && err != ERROR_LOCK_VIOLATION)
                break;

            std::error_code ec; fs::remove(dst, ec);
            Sleep(cfg::COW_COPY_RETRY_SLEEP_MS);
        }
        if (lastErr) *lastErr = err;
        return false;
    }

    /* PROBE — chẩn đoán khi getattr trả err=2. Ba phép thử độc lập, chỉ chạy
       khi đã gặp err=2 (hiếm) nên không ảnh hưởng đường nóng của file bình
       thường. Trả về true nếu một trong các cách thay thế TÌM THẤY file —
       nghĩa là file CÓ THẬT và lỗi nằm ở phía ta (đường dẫn), không phải ở
       đĩa. */
    struct ProbeResult {
        bool altPrefixOk = false;   /* \\?\ prefix mở được */
        bool findFirstOk = false;   /* FindFirstFileW thấy */
        bool shortPathOk = false;   /* GetShortPathName thành công */
        size_t rawLen = 0;
        std::wstring altPath;
    };

    inline ProbeResult ProbeMissingFile(const std::wstring& path) {
        ProbeResult r;
        r.rawLen = path.size();

        /* 1. Thử lại với \\?\ — vượt giới hạn MAX_PATH và tắt path normalization */
        if (path.size() > 2 && path[1] == L':') {
            r.altPath = L"\\\\?\\" + path;
            WIN32_FILE_ATTRIBUTE_DATA f2{};
            r.altPrefixOk = GetFileAttributesExW(r.altPath.c_str(),
                GetFileExInfoStandard, &f2) != 0;
        }

        /* 2. FindFirstFileW — đi qua đường khác trong kernel, khoan dung hơn */
        WIN32_FIND_DATAW fd{};
        HANDLE hf = FindFirstFileW(path.c_str(), &fd);
        if (hf != INVALID_HANDLE_VALUE) { r.findFirstOk = true; FindClose(hf); }

        /* 3. GetShortPathName — chỉ thành công nếu file tồn tại */
        wchar_t shortBuf[MAX_PATH]{};
        r.shortPathOk = GetShortPathNameW(path.c_str(), shortBuf, MAX_PATH) != 0;

        return r;
    }

    /* ---- Quota động ---- */
    inline uint64_t QuotaFor(QuotaTier tier, const DiskBudget& b) {
        switch (tier) {
        case QuotaTier::T0_Clean:
            return (std::min)(cfg::TIER0_CAP, (uint64_t)(b.budgetBytes * cfg::TIER0_PCT));
        case QuotaTier::T1_Suspect:
            return (std::min)(cfg::TIER1_CAP, (uint64_t)(b.budgetBytes * cfg::TIER1_PCT));
        case QuotaTier::T2_Danger:
            return (std::min)(cfg::TIER2_CAP, (uint64_t)(b.budgetBytes * cfg::TIER2_PCT));
        case QuotaTier::T3_Critical:
            return (uint64_t)(b.budgetBytes * cfg::TIER3_PCT);
        }
        return 0;
    }

    /* V(f) = 3*A + 2*P + 2*R - 4*J     (mục 4.1.4) */
    struct ValueScorer {
        static double Age(const std::wstring& path) {
            WIN32_FILE_ATTRIBUTE_DATA fad{};
            if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) return 0.4;

            ULARGE_INTEGER ct{}; ct.LowPart = fad.ftCreationTime.dwLowDateTime;
            ct.HighPart = fad.ftCreationTime.dwHighDateTime;
            FILETIME nowFt{}; GetSystemTimeAsFileTime(&nowFt);
            ULARGE_INTEGER now{}; now.LowPart = nowFt.dwLowDateTime; now.HighPart = nowFt.dwHighDateTime;

            if (now.QuadPart <= ct.QuadPart) return 0.1;
            double days = (double)(now.QuadPart - ct.QuadPart) / (10000000.0 * 86400.0);

            if (days > 30) return 1.0;
            if (days > 7)  return 0.7;
            if (days > 1)  return 0.4;
            return 0.1;
        }

        static double Provenance(const std::wstring& path) {
            std::wstring p = ToLower(path);
            auto has = [&](const std::wstring& d) {
                return !d.empty() && p.rfind(ToLower(d), 0) == 0;
                };
            if (has(Documents()) || has(Desktop()) || has(Pictures())) return 1.0;
            if (has(Downloads())) return 0.6;
            if (p.find(L"\\temp\\") != std::wstring::npos ||
                p.find(L"\\appdata\\") != std::wstring::npos ||
                p.find(L"\\windows\\") != std::wstring::npos) return 0.2;
            return 0.5;
        }

        static double Recent(const std::wstring& path) {
            WIN32_FILE_ATTRIBUTE_DATA fad{};
            if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) return 0.3;
            ULARGE_INTEGER at{}, ct{};
            at.LowPart = fad.ftLastAccessTime.dwLowDateTime; at.HighPart = fad.ftLastAccessTime.dwHighDateTime;
            ct.LowPart = fad.ftCreationTime.dwLowDateTime;  ct.HighPart = fad.ftCreationTime.dwHighDateTime;
            if (at.QuadPart <= ct.QuadPart) return 0.3;
            double hours = (double)(at.QuadPart - ct.QuadPart) / (10000000.0 * 3600.0);
            return hours > 1.0 ? 1.0 : 0.3;
        }

        static double Junk(const std::wstring& path, DWORD creatorPid, DWORD watchedPid) {
            if (creatorPid != 0 && creatorPid == watchedPid) return 1.0;

            std::wstring name = GetFileNameOnly(path);
            size_t dot = name.find_last_of(L'.');
            std::wstring stem = (dot == std::wstring::npos) ? name : name.substr(0, dot);
            if (stem.empty()) return 0.0;

            std::vector<uint8_t> bytes;
            for (wchar_t c : stem) bytes.push_back((uint8_t)(c & 0xFF));
            double h = CalculateEntropy(bytes.data(), bytes.size());

            int vowels = 0;
            for (wchar_t c : ToLower(stem))
                if (c == L'a' || c == L'e' || c == L'i' || c == L'o' || c == L'u') vowels++;
            double vowelRatio = (double)vowels / (double)stem.size();

            if (h > 3.2 && vowelRatio < 0.15 && stem.size() >= 6) return 1.0;
            return 0.0;
        }

        static double Score(const std::wstring& path, DWORD creatorPid, DWORD watchedPid) {
            return cfg::W_AGE * Age(path)
                + cfg::W_PROVENANCE * Provenance(path)
                + cfg::W_RECENT * Recent(path)
                - cfg::W_JUNK * Junk(path, creatorPid, watchedPid);
        }
    };

    /* ---- CoW Engine ---- */
    class CowEngine {
    public:
        explicit CowEngine(std::mutex& collectorMutex,
            std::map<DWORD, ProcessFeature>& collector)
            : mtx_(collectorMutex), coll_(collector) {
            fs::create_directories(cfg::BACKUP_ROOT);
            fs::create_directories(cfg::QUARANTINE_ROOT);
            fs::create_directories(cfg::RESTORED_ROOT);
            budget_ = DiskBudget::Measure();
            LogBudget();
        }

        void RefreshBudget() {
            budget_ = DiskBudget::Measure();
            LogBudget();
        }
        const DiskBudget& Budget() const { return budget_; }
        bool BelowReserve() const { return budget_.belowReserve; }

        /* Đếm số lần getattr err=2 mà PROBE khẳng định file CÓ THẬT */
        uint64_t GhostMissCount() const { return ghostMiss_.load(); }

        /* OnFirstTouch — điểm vào chính. Gọi khi driver pend IRP.

           disposition: NT create disposition từ driver (RW_EVENT.DirEntryCount).
                        Dùng để phân biệt "file mới hợp lệ" với "file đáng lẽ
                        phải tồn tại". RW_DISP_UNKNOWN nếu không có.

           Trả về true nếu không có gì đang bị đe doạ (đã backup, hoặc không
           có gì để cứu); false nếu có dữ liệu bị đe doạ mà không cứu được
           -> người gọi phải xử lý. */
        bool OnFirstTouch(DWORD pid, const std::wstring& filePath,
            DWORD rootPid = 0, DWORD disposition = RW_DISP_UNKNOWN) {
            /* Không log [COW-IN] riêng ở đây vì trùng thông tin với
               [COW-PEND] ở main.cpp (cùng pid, cùng disp, cùng tên file) —
               mỗi file pend chỉ nên tạo một dòng log. */

            if (budget_.belowReserve) COW_BAIL("below_reserve");
            if (filePath.empty())     return true;

            /* ---- Điều kiện backup: không phải lỗi, chỉ là ngoài phạm vi ---- */
            std::wstring ext = GetExtension(filePath);
            if (cfg::EXECUTABLE_EXTS.count(ext)) COW_SKIP("exe_ext");
            if (!cfg::VALUABLE_EXTS.count(ext))  COW_SKIP("not_valuable");

            WIN32_FILE_ATTRIBUTE_DATA fad{};
            if (!GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &fad)) {
                DWORD e = GetLastError();

                if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) {
                    /* Không kết luận vội "file chưa tồn tại" — chạy PROBE
                       trước (xem giải thích ở đầu file). */
                    ProbeResult pr = ProbeMissingFile(filePath);
                    bool reallyExists = pr.altPrefixOk || pr.findFirstOk || pr.shortPathOk;

                    if (reallyExists) {
                        /* FILE CÓ THẬT mà getattr không thấy -> LỖI CỦA TA */
                        ghostMiss_++;
                        LOG_E("[PROBE] *** FILE CO THAT MA GETATTR KHONG THAY *** "
                            "err=%lu disp=%s alt=%d find=%d short=%d len=%zu",
                            e, DispName(disposition),
                            (int)pr.altPrefixOk, (int)pr.findFirstOk,
                            (int)pr.shortPathOk, pr.rawLen);
                        LOG_E("[PROBE]   path=[%s]", ws2s(filePath).c_str());
                        if (pr.altPrefixOk)
                            LOG_E("[PROBE]   -> \\\\?\\ MO DUOC: duong dan dai hoac ky tu "
                                "dac biet. Sua: luon them prefix \\\\?\\ truoc khi goi Win32.");
                        else if (pr.findFirstOk || pr.shortPathOk)
                            LOG_E("[PROBE]   -> FindFirst/ShortPath thay nhung getattr khong: "
                                "chuoi co ky tu rac. Kiem tra NormalizeKernelPath trong Util.h.");
                        return false;   /* <<< LỖI THẬT, báo cho người gọi */
                    }

                    /* Không cách nào thấy file -> đúng là chưa tồn tại.
                       disp=OPEN/OPEN_IF trên đường dẫn chưa tồn tại không
                       phải lỗi: đó là thao tác kiểm tra tồn tại hoàn toàn
                       bình thường (ransomware hay làm vậy trước khi tạo
                       ransom note). Kiểm chứng qua log Akira: toàn bộ 15
                       lần cow-fail dạng này đều là akira_readme.txt bị
                       DENY IRP vô hại, không có file nạn nhân nào trong đó.
                       Không có dữ liệu bị đe doạ -> return true. */
                    LOG_D("[COW-SKIP] %-16s disp=%s %s", "file_moi",
                        DispName(disposition), ws2s(filePath).c_str());
                    return true;
                }

                LOG_W("[COW-BAIL] %-16s err=%lu %s", "getattr_fail", e,
                    ws2s(filePath).c_str());
                return false;
            }
            if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) COW_SKIP("is_directory");

            uint64_t size = ((uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
            if (size == 0) COW_SKIP("size_zero");

            /* ---- Lấy thông tin tiến trình (dưới lock, nhanh) ---- */
            uint64_t startTime;
            int      score;
            bool     frozen;
            uint64_t used, limit;
            {
                bool dup = false;
                std::lock_guard<std::mutex> lk(mtx_);
                auto& pf = coll_[pid];
                if (pf.pid == 0) { pf.pid = pid; pf.startTime = GetProcessStartTime(pid); }
                startTime = pf.startTime;
                score = pf.totalScore;
                frozen = pf.backupFrozen;
                used = pf.quotaUsed;

                pf.quotaTier = TierOf(score);
                pf.quotaLimit = QuotaFor(pf.quotaTier, budget_);
                limit = pf.quotaLimit;

                for (auto& e : pf.entries)
                    if (ToLower(e.originalPath) == ToLower(filePath)) { dup = true; break; }
                if (dup) COW_SKIP("da_backup_roi");
            }

            /* ---- Trần kích thước theo BẬC ---- */
            uint64_t sizeCap = (score >= cfg::SCORE_FREEZE)
                ? cfg::MAX_BACKUP_FILE_SIZE
                : cfg::MAX_BACKUP_FILE_SIZE_CLEAN;
            if (size > sizeCap) {
                LOG_W("[COW-BAIL] %-16s %llu MB > %llu MB (score=%d) %s", "size_too_big",
                    size / 1048576, sizeCap / 1048576, score, ws2s(filePath).c_str());
                return false;
            }

            /* ---- Quota đầy? ---- */
            if (used + size > limit) {
                if (score >= cfg::SCORE_FREEZE) {
                    if (!frozen) {
                        std::lock_guard<std::mutex> lk(mtx_);
                        coll_[pid].backupFrozen = true;
                        LOG_W("[COW] DONG BANG backup PID=%lu (score=%d) — khong xoa gi nua.",
                            pid, score);
                    }
                    COW_BAIL("quota_frozen");
                }
                if (!EvictByValue(pid, size)) COW_BAIL("evict_that_bai");
            }

            /* ---- Copy byte gốc ngay lập tức ---- */
            BackupEntry entry;
            entry.originalPath = filePath;
            entry.sizeBytes = size;
            entry.backedUpAtUnix = UnixNow();
            entry.valueScore = ValueScorer::Score(filePath, 0, pid);

            std::wstring dir = ProcDir(pid, startTime);
            std::error_code ec;
            fs::create_directories(dir, ec);

            entry.backupName = std::to_wstring(GetTickCount64()) + L"_" + GetFileNameOnly(filePath);
            std::wstring dest = dir + L"\\" + entry.backupName;

            DWORD cerr = 0;
            if (!CopyFileSharedRetry(filePath, dest, &cerr)) {
                std::error_code ec2; fs::remove(dest, ec2);

                if (cerr == ERROR_FILE_NOT_FOUND || cerr == ERROR_PATH_NOT_FOUND) {
                    LOG_W("[COW] File bien mat GIUA getattr va copy: %s",
                        ws2s(filePath).c_str());
                    return false;
                }
                if (cerr == ERROR_SHARING_VIOLATION || cerr == ERROR_LOCK_VIOLATION) {
                    LOG_E("[COW] BACKUP FAIL err=%lu (SHARING VIOLATION) — tien trinh dang "
                        "giu file DENY-ALL. KHONG CO BAN SAO: %s",
                        cerr, ws2s(filePath).c_str());
                }
                else {
                    LOG_W("[COW] Backup that bai (err=%lu): %s",
                        cerr, ws2s(filePath).c_str());
                }
                return false;
            }

            /* Phân tích TRÊN BẢN SAO */
            entry.entropyBefore = FileEntropy(dest, cfg::ENTROPY_SAMPLE_BYTES);
            entry.magicBefore = FileMagicHex(dest);
            entry.sha256Before = Sha256File(dest);

            /* Dedup SAU khi có hash */
            if (!entry.sha256Before.empty()) {
                std::lock_guard<std::mutex> lk(dedupMtx_);
                auto it = dedupIndex_.find(entry.sha256Before);
                if (it != dedupIndex_.end() && fs::exists(it->second) && it->second != dest) {
                    std::error_code ec2;
                    fs::remove(dest, ec2);
                    if (!CreateHardLinkW(dest.c_str(), it->second.c_str(), nullptr)) {
                        DWORD e2 = 0;
                        if (!CopyFileSharedRetry(filePath, dest, &e2)) {
                            LOG_E("[COW] Hardlink fail VA copy lai fail (err=%lu): %s",
                                e2, ws2s(filePath).c_str());
                            return false;
                        }
                    }
                    else {
                        entry.dedupLink = true;
                    }
                }
                else {
                    dedupIndex_[entry.sha256Before] = dest;
                }
            }

            {
                std::lock_guard<std::mutex> lk(mtx_);
                auto& pf = coll_[pid];
                pf.entries.push_back(entry);
                if (!entry.dedupLink) pf.quotaUsed += size;
                pf.manifestDirty = true;

                if (rootPid != 0 && rootPid != pid) {
                    auto& rootPf = coll_[rootPid];
                    if (rootPf.pid == 0) {
                        rootPf.pid = rootPid;
                        rootPf.startTime = GetProcessStartTime(rootPid);
                    }
                    bool alreadyInRoot = false;
                    for (auto& re : rootPf.entries)
                        if (ToLower(re.originalPath) == ToLower(filePath)) {
                            alreadyInRoot = true; break;
                        }
                    if (!alreadyInRoot) {
                        BackupEntry rootEntry = entry;
                        rootEntry.backupName = dest;   /* full path — RestoreFiles dùng trực tiếp */
                        rootPf.entries.push_back(rootEntry);
                        rootPf.manifestDirty = true;
                    }
                }
            }

            LOG_D("[COW] Backup %s%s  V=%.1f  %s",
                entry.dedupLink ? "(dedup) " : "",
                ws2s(GetFileNameOnly(filePath)).c_str(),
                entry.valueScore,
                ws2s(TierLabel(score)).c_str());
            return true;
        }

        /* LRU theo giá trị — chỉ chạy khi score <= 1 */
        bool EvictByValue(DWORD pid, uint64_t needBytes) {
            std::lock_guard<std::mutex> lk(mtx_);
            auto& pf = coll_[pid];
            if (pf.entries.empty()) return false;

            std::vector<size_t> idx(pf.entries.size());
            for (size_t i = 0; i < idx.size(); i++) idx[i] = i;
            std::sort(idx.begin(), idx.end(), [&](size_t a, size_t b) {
                return pf.entries[a].valueScore < pf.entries[b].valueScore;
                });

            uint64_t freed = 0;
            std::vector<size_t> toRemove;
            for (size_t i : idx) {
                if (pf.entries[i].valueScore > cfg::V_PROTECT_THRESHOLD) break;
                std::error_code ec;
                fs::remove(ProcDir(pid, pf.startTime) + L"\\" + pf.entries[i].backupName, ec);
                freed += pf.entries[i].sizeBytes;
                toRemove.push_back(i);
                if (freed >= needBytes) break;
            }
            if (freed < needBytes) {
                LOG_W("[COW] Khong evict du cho PID=%lu — moi file con lai deu gia tri cao. "
                    "NGUNG backup thay vi xoa.", pid);
                return false;
            }
            std::sort(toRemove.rbegin(), toRemove.rend());
            for (size_t i : toRemove) pf.entries.erase(pf.entries.begin() + i);
            pf.quotaUsed = (pf.quotaUsed > freed) ? pf.quotaUsed - freed : 0;
            pf.manifestDirty = true;
            LOG_I("[COW] LRU-value: evict %zu file rac, giai phong %llu KB (PID=%lu)",
                toRemove.size(), freed / 1024, pid);
            return true;
        }

        static std::wstring ProcDir(DWORD pid, uint64_t startTime) {
            return cfg::BACKUP_ROOT + L"\\" + MakeProcKey(pid, startTime);
        }

        std::string BuildManifestJson(ProcessFeature& pf) {
            JsonW j;
            j.Begin()
                .UInt("pid", pf.pid)
                .UInt("root_pid", pf.rootPid)
                .UInt("start_time", pf.startTime)
                .Str("process_image", pf.processImage)
                .Str("image_sha256", pf.imageSha256)
                .Int("score", pf.totalScore)
                .Str("quota_tier", TierName(pf.quotaTier))
                .UInt("quota_limit_bytes", pf.quotaLimit)
                .UInt("quota_used_bytes", pf.quotaUsed)
                .Str("session_start", IsoNow())
                .BeginArr("entries");
            for (auto& e : pf.entries) {
                j.BeginObj()
                    .Str("backup_name", e.backupName)
                    .Str("original_path", e.originalPath)
                    .Str("sha256_before", e.sha256Before)
                    .Str("magic_before", e.magicBefore)
                    .Num("entropy_before", e.entropyBefore)
                    .UInt("size_bytes", e.sizeBytes)
                    .UInt("backed_up_at", e.backedUpAtUnix)
                    .Num("value_score", e.valueScore)
                    .Bool01("dedup_link", e.dedupLink)
                    .EndObj();
            }
            j.EndArr().End();
            return j.Get();
        }

        void WriteManifest(ProcessFeature& pf) {
            pf.manifestDirty = false;
            AtomicWriteFile(ProcDir(pf.pid, pf.startTime) + L"\\manifest.json",
                BuildManifestJson(pf));
        }

        const BackupEntry* FindEntry(ProcessFeature& pf, const std::wstring& path) {
            std::wstring lp = ToLower(path);
            for (auto& e : pf.entries)
                if (ToLower(e.originalPath) == lp) return &e;
            return nullptr;
        }

        void FlushDirtyManifests() {
            struct Job { DWORD pid; std::string json; std::wstring path; };
            std::vector<Job> jobs;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                for (auto& [pid, pf] : coll_) {
                    if (!pf.manifestDirty) continue;
                    jobs.push_back({ pid, BuildManifestJson(pf),
                                     ProcDir(pf.pid, pf.startTime) + L"\\manifest.json" });
                    pf.manifestDirty = false;
                }
            }
            for (auto& j : jobs) AtomicWriteFile(j.path, j.json);
            if (!jobs.empty()) LOG_D("[COW] Ghi gop %zu manifest.", jobs.size());
        }

    private:
        std::mutex& mtx_;
        std::map<DWORD, ProcessFeature>& coll_;
        DiskBudget  budget_;
        std::mutex  dedupMtx_;
        std::map<std::string, std::wstring> dedupIndex_;
        std::atomic<uint64_t> ghostMiss_{ 0 };

        static std::wstring TierLabel(int score) {
            return s2ws(TierName(TierOf(score)));
        }
        void LogBudget() {
            if (budget_.belowReserve) {
                LOG_E("[COW] O DIA GAN DAY! free=%llu MB < reserve=%llu MB. "
                    "CoW TAM DUNG — khong the bao ve du lieu.",
                    budget_.freeBytes / 1048576, budget_.reserveBytes / 1048576);
            }
            else {
                LOG_I("[COW] Disk: free=%llu GB  reserve=%llu GB  BUDGET=%llu GB",
                    budget_.freeBytes / 1073741824,
                    budget_.reserveBytes / 1073741824,
                    budget_.budgetBytes / 1073741824);
            }
        }
    };

    /* Đọc log [PROBE] — bảng quyết định:
         alt=1                  -> Đường dẫn dài / ký tự đặc biệt.
                                   SỬA: luôn thêm prefix \\?\ trước mọi lời gọi
                                   Win32 file API trong CoW.

         alt=0 find=1           -> Chuỗi có ký tự rác (thường là NUL hoặc khoảng
              hoặc short=1         trắng thừa ở cuối) mà FindFirstFile khoan dung
                                   hơn getattr. SỬA: NormalizeKernelPath trong
                                   Util.h — cắt đúng theo độ dài thật.

         alt=0 find=0 short=0   -> File THỰC SỰ không còn. Kèm disp=OPEN_IF
                                   nghĩa là ransomware đã rename/xoá TRƯỚC khi
                                   ta kịp pend. SỬA: bắt sớm hơn ở PreCreate,
                                   hoặc pend cả IRP_MJ_SET_INFORMATION rename
                                   ở nguồn (chưa làm).

       Không có dòng [PROBE] nào -> mọi err=2 đều là file mới thật, CoW đang
       hoạt động đúng và lỗ hổng nằm chỗ khác. */

       /* Việc còn lại:
          1. FirstTouch bị TIÊU THỤ dù backup thất bại. PreCreate gọi FtTestAndSet
             TRƯỚC khi biết user-space cứu được không -> IRP_MJ_WRITE sau đó không
             pend nữa. Cần RwReplyRetryLater để driver nhả slot.

          2. Copy user-space không vượt được share mode deny-all. Cách dứt điểm:
             FltCreateFileEx2(... IO_IGNORE_SHARE_ACCESS_CHECK ...) + FltReadFile
             trong kernel. */

} // namespace rw