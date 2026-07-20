/*
 * CowEngine.h — Copy-on-Write engine.
 *
 * NGUYÊN LÝ 1: Backup từ file ĐẦU TIÊN bị chạm. Không chờ điểm, không chờ ML.
 * NGUYÊN LÝ 2: CoW không có nhánh nào đi xuống ML. Nó backup rồi KẾT THÚC.
 *
 * Chứa:
 *   - Quota động 4 bậc theo score (mục 4.1.3)
 *   - Quy tắc ĐÓNG BĂNG ở score >= 2  <- chống đòn "ghi rác đá bay backup"
 *   - LRU theo GIÁ TRỊ V(f) (mục 4.1.4)
 *   - Dedup SHA-256 qua hard link
 *   - manifest.json (mục 4.1.5)
 */
#pragma once

#include "Util.h"
#include "Config.h"
#include "Features.h"
#include <mutex>

namespace rw {

    /* ======================================================================
       DISK BUDGET
       ====================================================================== */
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

    /* ======================================================================
       QUOTA ĐỘNG — tiến trình càng đáng ngờ, quota càng NỚI
       ====================================================================== */
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

    /* ======================================================================
       V(f) = 3*A + 2*P + 2*R - 4*J     (mục 4.1.4)
       ======================================================================
       LRU thuần theo thời gian xoá "cũ nhất" = xoá NẠN NHÂN ĐẦU TIÊN.
       Ransomware chỉ cần ghi 400MB rác là đá bay hết tài liệu thật.
       ====================================================================== */
    struct ValueScorer {
        /* A(f): tuổi file TRÊN ĐĨA, không phải tuổi backup */
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
            return 0.1;                 // < 1 ngày -> nghi là file rác
        }

        /* P(f): provenance — thư mục chứa file */
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

        /* R(f): đã từng được tiến trình khác truy cập (có trong Recent) */
        static double Recent(const std::wstring& path) {
            WIN32_FILE_ATTRIBUTE_DATA fad{};
            if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) return 0.3;
            /* Heuristic: LastAccess khác xa CreationTime => đã được mở lại */
            ULARGE_INTEGER at{}, ct{};
            at.LowPart = fad.ftLastAccessTime.dwLowDateTime; at.HighPart = fad.ftLastAccessTime.dwHighDateTime;
            ct.LowPart = fad.ftCreationTime.dwLowDateTime;  ct.HighPart = fad.ftCreationTime.dwHighDateTime;
            if (at.QuadPart <= ct.QuadPart) return 0.3;
            double hours = (double)(at.QuadPart - ct.QuadPart) / (10000000.0 * 3600.0);
            return hours > 1.0 ? 1.0 : 0.3;
        }

        /* J(f): junk penalty — dấu hiệu file rác */
        static double Junk(const std::wstring& path, DWORD creatorPid, DWORD watchedPid) {
            /* Tạo bởi chính tiến trình đang bị theo dõi trong phiên này */
            if (creatorPid != 0 && creatorPid == watchedPid) return 1.0;

            std::wstring name = GetFileNameOnly(path);
            size_t dot = name.find_last_of(L'.');
            std::wstring stem = (dot == std::wstring::npos) ? name : name.substr(0, dot);
            if (stem.empty()) return 0.0;

            /* Tên có entropy ký tự cao và không có nguyên âm -> nghi random */
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

    /* ======================================================================
       COW ENGINE
       ====================================================================== */
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

        /* ==================================================================
           OnFirstTouch — điểm vào chính. Gọi khi driver pend IRP.
           Trả về ngay sau khi copy xong. KHÔNG gọi ML. KHÔNG chờ điểm.
           rootPid: RootPid của cây tiến trình — entry sẽ được đăng ký vào
           cả coll_[pid] lẫn coll_[rootPid] để RestoreFiles tìm thấy qua RootPid.
           ================================================================== */
        bool OnFirstTouch(DWORD pid, const std::wstring& filePath,
            DWORD rootPid = 0) {
            if (budget_.belowReserve) return false;
            if (filePath.empty()) return false;

            /* ---- Điều kiện backup ---- */
            std::wstring ext = GetExtension(filePath);
            if (cfg::EXECUTABLE_EXTS.count(ext)) return false;
            if (!cfg::VALUABLE_EXTS.count(ext))  return false;

            WIN32_FILE_ATTRIBUTE_DATA fad{};
            if (!GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &fad)) return false;
            if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return false;

            uint64_t size = ((uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
            if (size == 0 || size > cfg::MAX_BACKUP_FILE_SIZE) return false;

            /* ---- Lấy thông tin tiến trình (dưới lock, nhanh) ---- */
            uint64_t startTime;
            int      score;
            bool     frozen;
            uint64_t used, limit;
            {
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

                /* Đã có backup file này rồi thì thôi */
                for (auto& e : pf.entries)
                    if (ToLower(e.originalPath) == ToLower(filePath)) return false;
            }

            /* ---- Quota đầy? ---- */
            if (used + size > limit) {
                if (score >= cfg::SCORE_FREEZE) {
                    /*
                     * ĐÓNG BĂNG. Đây là phòng tuyến quan trọng nhất.
                     * Đã nghi ngờ thì thứ đã cứu được PHẢI GIỮ.
                     * Từ chối file mới, TUYỆT ĐỐI không xoá file cũ.
                     */
                    if (!frozen) {
                        std::lock_guard<std::mutex> lk(mtx_);
                        coll_[pid].backupFrozen = true;
                        LOG_W("[COW] DONG BANG backup PID=%lu (score=%d) — khong xoa gi nua.",
                            pid, score);
                    }
                    return false;
                }
                /* score <= 1: LRU theo giá trị */
                if (!EvictByValue(pid, size)) return false;
            }

            /* ---- Chụp metadata TRƯỚC khi file bị ghi (nguồn của F12, F13) ---- */
            BackupEntry entry;
            entry.originalPath = filePath;
            entry.sizeBytes = size;
            entry.backedUpAtUnix = UnixNow();
            entry.entropyBefore = FileEntropy(filePath, cfg::ENTROPY_SAMPLE_BYTES);
            entry.magicBefore = FileMagicHex(filePath);
            entry.sha256Before = Sha256File(filePath);
            entry.valueScore = ValueScorer::Score(filePath, 0, pid);

            std::wstring dir = ProcDir(pid, startTime);
            std::error_code ec;
            fs::create_directories(dir, ec);

            entry.backupName = std::to_wstring(GetTickCount64()) + L"_" + GetFileNameOnly(filePath);
            std::wstring dest = dir + L"\\" + entry.backupName;

            /* ---- Dedup: hash trùng -> hard link, tốn 0 byte ---- */
            bool copied = false;
            if (!entry.sha256Before.empty()) {
                std::lock_guard<std::mutex> lk(dedupMtx_);
                auto it = dedupIndex_.find(entry.sha256Before);
                if (it != dedupIndex_.end() && fs::exists(it->second)) {
                    if (CreateHardLinkW(dest.c_str(), it->second.c_str(), nullptr)) {
                        entry.dedupLink = true;
                        copied = true;
                    }
                }
            }
            if (!copied) {
                copied = CopyFileW(filePath.c_str(), dest.c_str(), TRUE) != 0;
                if (copied && !entry.sha256Before.empty()) {
                    std::lock_guard<std::mutex> lk(dedupMtx_);
                    dedupIndex_[entry.sha256Before] = dest;
                }
            }
            if (!copied) {
                LOG_W("[COW] Backup that bai (err=%lu): %s", GetLastError(), ws2s(filePath).c_str());
                return false;
            }

            {
                std::lock_guard<std::mutex> lk(mtx_);
                auto& pf = coll_[pid];
                pf.entries.push_back(entry);
                if (!entry.dedupLink) pf.quotaUsed += size;
                pf.manifestDirty = true;

                /*
                 * Đăng ký entry vào RootPid để RestoreFiles(rootPid) tìm thấy.
                 * CoW backup theo pid thật (tiến trình con), nhưng kill và restore
                 * chạy trên RootPid → cần entry ở cả hai nơi.
                 */
                if (rootPid != 0 && rootPid != pid) {
                    auto& rootPf = coll_[rootPid];
                    if (rootPf.pid == 0) {
                        rootPf.pid = rootPid;
                        rootPf.startTime = GetProcessStartTime(rootPid);
                    }
                    /* Chỉ thêm nếu chưa có — tránh duplicate */
                    bool alreadyInRoot = false;
                    for (auto& re : rootPf.entries)
                        if (ToLower(re.originalPath) == ToLower(filePath))
                        {
                            alreadyInRoot = true; break;
                        }
                    if (!alreadyInRoot) {
                        BackupEntry rootEntry = entry;
                        /*
                         * File backup nằm ở ProcDir(childPid) không phải ProcDir(rootPid).
                         * RestoreFiles tính src = ProcDir(rootPid) + backupName → sai.
                         * Lưu FULL PATH vào backupName để RestoreFiles dùng trực tiếp.
                         */
                        rootEntry.backupName = dest;   /* dest = full path của file backup */
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

        /* ==================================================================
           LRU theo GIÁ TRỊ — chỉ chạy khi score <= 1
           ================================================================== */
        bool EvictByValue(DWORD pid, uint64_t needBytes) {
            std::lock_guard<std::mutex> lk(mtx_);
            auto& pf = coll_[pid];
            if (pf.entries.empty()) return false;

            /* Xếp theo V(f) TĂNG dần — file rác ra đi trước */
            std::vector<size_t> idx(pf.entries.size());
            for (size_t i = 0; i < idx.size(); i++) idx[i] = i;
            std::sort(idx.begin(), idx.end(), [&](size_t a, size_t b) {
                return pf.entries[a].valueScore < pf.entries[b].valueScore;
                });

            uint64_t freed = 0;
            std::vector<size_t> toRemove;
            for (size_t i : idx) {
                /* Mọi file còn lại đều giá trị cao -> thà NGỪNG backup còn hơn evict */
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
            pf.manifestDirty = true;   /* không ghi đĩa dưới lock */
            LOG_I("[COW] LRU-value: evict %zu file rac, giai phong %llu KB (PID=%lu)",
                toRemove.size(), freed / 1024, pid);
            return true;
        }

        /* ================================================================== */
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

        /* Ghi ngay — chỉ dùng ngoài đường nóng (cleanup, shutdown) */
        void WriteManifest(ProcessFeature& pf) {
            pf.manifestDirty = false;
            AtomicWriteFile(ProcDir(pf.pid, pf.startTime) + L"\\manifest.json",
                BuildManifestJson(pf));
        }

        /* Tìm entry backup của một file cụ thể — nguồn của F12/F13 */
        const BackupEntry* FindEntry(ProcessFeature& pf, const std::wstring& path) {
            std::wstring lp = ToLower(path);
            for (auto& e : pf.entries)
                if (ToLower(e.originalPath) == lp) return &e;
            return nullptr;
        }

        /*
         * FlushDirtyManifests — gọi từ MaintenanceThread mỗi 5 giây.
         * Ghi manifest NGOÀI đường pend, gộp nhiều entry thành một lần ghi.
         */
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
            /* Ghi đĩa NGOÀI lock — đây là chỗ tốn hàng chục ms mỗi file */
            for (auto& j : jobs) AtomicWriteFile(j.path, j.json);
            if (!jobs.empty()) LOG_D("[COW] Ghi gop %zu manifest.", jobs.size());
        }

    private:
        std::mutex& mtx_;
        std::map<DWORD, ProcessFeature>& coll_;
        DiskBudget  budget_;
        std::mutex  dedupMtx_;
        std::map<std::string, std::wstring> dedupIndex_;

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

} // namespace rw