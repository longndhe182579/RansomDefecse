/*
 * Cleanup.h — Vòng đời và dọn dẹp backup (mục 4.1.6) + Restore có điều kiện (4.4).
 *
 * Bốn cơ chế độc lập. Thiếu bất kỳ cái nào thì CoW ăn hết ổ đĩa trong vài
 * ngày, vì tiến trình sạch (Word/Photoshop/7-Zip...) score thấp không bao
 * giờ chạm ngưỡng ML nhưng vẫn tạo backup cho hàng nghìn file:
 *   (1) Early cleanup   — tiến trình ĐANG CHẠY, score <= 1
 *   (2) Exit cleanup    — tiến trình THOÁT, có grace period
 *   (3) Verdict cleanup — sau khi ML phán quyết
 *   (4) Orphan sweep    — backup mồ côi sau crash/reboot
 */
#pragma once

#include "Util.h"
#include "Config.h"
#include "Features.h"
#include "CowEngine.h"
#include <mutex>
#include <set>

namespace rw {

    enum class CleanupReason { EarlyClean, ProcessExit, BenignVerdict, MalwareVerdict, Orphan };

    /*
     * Ransom note KHÔNG nằm trong BackupEntry — nó là file MỚI (FILE_CREATE),
     * mà PreCreate trong Driver.c chủ động bỏ qua nhánh này ("không có gì để
     * cứu, cũng không có gì để bẫy"), nên hệ thống chưa từng biết đường dẫn
     * của nó để mà xoá. Nhận diện bằng TÊN FILE thay vì đuôi ransomware đã
     * biết (CleanRansomArtifacts) — ransom note luôn dùng đuôi thường
     * (.txt/.html) nên không thể phân biệt bằng đuôi.
     */
    inline bool LooksLikeRansomNote(const std::wstring& fileName) {
        std::wstring low = ToLower(fileName);
        static const std::vector<std::wstring> kMarkers = {
            L"decrypt", L"restore-my-files", L"restore_my_files", L"restore-files",
            L"how_to_decrypt", L"how-to-decrypt", L"recover-files",
            L"recovery_instructions", L"_readme", L"!!!readme!!!", L"!!read",
            L"read_it", L"read-me", L"files_encrypted", L"help_decrypt",
            L"ransom_note", L"your_files",
        };
        for (auto& m : kMarkers)
            if (low.find(m) != std::wstring::npos) return true;
        return low == L"readme.txt" || low == L"read_me.txt" || low == L"read me.txt";
    }

    inline const char* ReasonName(CleanupReason r) {
        switch (r) {
        case CleanupReason::EarlyClean:     return "early";
        case CleanupReason::ProcessExit:    return "exit";
        case CleanupReason::BenignVerdict:  return "benign";
        case CleanupReason::MalwareVerdict: return "malware";
        case CleanupReason::Orphan:         return "orphan";
        }
        return "?";
    }

    class CleanupEngine {
    public:
        CleanupEngine(std::mutex& mtx, std::map<DWORD, ProcessFeature>& coll, CowEngine& cow)
            : mtx_(mtx), coll_(coll), cow_(cow) {
        }

        /* ---- (1) Early cleanup ---- */
        void EarlyCleanupPass() {
            std::vector<DWORD> pids;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                for (auto& [pid, pf] : coll_)
                    if (!pf.exited && pf.totalScore <= cfg::SCORE_CLEANUP_MAX && !pf.entries.empty())
                        pids.push_back(pid);
            }
            for (DWORD pid : pids) EarlyCleanupOne(pid);
        }

        void EarlyCleanupOne(DWORD pid) {
            std::lock_guard<std::mutex> lk(mtx_);
            auto it = coll_.find(pid);
            if (it == coll_.end()) return;
            auto& pf = it->second;

            if (pf.totalScore > cfg::SCORE_CLEANUP_MAX) return;
            if (pf.entries.size() <= cfg::EARLY_CLEANUP_KEEP_RECENT) return;

            uint64_t now = UnixNow();
            uint64_t freed = 0;
            size_t   removed = 0;

            /*
             * Sắp theo thời gian backup TĂNG dần, xoá từ cũ nhất,
             * NHƯNG luôn giữ lại 20 entry gần nhất.
             *
             * Cửa sổ 20 entry là vùng đệm cho khoảng thời gian từ lúc hành vi
             * xấu bắt đầu tới lúc score kịp vượt 1. Nếu xoá sạch, một tiến trình
             * "ngủ đông" rồi đột ngột mã hoá sẽ không có bản gốc nào.
             */
            std::sort(pf.entries.begin(), pf.entries.end(),
                [](const BackupEntry& a, const BackupEntry& b) {
                    return a.backedUpAtUnix < b.backedUpAtUnix;
                });

            size_t maxRemove = pf.entries.size() - cfg::EARLY_CLEANUP_KEEP_RECENT;
            size_t i = 0;
            while (i < maxRemove) {
                auto& e = pf.entries[i];
                if (now - e.backedUpAtUnix <= (uint64_t)cfg::EARLY_CLEANUP_AGE_SEC) break;
                std::error_code ec;
                fs::remove(CowEngine::ProcDir(pid, pf.startTime) + L"\\" + e.backupName, ec);
                if (!e.dedupLink) freed += e.sizeBytes;
                removed++; i++;
            }
            if (removed == 0) return;

            pf.entries.erase(pf.entries.begin(), pf.entries.begin() + removed);
            pf.quotaUsed = (pf.quotaUsed > freed) ? pf.quotaUsed - freed : 0;
            pf.manifestDirty = true;   /* MaintenanceThread ghi gộp, không flush dưới lock */

            LOG_D("[CLEAN-1] PID=%lu score=%d: xoa %zu backup cu (%llu KB), giu lai %zu gan nhat.",
                pid, pf.totalScore, removed, freed / 1024, pf.entries.size());
        }

        /* ---- (2) Exit cleanup ---- */
        void OnProcessExit(DWORD pid) {
            std::lock_guard<std::mutex> lk(mtx_);
            auto it = coll_.find(pid);
            if (it == coll_.end()) return;
            it->second.exited = true;
            it->second.exitedAt = Clock::now();
            LOG_D("[EXIT] PID=%lu thoat, score cuoi=%d", pid, it->second.totalScore);
        }

        void ExitCleanupPass() {
            struct Job { DWORD pid; uint64_t startTime; int score; bool keepManifest; };
            std::vector<Job> jobs;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                auto now = Clock::now();
                for (auto it = coll_.begin(); it != coll_.end();) {
                    auto& pf = it->second;
                    /* Phòng trường hợp không nhận được event exit từ driver */
                    if (!pf.exited && pf.pid != 0 && !IsProcessAlive(pf.pid)) {
                        pf.exited = true; pf.exitedAt = now;
                    }
                    if (!pf.exited) { ++it; continue; }

                    auto age = std::chrono::duration_cast<std::chrono::seconds>(
                        now - pf.exitedAt).count();

                    if (pf.totalScore >= cfg::SCORE_ML_TRIGGER) {
                        if (pf.ml.inFlight) {
                            /* Cuoc goi ML dang chay do, khong dong vao -
                               CallML tu xu ly khi co phan hoi ve. */
                            ++it; continue;
                        }
                        if (pf.ml.lastVerdict == Verdict::Benign &&
                            pf.ml.callCount >= 1 &&
                            pf.ml.callCount < cfg::ML_MAX_SCHEDULED_CALLS) {
                            /* Da co it nhat 1 lan Benign nhung chua du 4 lan
                               thi process da thoat - khong con su kien moi
                               nao de cho lich 30/60/90s nua, dung luon
                               verdict da co, xoa backup ngay (giu manifest
                               giong OnBenign) thay vi giu vo thoi han. */
                            jobs.push_back({ pf.pid, pf.startTime, pf.totalScore, true });
                            it = coll_.erase(it);
                            continue;
                        }
                        /* Chua tung goi ML (callCount==0) hoac verdict=Malware/
                           Unknown -> GIU VO THOI HAN, cho ML/user. */
                        ++it; continue;
                    }
                    if (pf.totalScore >= cfg::SCORE_FREEZE) {
                        /*
                         * GRACE PERIOD 10 phút.
                         * Ransomware nhiều tầng: dropper chạy 3s rồi tự xoá,
                         * payload chạy sau. Xoá backup ngay khi PID biến mất
                         * thì tầng sau không còn gì để khôi phục.
                         */
                        if (age < cfg::EXIT_GRACE_PERIOD_SEC) { ++it; continue; }
                    }
                    jobs.push_back({ pf.pid, pf.startTime, pf.totalScore, false });
                    it = coll_.erase(it);
                }
            }
            for (auto& j : jobs) {
                if (j.keepManifest) {
                    PurgeFilesKeepManifest(j.pid, j.startTime);
                    LOG_D("[CLEAN-2] PID=%lu da thoat giua chung goi ML (score=%d) -> Benign, xoa backup.", j.pid, j.score);
                }
                else {
                    Purge(j.pid, j.startTime, CleanupReason::ProcessExit);
                    LOG_D("[CLEAN-2] PID=%lu (score=%d) da thoat -> xoa backup.", j.pid, j.score);
                }
            }
        }

        /* ---- (3) Verdict cleanup ---- */
        void OnBenign(DWORD pid) {
            uint64_t st = 0;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                auto it = coll_.find(pid);
                if (it == coll_.end()) return;
                st = it->second.startTime;
                it->second.entries.clear();
                it->second.quotaUsed = 0;
                it->second.backupFrozen = false;
            }
            /* Xoá backup nhưng GIỮ manifest — cần cho audit và ShouldCallML */
            PurgeFilesKeepManifest(pid, st);
            LOG_I("[CLEAN-3] PID=%lu BENIGN -> xoa backup, giu manifest.", pid);
        }

        void OnMalware(DWORD pid) {
            uint64_t st = 0;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                auto it = coll_.find(pid);
                if (it != coll_.end()) st = it->second.startTime;
            }
            /* KHÔNG xoá — chuyển sang quarantine làm bằng chứng */
            std::error_code ec;
            std::wstring src = CowEngine::ProcDir(pid, st);
            std::wstring dst = cfg::QUARANTINE_ROOT + L"\\" +
                std::to_wstring(UnixNow()) + L"_" + std::to_wstring(pid);
            fs::rename(src, dst, ec);
            if (ec) LOG_W("[CLEAN-3] Chuyen quarantine that bai: %s", ec.message().c_str());
            else    LOG_I("[CLEAN-3] PID=%lu MALWARE -> quarantine: %s", pid, ws2s(dst).c_str());
        }

        /* ---- (4) Orphan sweep — chạy một lần lúc khởi động ---- */
        void OrphanSweep() {
            bool prevCrashed = fs::exists(cfg::SESSION_FILE);
            if (prevCrashed)
                LOG_W("[CLEAN-4] Phat hien .session con sot -> phien truoc CRASH hoac BI KILL.");

            if (!fs::exists(cfg::BACKUP_ROOT)) return;

            int kept = 0, purged = 0, quarantined = 0, alerts = 0;
            std::error_code ec;

            for (auto& de : fs::directory_iterator(cfg::BACKUP_ROOT, ec)) {
                if (!de.is_directory()) continue;
                std::wstring dir = de.path().wstring();
                std::wstring mf = dir + L"\\manifest.json";

                if (!fs::exists(mf)) {
                    /* Không có manifest -> KHÔNG XOÁ, có thể là dữ liệu người dùng thật */
                    MoveToQuarantine(dir, L"orphan_nomanifest");
                    quarantined++;
                    continue;
                }
                JsonVal v;
                if (!JsonP::Parse(ReadTextFile(mf), v) || v.type != JsonVal::Obj) {
                    MoveToQuarantine(dir, L"orphan_badmanifest");
                    quarantined++;
                    continue;
                }

                int      score = (int)v.N("score", 0);
                uint64_t startTime = (uint64_t)v.N("start_time", 0);
                DWORD    pid = (DWORD)v.N("pid", 0);

                /* Tiến trình còn sống và ĐÚNG là nó (so start_time -> chống PID reuse) */
                bool stillAlive = IsProcessAlive(pid) && GetProcessStartTime(pid) == startTime;
                if (stillAlive) { kept++; continue; }

                /*
                 * NHÁNH QUAN TRỌNG NHẤT:
                 * session bị cắt giữa chừng + score >= 6
                 * = ransomware nhiều khả năng đã KILL RansomDefense rồi mã hoá tự do.
                 * Backup còn lại là thứ DUY NHẤT cứu được dữ liệu.
                 * TUYỆT ĐỐI không dọn tự động.
                 */
                if (prevCrashed && score >= cfg::SCORE_ML_TRIGGER) {
                    LOG_A("[CLEAN-4] CANH BAO: phien truoc bi cat khi dang theo doi PID=%lu "
                        "score=%d. Giu nguyen backup tai %s", pid, score, ws2s(dir).c_str());
                    alerts++;
                    kept++;
                    continue;
                }

                /* Lành tính và đã cũ -> xoá */
                uint64_t oldest = UINT64_MAX;
                if (auto* arr = v.A("entries"))
                    for (auto& e : *arr)
                        oldest = (std::min)(oldest, (uint64_t)e.N("backed_up_at", 0));

                bool old = (oldest == UINT64_MAX) ||
                    (UnixNow() - oldest > (uint64_t)cfg::ORPHAN_MAX_AGE_HOURS * 3600);

                if (score <= cfg::SCORE_CLEANUP_MAX && old) {
                    fs::remove_all(dir, ec);
                    purged++;
                }
                else {
                    kept++;
                }
            }

            if (alerts > 0) {
                std::wstring msg = L"RansomDefense: phien truoc ket thuc bat thuong khi dang theo doi "
                    + std::to_wstring(alerts) + L" tien trinh dang ngo.\n"
                    L"Backup da duoc giu lai tai " + cfg::BACKUP_ROOT +
                    L"\nKiem tra du lieu cua ban.";
                MessageBoxW(nullptr, msg.c_str(), L"RansomDefense — Canh bao khoi dong",
                    MB_OK | MB_ICONWARNING);
            }
            LOG_I("[CLEAN-4] Orphan sweep: giu=%d  xoa=%d  quarantine=%d  canh bao=%d",
                kept, purged, quarantined, alerts);
        }

        /* Heartbeat — phân biệt crash và thoát sạch */
        static void WriteHeartbeat() {
            AtomicWriteFile(cfg::SESSION_FILE, std::to_string(UnixNow()));
        }
        static void ClearHeartbeat() {
            std::error_code ec;
            fs::remove(cfg::SESSION_FILE, ec);
        }

        /*
         * RESTORE CÓ ĐIỀU KIỆN (mục 4.4) — không đè file vô điều kiện.
         * Nếu ML phán nhầm và tiến trình bị nghi oan là một editor đang lưu
         * bài hợp lệ, đè file vô điều kiện sẽ xoá mất công việc thật của
         * người dùng. Chỉ đè khi có dấu hiệu mã hoá rõ ràng (xem dưới).
         */
        struct RestoreStats { int overwritten = 0, sidelined = 0, skipped = 0, missing = 0; };

        RestoreStats RestoreFiles(DWORD pid) {
            RestoreStats st;
            std::vector<BackupEntry> entries;
            uint64_t startTime = 0;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                auto it = coll_.find(pid);
                if (it == coll_.end()) return st;
                entries = it->second.entries;
                startTime = it->second.startTime;
            }
            std::wstring dir = CowEngine::ProcDir(pid, startTime);

            LOG_I("[RESTORE] PID=%lu: %zu entries, dir=%s",
                pid, entries.size(), ws2s(dir).c_str());

            for (auto& e : entries) {
                /*
                 * backupName có thể là:
                 *   1. Tên file ngắn (entry của childPid) → src = dir + backupName
                 *   2. Full path (entry đăng ký từ childPid vào rootPid) → dùng trực tiếp
                 */
                std::wstring src;
                if (e.backupName.size() > 2 && e.backupName[1] == L':') {
                    src = e.backupName;   /* full path */
                }
                else {
                    src = dir + L"\\" + e.backupName;
                }

                LOG_D("[RESTORE] Entry: src=%s exists=%d originalPath=%s",
                    ws2s(e.backupName).c_str(),
                    (int)fs::exists(src),
                    ws2s(e.originalPath).c_str());

                if (!fs::exists(src)) {
                    LOG_W("[RESTORE] Bo qua: file backup khong ton tai: %s", ws2s(src).c_str());
                    continue;
                }

                /* File đã bị xoá/rename -> chắc chắn cần khôi phục */
                if (!fs::exists(e.originalPath)) {
                    std::error_code ec;
                    fs::create_directories(fs::path(e.originalPath).parent_path(), ec);
                    if (CopyFileW(src.c_str(), e.originalPath.c_str(), FALSE)) {
                        st.missing++;
                        LOG_I("   [RESTORE] (da bi xoa) %s", ws2s(e.originalPath).c_str());
                    }
                    continue;
                }

                std::string  hashNow = Sha256File(e.originalPath);
                double       hNow = FileEntropy(e.originalPath, cfg::ENTROPY_SAMPLE_BYTES);
                std::string  magicNow = FileMagicHex(e.originalPath);

                /* Không đổi -> không làm gì */
                if (!hashNow.empty() && hashNow == e.sha256Before) { st.skipped++; continue; }

                /*
                 * Dấu hiệu mã hoá:
                 *   - Entropy TĂNG mạnh  (dH > +2.0)  — dữ liệu trở nên ngẫu nhiên
                 *   - HOẶC magic byte đổi VÀ entropy cao (> 7.0)
                 *
                 * Chỉ xét "magic đổi" đơn thuần sẽ đè cả khi dH ÂM (file bị
                 * zero/rỗng): entropy giảm mạnh không phải dấu hiệu mã hoá.
                 */
                double dH = hNow - e.entropyBefore;
                bool entropyJump = (dH > cfg::ENTROPY_DELTA_THRESHOLD);
                bool magicChanged = (!e.magicBefore.empty() && magicNow != e.magicBefore);
                bool looksEncrypted = entropyJump ||
                    (magicChanged && hNow > 7.0);

                if (looksEncrypted) {
                    if (CopyFileW(src.c_str(), e.originalPath.c_str(), FALSE)) {
                        st.overwritten++;
                        LOG_I("   [RESTORE] de (dH=%+.2f) %s",
                            dH, ws2s(e.originalPath).c_str());
                    }
                }
                else {
                    /*
                     * File đổi nhưng KHÔNG có dấu hiệu mã hoá.
                     * Có thể là công việc thật của user -> KHÔNG ĐÈ.
                     */
                    std::wstring side = cfg::RESTORED_ROOT + L"\\" + std::to_wstring(pid);
                    std::error_code ec; fs::create_directories(side, ec);
                    CopyFileW(src.c_str(), (side + L"\\" + e.backupName).c_str(), FALSE);
                    st.sidelined++;
                    LOG_W("   [RESTORE] KHONG de (khong co dau hieu ma hoa): %s "
                        "-> ban sao luu tai %s", ws2s(e.originalPath).c_str(), ws2s(side).c_str());
                }
            }
            LOG_I("[RESTORE] PID=%lu: de=%d  khoi-phuc-file-da-xoa=%d  "
                "de-user-quyet=%d  khong-doi=%d",
                pid, st.overwritten, st.missing, st.sidelined, st.skipped);
            return st;
        }

        /*
         * DỌN FILE RÁC DO RANSOMWARE TẠO RA.
         *
         * WannaCry (và phần lớn ransomware) làm 3 bước: đọc file gốc, ghi bản
         * mã hoá ra file mới (vd file.docx.WNCRY), rồi xoá file gốc.
         * RestoreFiles khôi phục được file gốc, nhưng file .WNCRY không ai
         * xoá — nó chưa từng là file của user nên không nằm trong manifest.
         *
         * An toàn: chỉ xoá <original_path> + <đuôi ransomware>, tức đúng
         * những file biết chắc sinh ra từ một entry trong manifest. Không
         * quét thư mục, không đoán, không đụng gì khác.
         */
        int CleanRansomArtifacts(DWORD pid) {
            static const wchar_t* kRansomExts[] = {
                L".WNCRY", L".WNCRYT", L".wncry", L".wnry", L".wncryt",
                L".locked", L".encrypted", L".enc", L".crypt", L".crypto",
                L".cerber", L".locky", L".zepto", L".odin", L".thor", L".aesir",
                L".conti", L".lockbit", L".ryuk",
            };

            std::vector<std::wstring> originals;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                auto it = coll_.find(pid);
                if (it == coll_.end()) return 0;
                for (auto& e : it->second.entries) originals.push_back(e.originalPath);
            }

            int removed = 0;
            std::error_code ec;
            for (const auto& orig : originals) {
                for (auto* ext : kRansomExts) {
                    std::wstring artifact = orig + ext;
                    if (!fs::exists(artifact, ec)) { ec.clear(); continue; }
                    if (fs::remove(artifact, ec)) {
                        removed++;
                        LOG_D("   [CLEAN] Xoa rac ma hoa: %s",
                            ws2s(GetFileNameOnly(artifact)).c_str());
                    }
                    ec.clear();
                }
            }
            if (removed > 0)
                LOG_I("   [CLEAN] Da xoa %d file rac do ransomware tao ra.", removed);
            return removed;
        }

        /*
         * Dọn ransom note. Chỉ quét các THƯ MỤC đã có ít nhất một BackupEntry
         * (tức chắc chắn là nạn nhân thật, không quét toàn ổ đĩa), tìm file
         * MỚI không nằm trong manifest, tên khớp mẫu ransom note, và được
         * tạo SAU khi tiến trình bắt đầu chạy — điều kiện thời gian này để
         * không đụng file người dùng đã đặt sẵn từ trước (vd tự tạo README
         * để test).
         */
        int CleanRansomNotes(DWORD pid) {
            std::set<std::wstring> dirs;
            std::set<std::wstring> knownFiles;
            uint64_t startTime = 0;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                auto it = coll_.find(pid);
                if (it == coll_.end()) return 0;
                startTime = it->second.startTime;
                for (auto& e : it->second.entries) {
                    std::wstring dir = fs::path(e.originalPath).parent_path().wstring();
                    if (!dir.empty()) dirs.insert(ToLower(dir));
                    knownFiles.insert(ToLower(e.originalPath));
                }
            }
            if (dirs.empty() || startTime == 0) return 0;

            /* Biên an toàn 2 giây (đơn vị FILETIME, 100ns) cho sai số đo thời gian */
            constexpr uint64_t kMarginFt = 2ull * 10'000'000;
            uint64_t cutoff = (startTime > kMarginFt) ? startTime - kMarginFt : 0;

            int removed = 0;
            std::error_code ec;
            for (const auto& dir : dirs) {
                for (auto& de : fs::directory_iterator(dir, ec)) {
                    if (!de.is_regular_file(ec)) { ec.clear(); continue; }

                    std::wstring full = ToLower(de.path().wstring());
                    if (knownFiles.count(full)) continue;
                    if (!LooksLikeRansomNote(de.path().filename().wstring())) continue;

                    WIN32_FILE_ATTRIBUTE_DATA fad{};
                    if (!GetFileAttributesExW(de.path().c_str(), GetFileExInfoStandard, &fad))
                        continue;
                    ULARGE_INTEGER ct{};
                    ct.LowPart = fad.ftCreationTime.dwLowDateTime;
                    ct.HighPart = fad.ftCreationTime.dwHighDateTime;
                    if (ct.QuadPart < cutoff) continue;   /* có trước khi tiến trình chạy -> bỏ qua */

                    if (fs::remove(de.path(), ec)) {
                        removed++;
                        LOG_D("   [CLEAN] Xoa ransom note: %s",
                            ws2s(de.path().filename().wstring()).c_str());
                    }
                    ec.clear();
                }
                ec.clear();
            }
            if (removed > 0)
                LOG_I("   [CLEAN] Da xoa %d ransom note.", removed);
            return removed;
        }

    private:
        std::mutex& mtx_;
        std::map<DWORD, ProcessFeature>& coll_;
        CowEngine& cow_;

        static void Purge(DWORD pid, uint64_t startTime, CleanupReason r) {
            std::error_code ec;
            uintmax_t n = fs::remove_all(CowEngine::ProcDir(pid, startTime), ec);
            if (ec) LOG_W("[CLEAN] Xoa that bai pid=%lu (%s): %s",
                pid, ReasonName(r), ec.message().c_str());
            else if (n > 0) LOG_D("[CLEAN] pid=%lu reason=%s files=%ju", pid, ReasonName(r), n);
        }

        static void PurgeFilesKeepManifest(DWORD pid, uint64_t startTime) {
            std::error_code ec;
            std::wstring dir = CowEngine::ProcDir(pid, startTime);
            if (!fs::exists(dir)) return;
            for (auto& de : fs::directory_iterator(dir, ec)) {
                if (de.path().filename() == L"manifest.json") continue;
                fs::remove(de.path(), ec);
            }
        }

        static void MoveToQuarantine(const std::wstring& dir, const std::wstring& tag) {
            std::error_code ec;
            std::wstring dst = cfg::QUARANTINE_ROOT + L"\\" + tag + L"_" +
                std::to_wstring(UnixNow()) + L"_" +
                fs::path(dir).filename().wstring();
            fs::rename(dir, dst, ec);
            if (!ec) LOG_W("[CLEAN-4] Thu muc mo coi -> quarantine: %s", ws2s(dst).c_str());
        }
    };

} // namespace rw