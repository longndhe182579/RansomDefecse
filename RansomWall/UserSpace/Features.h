/*
 * Features.h — Cấu trúc dữ liệu đặc trưng RansomWall v4.0
 */
#pragma once

#include "Util.h"
#include "Config.h"
#include <deque>
#include <set>
#include <map>
#include <vector>
#include <string>

namespace rw {

    /* ======================================================================
       LATCH — cờ một chiều, chỉ tăng không giảm, không có decay
       ====================================================================== */
    struct Latch {
        bool      value = false;
        TimePoint setAt{};

        void Set() {
            if (!value) {
                value = true;
                setAt = Clock::now();
            }
        }

        explicit operator bool() const { return value; }
    };

    /* ======================================================================
       SLIDING COUNTER — đo TỐC ĐỘ trong cửa sổ trượt WINDOW_SEC giây
       Ransomware khác biệt ở MẬT ĐỘ, không phải tổng số thao tác.
       ====================================================================== */
    struct SlidingCounter {
        std::deque<TimePoint> ev;

        void Add(int n = 1) {
            auto now = Clock::now();
            for (int i = 0; i < n; i++) ev.push_back(now);
            Trim(now);
        }

        double Rate() {
            Trim(Clock::now());
            return (double)ev.size() / (double)cfg::WINDOW_SEC;
        }

        size_t Count() {
            Trim(Clock::now());
            return ev.size();
        }

    private:
        void Trim(TimePoint now) {
            while (!ev.empty() &&
                std::chrono::duration_cast<std::chrono::seconds>(
                    now - ev.front()).count() > cfg::WINDOW_SEC)
                ev.pop_front();
        }
    };

    /* ======================================================================
       RUNNING MEAN — trung bình động cho entropy delta
       ====================================================================== */
    struct RunningMean {
        double   sum = 0;
        uint64_t n = 0;

        void   Add(double v) { sum += v; n++; }
        double Mean() const { return n ? sum / (double)n : 0.0; }
    };

    /* ======================================================================
       VERDICT + ML STATE
       Không còn Offline — nếu Flask không phản hồi trả về Unknown.
       ====================================================================== */
    enum class Verdict { Unknown, Benign, Malware };

    struct MLState {
        int       callCount = 0;
        TimePoint lastCall{};
        Verdict   lastVerdict = Verdict::Unknown;
        int       scoreAtLastCall = 0;
        double    ioRateAtLastCall = 0;
        bool      vectorDirty = false;  // true khi có Raise() mới kể từ lần gọi cuối

        /*
         * inFlight — CHỐNG STAMPEDE.
         * Đặt = true NGAY TẠI điểm kiểm tra, dưới cùng một lock,
         * trước khi spawn thread. Tránh 30 thread gọi ML đồng thời.
         */
        bool      inFlight = false;

        /* Đã xử lý MALWARE rồi → không kill/restore lần hai */
        bool      verdictHandled = false;
    };

    /* ======================================================================
       QUOTA TIER — bốn bậc theo totalScore
       ====================================================================== */
    enum class QuotaTier { T0_Clean, T1_Suspect, T2_Danger, T3_Critical };

    inline const char* TierName(QuotaTier t) {
        switch (t) {
        case QuotaTier::T0_Clean:    return "T0(score 0-1)";
        case QuotaTier::T1_Suspect:  return "T1(score 2-3)";
        case QuotaTier::T2_Danger:   return "T2(score 4-5)";
        case QuotaTier::T3_Critical: return "T3(score>=6)";
        }
        return "?";
    }

    inline QuotaTier TierOf(int score) {
        if (score <= 1) return QuotaTier::T0_Clean;
        if (score <= 3) return QuotaTier::T1_Suspect;
        if (score <= 5) return QuotaTier::T2_Danger;
        return QuotaTier::T3_Critical;
    }

    /* ======================================================================
       BACKUP ENTRY — một dòng trong manifest.json
       ====================================================================== */
    struct BackupEntry {
        std::wstring backupName;       // ví dụ: 1736938201_report.xlsx
        std::wstring originalPath;     // C:\Users\x\Documents\report.xlsx
        std::string  sha256Before;     // dedup key
        std::string  magicBefore;      // 16 byte đầu dạng hex  → nguồn F12
        double       entropyBefore = 0; //                       → nguồn F13
        uint64_t     sizeBytes = 0;
        uint64_t     backedUpAtUnix = 0;
        double       valueScore = 0; // V(f) → LRU theo giá trị
        bool         dedupLink = false;
    };

    /* ======================================================================
       PROCESS FEATURE — toàn bộ trạng thái theo dõi một PID
       ====================================================================== */
    struct ProcessFeature {
        DWORD        pid = 0;
        DWORD        rootPid = 0;
        uint64_t     startTime = 0;        // chống PID reuse
        std::wstring processImage;
        std::string  imageSha256;
        int          totalScore = 0;
        bool         exited = false;
        TimePoint    exitedAt{};
        TimePoint    createdAt = Clock::now();

        /* ── Đặc trưng tĩnh (A) — không decay ── */
        Latch f1_unsigned;
        Latch f2_packed;
        Latch f3_suspStrings;

        /* ── Đặc trưng trap (C2) — không decay ── */
        Latch f4_honeyModified;
        Latch f5_cryptoApi;
        Latch f6_safeModeDisable;
        Latch f7_shadowDeleted;
        Latch f8_registryPersist;

        /* ── Đặc trưng động (C3) — không decay, SlidingCounter đo tốc độ ── */
        Latch f9_dirEnum;
        Latch f10_highIo;
        Latch f11_extChanged;
        Latch f12_fingerprintMismatch;
        Latch f13_highEntropy;

        /* ── Counter tốc độ ── */
        SlidingCounter ioOps;
        SlidingCounter renames;
        SlidingCounter dirEntries;
        std::set<std::wstring>      affectedExts;
        RunningMean                 entropyDelta;
        std::map<std::wstring, int> newExtHistogram;

        /* ── CoW state ── */
        QuotaTier    quotaTier = QuotaTier::T0_Clean;
        uint64_t     quotaLimit = 0;
        uint64_t     quotaUsed = 0;
        bool         backupFrozen = false;  // quota đầy + score>=2 → đóng băng
        bool         manifestDirty = false;  // MaintenanceThread ghi gộp mỗi 5s
        std::vector<BackupEntry> entries;

        /* ── ML state ── */
        MLState ml;

        /* ================================================================
           Raise — bật cờ + cộng điểm.
           Trả về true nếu đây là lần bật ĐẦU TIÊN (score vừa tăng).
           ================================================================ */
        bool Raise(Latch& l, const char* name) {
            bool was = l.value;
            l.Set();
            if (!was) {
                totalScore++;
                ml.vectorDirty = true;
                LOG_A("  [+] %s  PID=%lu  score=%d", name, pid, totalScore);
                return true;
            }
            return false;
        }

        /* ================================================================
           ShouldCallML — kiểm tra có nên gọi ML không.
           Điều kiện: score đủ ngưỡng + vector có thay đổi mới +
                      không quá gần lần gọi trước.
           ================================================================ */
        bool ShouldCallML() {
            if (totalScore < cfg::SCORE_ML_TRIGGER) return false;
            if (!ml.vectorDirty)                    return false;

            if (ml.callCount == 0) return true;

            auto sinceLast = std::chrono::duration_cast<std::chrono::milliseconds>(
                Clock::now() - ml.lastCall).count();
            if (sinceLast < cfg::ML_MIN_INTERVAL_MS) return false;

            /* Gọi lại khi có bằng chứng MỚI so với lần phán quyết trước */
            if (totalScore > ml.scoreAtLastCall)                              return true;
            if (ioOps.Rate() > 2.0 * ml.ioRateAtLastCall
                && ml.ioRateAtLastCall > 0)                                   return true;

            return false;
        }

        /* ================================================================
           ToJson — vector 15 chiều gửi Flask.
           Khớp FEATURE_ORDER trong train.py và app.py.
           ================================================================ */
        std::string ToJson() {
            JsonW j;
            j.Begin()
                .UInt("pid", pid)
                /* 13 boolean F1-F13 */
                .Bool01("unsigned", f1_unsigned.value)
                .Bool01("packed", f2_packed.value)
                .Bool01("suspicious_strings", f3_suspStrings.value)
                .Bool01("honey_modified", f4_honeyModified.value)
                .Bool01("crypto_api", f5_cryptoApi.value)
                .Bool01("safe_mode_disable", f6_safeModeDisable.value)
                .Bool01("shadow_deleted", f7_shadowDeleted.value)
                .Bool01("registry_persist", f8_registryPersist.value)
                .Bool01("dir_enum", f9_dirEnum.value)
                .Bool01("high_io", f10_highIo.value)
                .Bool01("ext_changed", f11_extChanged.value)
                .Bool01("fingerprint_mismatch", f12_fingerprintMismatch.value)
                .Bool01("high_entropy", f13_highEntropy.value)
                /* 2 đặc trưng tốc độ bổ sung */
                .Num("io_rate", ioOps.Rate())
                .Num("mean_entropy_delta", entropyDelta.Mean())
                .End();
            return j.Get();
        }
    };

} // namespace rw