/*
 * Features.h — Cấu trúc dữ liệu đặc trưng.
 *
 * SỬA LỖI v3.0:
 *   - Điểm chỉ tăng, không bao giờ giảm  -> Latch một chiều (không decay)
 *   - Counter tích luỹ (ioOperationsCount > 3) -> SlidingCounter theo TỐC ĐỘ
 *   - FeatureCollector phình vô hạn      -> có GC
 *   - aiCalled một chiều                 -> MLState cho phép tái đánh giá
 */
#pragma once

#include "Util.h"
#include "Config.h"
#include <deque>
#include <set>

namespace rw {

    /* ======================================================================
       LATCH — cờ một chiều, chỉ bật không tắt
       ====================================================================== */
    struct Latch {
        bool      value = false;
        TimePoint setAt{};

        void Set() {
            if (!value) { value = true; setAt = Clock::now(); }
        }
        explicit operator bool() const { return value; }
    };

    /* ======================================================================
       SLIDING COUNTER — đo TỐC ĐỘ, không phải tổng tích luỹ
       ======================================================================
       v3.0: ioOperationsCount > 3 (tích luỹ)
             -> 7-Zip / indexer chạy cả ngày CHẮC CHẮN vượt.
             Ransomware khác biệt ở MẬT ĐỘ, không phải tổng.
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
        size_t Count() { Trim(Clock::now()); return ev.size(); }

    private:
        void Trim(TimePoint now) {
            while (!ev.empty() &&
                std::chrono::duration_cast<std::chrono::seconds>(now - ev.front()).count()
            > cfg::WINDOW_SEC)
                ev.pop_front();
        }
    };

    struct RunningMean {
        double sum = 0; uint64_t n = 0;
        void Add(double v) { sum += v; n++; }
        double Mean() const { return n ? sum / (double)n : 0.0; }
    };

    /* ======================================================================
       ML STATE — KHÔNG phải cờ một chiều
       ======================================================================
       v3.0: if (pf.aiCalled) return;  -> ML sai một lần là sai vĩnh viễn.
       v4.0: cho gọi lại khi có bằng chứng MỚI.
       ====================================================================== */
    enum class Verdict { Unknown, Benign, Malware };

    struct MLState {
        int       callCount = 0;
        TimePoint lastCall{};
        Verdict   lastVerdict = Verdict::Unknown;
        int       scoreAtLastCall = 0;
        double    ioRateAtLastCall = 0;
        bool      vectorDirty = false;

        /*
         * inFlight — CHỐNG STAMPEDE.
         *
         * LỖI ĐÃ SỬA (30 luồng ML cùng lúc, 30 lần restore đồng thời):
         *   MaybeCallML kiểm tra ShouldCallML() rồi spawn thread; việc cập nhật
         *   lastCall lại nằm BÊN TRONG thread đó. 30 event ập tới trong vài
         *   micro giây -> tất cả kiểm tra TRƯỚC khi bất kỳ ai cập nhật -> pass hết.
         *   -> 30 luồng CopyFileW vào CÙNG một đích -> file bị zero (dH=-7.93).
         *   Code khôi phục tự phá file.
         *
         * Phải "giành quyền" NGAY tại điểm kiểm tra, dưới cùng một lock.
         */
        bool      inFlight = false;

        /* Đã xử lý phán quyết MALWARE rồi -> không kill/restore lần hai */
        bool      verdictHandled = false;
    };

    /* ======================================================================
       QUOTA TIER
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
       BACKUP ENTRY — một dòng trong manifest
       ====================================================================== */
    struct BackupEntry {
        std::wstring backupName;      // 1736938201_report.xlsx
        std::wstring originalPath;    // C:\Users\x\Documents\Finance\report.xlsx
        std::string  sha256Before;
        std::string  magicBefore;     // 16 byte đầu, hex  -> F12
        double       entropyBefore = 0;  //                -> F13
        uint64_t     sizeBytes = 0;
        uint64_t     backedUpAtUnix = 0;
        double       valueScore = 0;  // V(f) -> LRU theo giá trị
        bool         dedupLink = false;
    };

    /* ======================================================================
       PROCESS FEATURE
       ====================================================================== */
    struct ProcessFeature {
        DWORD        pid = 0;
        DWORD        rootPid = 0;
        uint64_t     startTime = 0;      // chống PID reuse
        std::wstring processImage;
        std::string  imageSha256;
        int          totalScore = 0;
        bool         exited = false;
        TimePoint    exitedAt{};
        TimePoint    createdAt = Clock::now();

        /* ---- STATIC (không decay) ---- */
        Latch f1_unsigned;
        Latch f2_packed;
        Latch f3_suspStrings;

        /* ---- TRAP (không decay) ---- */
        Latch f4_honeyModified;
        Latch f5_cryptoApi;
        Latch f6_safeModeDisable;
        Latch f7_shadowDeleted;
        Latch f8_registryPersist;

        /* ---- DYNAMIC (decay sau 30s) ---- */
        Latch f9_dirEnum;
        Latch f10_highIo;
        Latch f11_extChanged;
        Latch f12_fingerprintMismatch;
        Latch f13_highEntropy;

        /* ---- Counter theo tốc độ ---- */
        SlidingCounter ioOps;
        SlidingCounter renames;
        SlidingCounter dirEntries;
        std::set<std::wstring> affectedExts;
        RunningMean    entropyDelta;

        /* ---- Đuôi file mới xuất hiện hàng loạt (F11) ---- */
        std::map<std::wstring, int> newExtHistogram;

        /* ---- CoW state ---- */
        QuotaTier    quotaTier = QuotaTier::T0_Clean;
        uint64_t     quotaLimit = 0;
        uint64_t     quotaUsed = 0;
        bool         backupFrozen = false;   // true khi score >= 2
        bool         manifestDirty = false;  // chờ MaintenanceThread ghi gộp
        std::vector<BackupEntry> entries;

        /* ---- ML state ---- */
        MLState      ml;

        /* Bật cờ + cộng điểm. Trả về true nếu vừa bật lần đầu. */
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

        /*
         * ShouldCallML — thay cho cờ aiCalled một chiều của v3.0.
         * score >= 6 là ĐIỀU KIỆN CẦN, không phải trigger duy nhất.
         */
        bool ShouldCallML() {
            if (totalScore < cfg::SCORE_ML_TRIGGER) return false;

            auto now = Clock::now();
            auto sinceLast = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - ml.lastCall).count();
            if (ml.callCount == 0) return true;
            if (sinceLast < cfg::ML_MIN_INTERVAL_MS) return false;
            if (!ml.vectorDirty) return false;

            /* Chỉ gọi lại khi có bằng chứng MỚI so với lần phán quyết trước */
            if (totalScore > ml.scoreAtLastCall) return true;
            if (ioOps.Rate() > 2.0 * ml.ioRateAtLastCall && ml.ioRateAtLastCall > 0) return true;
            return false;
        }

        /* Feature vector 13 chiều F1-F13 — đúng theo bài báo Shaukat & Ribeiro 2018 */
        std::string ToJson() {
            JsonW j;
            j.Begin()
                .UInt("pid", pid)
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
                .End();
            return j.Get();
        }
    };

} // namespace rw