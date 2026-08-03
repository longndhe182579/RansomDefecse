/*
 * Features.h — Cấu trúc dữ liệu đặc trưng.
 *
 * SỬA LỖI v3.0:
 *   - Điểm chỉ tăng, không bao giờ giảm  -> Latch một chiều (không decay)
 *   - Counter tích luỹ (ioOperationsCount > 3) -> SlidingCounter theo TỐC ĐỘ
 *   - FeatureCollector phình vô hạn      -> có GC
 *   - aiCalled một chiều                 -> MLState cho phép tái đánh giá
 *
 * ===========================================================================
 * BẢN VÁ v4.5
 * ===========================================================================
 *   [FIX 22] newExtHistogram TÍCH LUỸ VÔ HẠN — đúng lỗi đã sửa cho
 *            ioOperationsCount ở v3.0 nhưng bỏ sót chỗ này.
 *            std::map<wstring,int> chỉ ++ mà không bao giờ trừ, ngưỡng n>=5
 *            là tổng tuyệt đối. Tiến trình benign chạy vài giờ sẽ chạm.
 *            -> Đổi sang map<wstring, SlidingCounter>, đếm theo cửa sổ 30s.
 *
 *   [FIX 23] LƯU GIÁ TRỊ LIÊN TỤC, không chỉ boolean.
 *            daaMin và entropyDeltaMax trước đây bị tính rồi vứt đi ngay sau
 *            khi nhị phân hoá thành F13/F14. Với 14 boolean thì không gian
 *            đặc trưng chỉ có 2^14 điểm và các cột tương quan mạnh — quá
 *            mỏng để train. Giữ lại số gốc cho ToTrainingJson().
 *
 *   [FIX 24] cowFiles / cowFailed — đếm CoW có chạy được cho tiến trình này
 *            không. BẮT BUỘC phải có trong dataset: F12/F13 chỉ bật được khi
 *            tồn tại metadata trước-ghi, nên F13=0 mang HAI nghĩa khác nhau
 *            ("không mã hoá" và "không có gì để so sánh"). Không tách được
 *            hai nghĩa đó thì model sẽ học nhầm F13 thành "CoW có chạy không".
 *
 *   [FIX 25] ToJson() bổ sung root_pid / process_start_time / total_score.
 *            Trường "pid" GIỮ NGUYÊN để không phá Flask hiện có, nhưng lưu ý:
 *            giá trị trong đó vốn đã là rootPid (CallML được gọi với root).
 * ===========================================================================
 */
#pragma once

#include "Util.h"
#include "Config.h"
#include <deque>
#include <set>

namespace rw {

    /* ======================================================================
       LATCH — cờ một chiều, chỉ bật không tắt
       ======================================================================
       KHÔNG thêm decay vào đây. Lý do đo được từ log Chaos:
           21:38:29  score 5  (F9 + F10)
           ...43 giay dung yen...
           21:39:12  score 6  (F7)
       Nếu F9/F10 hết hạn sau 30s thì score tụt về 3 và KHÔNG BAO GIỜ chạm 6
       -> không kill. Latch một chiều là lý do hệ thống bắt được Chaos.

       Muốn biết "feature có đang active trong cửa sổ hiện tại không" thì dùng
       ActiveNow() — dựa vào setAt, không đụng vào giá trị latch.
       ====================================================================== */
    struct Latch {
        bool      value = false;
        TimePoint setAt{};

        void Set() {
            if (!value) { value = true; setAt = Clock::now(); }
        }
        explicit operator bool() const { return value; }
    };

    /* [FIX 23] Feature có bật TRONG cửa sổ WINDOW_SEC gần nhất không.
       Chỉ dùng để EXPORT cho ML — không dùng để chấm điểm/trigger. */
    inline bool ActiveNow(const Latch& l) {
        if (!l.value) return false;
        return std::chrono::duration_cast<std::chrono::seconds>(
            Clock::now() - l.setAt).count() <= cfg::WINDOW_SEC;
    }

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
        Latch f5_cryptoApi;        /* F5 là STATIC (parse IAT), không phải TRAP */

        /* ---- TRAP (không decay) ---- */
        Latch f4_honeyModified;    /* thực tế bật cả khi MỞ ĐỌC honey — xem F4 */
        Latch f6_safeModeDisable;
        Latch f7_shadowDeleted;
        Latch f8_registryPersist;

        /* ---- DYNAMIC ----
           LƯU Ý: các cờ này KHÔNG decay (Latch một chiều). Cửa sổ 30 giây chỉ
           quyết định KHI NÀO cờ được bật lần đầu, không hạ cờ. Dùng ActiveNow()
           nếu cần biết trạng thái trong cửa sổ hiện tại. */
        Latch f9_dirEnum;
        Latch f10_highIo;
        Latch f11_extChanged;
        Latch f12_fingerprintMismatch;
        Latch f13_highEntropy;
        Latch f14_daa;             /* F14 Differential Area Analysis (Davies 2021) */

        /* ---- Counter theo tốc độ ---- */
        SlidingCounter ioOps;
        SlidingCounter renames;
        SlidingCounter dirEntries;
        std::set<std::wstring> affectedExts;
        RunningMean    entropyDelta;

        /* [FIX 23] Giá trị liên tục — giữ lại thay vì vứt sau khi nhị phân hoá */
        double       daaMin = 9999.0;   // F14: DAA thấp nhất từng thấy
        double       entropyDeltaMax = 0.0;     // F13: dH lớn nhất từng thấy

        /* [FIX 24] CoW có chạy được cho tiến trình này không */
        uint64_t     cowFiles = 0;      // số file pend đã xử lý xong
        uint64_t     cowFailed = 0;     // trong đó bao nhiêu KHÔNG cứu được

        /* ---- Đuôi file mới xuất hiện hàng loạt (F11) ---- */
        /* [FIX 22] SlidingCounter, KHÔNG phải int tích luỹ */
        std::map<std::wstring, SlidingCounter> newExtHistogram;

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

        /* [FIX 22] Số lần xuất hiện của đuôi mới "nóng" nhất TRONG CỬA SỔ.
           Tiện thể dọn các đuôi đã nguội để map không phình theo thời gian. */
        int MaxNewExtCount() {
            int mx = 0;
            for (auto it = newExtHistogram.begin(); it != newExtHistogram.end(); ) {
                int c = (int)it->second.Count();
                if (c == 0) { it = newExtHistogram.erase(it); continue; }
                if (c > mx) mx = c;
                ++it;
            }
            return mx;
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

            /* ==============================================================
               [FIX 26] THEO DOI 90 GIAY SAU KHI PHAN BENIGN
               ==============================================================
               Phai kiem tra TRUOC if(!vectorDirty) vi sau ML call lan 1:
                 - vectorDirty bi set false
                 - F1-F14 da bat het, Raise() khong bao gio set dirty lai
                 -> neu de vectorDirty chong, retry se bi chan mai mai

               Lich goi lai: +30s / +60s / +90s
               Muc dich: de cow_files, entropy_delta_mean kip cap nhat
               truoc khi phan quyet. Voi Rhysida, luc goi lan 1 (t~20s)
               cow_files=0 va entropy=0 vi CoW chua kip doc xong.
               Sau 30s CoW da backup ~700 file, entropy co so lieu -> predict
               chinh xac hon.
               ============================================================== */
            if (ml.lastVerdict == Verdict::Benign) {
                if (sinceLast >= 30000 && ml.callCount == 1) return true;
                if (sinceLast >= 60000 && ml.callCount == 2) return true;
                if (sinceLast >= 90000 && ml.callCount == 3) return true;
            }

            if (!ml.vectorDirty) return false;

            /* Goi lai khi co bang chung MOI so voi lan phan quyet truoc */
            if (totalScore > ml.scoreAtLastCall) return true;
            if (ioOps.Rate() > 2.0 * ml.ioRateAtLastCall && ml.ioRateAtLastCall > 0) return true;
            return false;
        }

        uint64_t AgeMs() const {
            return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
                Clock::now() - createdAt).count();
        }

        /* Feature vector 14 chiều F1-F14 — payload gửi Khối E lúc chạy thật.
           F1-F13: Shaukat & Ribeiro, COMSNETS 2018
           F14:    Davies et al., arXiv:2106.14418, 2021 (DAA)

           [FIX 25] Thêm root_pid / process_start_time / total_score cho khớp
           mô tả 3.1.6 ("gửi kèm để phục vụ truy vết"). Giữ nguyên "pid" để
           không phá Flask đang chạy. */
        std::string ToJson() {
            JsonW j;
            j.Begin()
                .UInt("pid", pid)
                .UInt("root_pid", rootPid ? rootPid : pid)
                .UInt("process_start_time", startTime)
                .Int("total_score", totalScore)
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
                .Bool01("daa_encrypted", f14_daa.value)
                .Num("io_rate",            ioOps.Rate())
                .Num("rename_rate",        renames.Rate())
                .Num("dirent_rate",        dirEntries.Rate())
                .Num("entropy_delta_mean", entropyDelta.Mean())
                .Num("entropy_delta_max",  entropyDeltaMax)
                .Num("daa_min",            daaMin < 9000.0 ? daaMin : 0.0)
                .UInt("entropy_samples",   (uint64_t)entropyDelta.n)
                .UInt("cow_files",         cowFiles)
                .UInt("cow_failed",        cowFailed)
                .UInt("affected_ext_count",(uint64_t)affectedExts.size())
                .Int("new_ext_max",        MaxNewExtCount())
                .UInt("backup_entries",    (uint64_t)entries.size())
                .UInt("quota_used",        quotaUsed)
                .UInt("t_ms",              AgeMs())
                .End();
            return j.Get();
        }

        /* ==================================================================
           [FIX 23/24] ToTrainingJson — BẢN GHI DÙNG ĐỂ TRAIN, không phải để
           suy luận lúc chạy.
           ==================================================================
           Khác ToJson() ở ba điểm, và cả ba đều cần thiết:

           1. fN_now  — feature có active trong cửa sổ 30 giây hiện tại không.
              Cột fN (latch) trả lời "đã từng", cột fN_now trả lời "đang".
              Có cả hai thì lúc train mới thử được cả hai giả thuyết.

           2. Giá trị LIÊN TỤC (io_rate, daa_min, entropy_delta_max...).
              14 boolean là không gian quá mỏng. GradientBoosting tự học
              ngưỡng từ số thực thường tốt hơn ngưỡng đặt tay trong Config.h.

           3. cow_backed_up / cow_failed — MẶT NẠ HỢP LỆ cho F12/F13.
              Không có bản backup hoặc pre-metadata thì F12/F13 KHÔNG THỂ bật,
              kể cả khi file bị mã hoá rành rành. Thiếu cột này thì hai nghĩa
              của số 0 bị trộn làm một.

           runId do người gọi truyền vào: mỗi phiên chạy mẫu một giá trị, dùng
           để tách train/test THEO PHIÊN. Nếu hai snapshot cách nhau 1 giây của
           cùng một lần chạy rơi vào cả train lẫn test thì accuracy sẽ đẹp một
           cách vô nghĩa.
           ================================================================== */
        std::string ToTrainingJson(const std::string& runId, const char* label) {
            JsonW j;
            j.Begin()
                .Int("schema", 1)
                .Str("run_id", runId)
                .Str("label", label ? label : "unknown")
                .UInt("root_pid", rootPid ? rootPid : pid)
                .UInt("pid", pid)
                .UInt("process_start_time", startTime)
                .Str("image_sha256", imageSha256)
                .Str("image_name", GetFileNameOnly(processImage))
                .UInt("t_ms", AgeMs())
                .Int("total_score", totalScore)

                /* --- vector latch: giống hệt ToJson --- */
                .Bool01("f1_unsigned", f1_unsigned.value)
                .Bool01("f2_packed", f2_packed.value)
                .Bool01("f3_susp_strings", f3_suspStrings.value)
                .Bool01("f4_honey", f4_honeyModified.value)
                .Bool01("f5_crypto_api", f5_cryptoApi.value)
                .Bool01("f6_safe_mode", f6_safeModeDisable.value)
                .Bool01("f7_shadow_del", f7_shadowDeleted.value)
                .Bool01("f8_reg_persist", f8_registryPersist.value)
                .Bool01("f9_dir_enum", f9_dirEnum.value)
                .Bool01("f10_high_io", f10_highIo.value)
                .Bool01("f11_ext_changed", f11_extChanged.value)
                .Bool01("f12_fingerprint", f12_fingerprintMismatch.value)
                .Bool01("f13_entropy", f13_highEntropy.value)
                .Bool01("f14_daa", f14_daa.value)

                /* --- cùng feature nhưng theo cửa sổ hiện tại --- */
                .Bool01("f9_now", ActiveNow(f9_dirEnum))
                .Bool01("f10_now", ActiveNow(f10_highIo))
                .Bool01("f11_now", ActiveNow(f11_extChanged))
                .Bool01("f12_now", ActiveNow(f12_fingerprintMismatch))
                .Bool01("f13_now", ActiveNow(f13_highEntropy))
                .Bool01("f14_now", ActiveNow(f14_daa))

                /* --- giá trị liên tục --- */
                .Num("io_rate", ioOps.Rate())
                .Num("rename_rate", renames.Rate())
                .Num("dirent_rate", dirEntries.Rate())
                .Num("entropy_delta_mean", entropyDelta.Mean())
                .Num("entropy_delta_max", entropyDeltaMax)
                .Num("daa_min", daaMin)
                .UInt("affected_ext_count", (uint64_t)affectedExts.size())
                .Int("new_ext_max", MaxNewExtCount())

                /* --- mặt nạ hợp lệ cho F12/F13 + trạng thái CoW --- */
                .UInt("cow_files", cowFiles)
                .UInt("cow_failed", cowFailed)
                .UInt("backup_entries", (uint64_t)entries.size())
                .Bool01("backup_frozen", backupFrozen)
                .Int("quota_tier", (int)quotaTier)
                .UInt("quota_used", quotaUsed)
                .Bool01("exited", exited)
                .End();
            return j.Get();
        }
    };

} // namespace rw