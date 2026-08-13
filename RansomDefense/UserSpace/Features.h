/*
 * Features.h — Cấu trúc dữ liệu đặc trưng.
 *
 * Nguyên tắc thiết kế:
 *   - Điểm chỉ tăng, không bao giờ giảm (Latch một chiều, không decay).
 *   - Đếm theo TỐC ĐỘ (SlidingCounter) thay vì tổng tích luỹ vô hạn, kể cả
 *     cho newExtHistogram — một map cộng dồn mãi mãi sẽ khiến tiến trình
 *     benign chạy đủ lâu cũng vượt ngưỡng.
 *   - Lưu lại giá trị liên tục (daaMin, entropyDeltaMax...) thay vì chỉ giữ
 *     boolean sau khi nhị phân hoá: 14 cột boolean chỉ có 2^14 điểm và tương
 *     quan mạnh với nhau — quá mỏng để train tốt.
 *   - cowFiles/cowFailed bắt buộc có trong dataset: F12/F13 chỉ bật được khi
 *     tồn tại metadata trước-ghi, nên F13=0 mang hai nghĩa khác nhau ("không
 *     mã hoá" và "không có gì để so sánh") — thiếu cột này model sẽ học nhầm
 *     F13 thành "CoW có chạy không".
 *   - MLState cho phép gọi lại ML khi có bằng chứng mới, thay vì cờ một
 *     chiều "đã gọi rồi thì thôi".
 */
#pragma once

#include "Util.h"
#include "Config.h"
#include <deque>
#include <set>

namespace rw {

    /*
     * LATCH — cờ một chiều, chỉ bật không tắt.
     *
     * Không decay: nếu một cờ tự hết hạn sau WINDOW_SEC, tổng điểm có thể
     * tụt xuống dưới ngưỡng kill trong lúc ransomware tạm dừng hoạt động
     * (I/O) giữa hai giai đoạn tấn công, khiến hệ thống bỏ lỡ điểm kill.
     * Latch một chiều đảm bảo bằng chứng đã thấy không bao giờ bị quên.
     *
     * Muốn biết "feature có đang active trong cửa sổ hiện tại không" thì dùng
     * ActiveNow() — dựa vào setAt, không đụng vào giá trị latch.
     */
    struct Latch {
        bool      value = false;
        TimePoint setAt{};

        void Set() {
            if (!value) { value = true; setAt = Clock::now(); }
        }
        explicit operator bool() const { return value; }
    };

    /* Feature có bật trong cửa sổ WINDOW_SEC gần nhất không.
       Chỉ dùng để export cho ML — không dùng để chấm điểm/trigger. */
    inline bool ActiveNow(const Latch& l) {
        if (!l.value) return false;
        return std::chrono::duration_cast<std::chrono::seconds>(
            Clock::now() - l.setAt).count() <= cfg::WINDOW_SEC;
    }

    /*
     * SLIDING COUNTER — đo tốc độ (event trong cửa sổ WINDOW_SEC gần nhất),
     * không phải tổng tích luỹ. Đếm tích luỹ khiến tiến trình sạch (7-Zip,
     * indexer...) chạy đủ lâu cũng vượt ngưỡng; ransomware khác biệt ở mật
     * độ thao tác, không phải tổng số.
     */
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

    /* ML STATE — không phải cờ một chiều: cho gọi lại ML khi có bằng chứng
       mới, thay vì một lần gọi sai là sai vĩnh viễn. */
    enum class Verdict { Unknown, Benign, Malware };

    struct MLState {
        int       callCount = 0;
        TimePoint lastCall{};
        Verdict   lastVerdict = Verdict::Unknown;
        int       scoreAtLastCall = 0;
        double    ioRateAtLastCall = 0;
        bool      vectorDirty = false;

        /*
         * inFlight — chống stampede: nếu MaybeCallML chỉ kiểm tra
         * ShouldCallML() rồi spawn thread, và lastCall chỉ được cập nhật bên
         * trong thread đó, nhiều event ập tới cùng lúc sẽ đều thấy điều kiện
         * còn thoả và cùng spawn — nhiều luồng ghi/restore đồng thời vào
         * cùng một đích sẽ phá lẫn nhau. Phải "giành quyền" ngay tại điểm
         * kiểm tra, dưới cùng một lock.
         */
        bool      inFlight = false;

        /* Đã xử lý phán quyết MALWARE rồi -> không kill/restore lần hai */
        bool      verdictHandled = false;
    };

    /* ---- Quota tier ---- */
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

    /* ---- Backup entry: một dòng trong manifest ---- */
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

        /* Giá trị liên tục — giữ lại thay vì vứt sau khi nhị phân hoá */
        double       daaMin = 9999.0;   // F14: DAA thấp nhất từng thấy
        double       entropyDeltaMax = 0.0;     // F13: dH lớn nhất từng thấy

        /* CoW có chạy được cho tiến trình này không */
        uint64_t     cowFiles = 0;      // số file pend đã xử lý xong
        uint64_t     cowFailed = 0;     // trong đó bao nhiêu KHÔNG cứu được

        /* Đuôi file mới xuất hiện hàng loạt (F11) — SlidingCounter theo cửa
           sổ, không phải int tích luỹ vô hạn */
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

        /* Số lần xuất hiện của đuôi mới "nóng" nhất trong cửa sổ.
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

            /*
             * Theo dõi thêm 90 giây sau khi ML phán benign, gọi lại cách đều
             * mỗi 30 giây (lần 2 ở +30s, lần 3 ở +60s, lần 4 ở +90s tính từ
             * lần gọi đầu) để backup_entries và entropy_delta_mean kịp cập
             * nhật trước khi phán quyết — ở lần gọi đầu (t~20s) CoW có thể
             * chưa kịp backup đủ file nên các feature đó vẫn bằng 0. Phải
             * kiểm tra trước if(!vectorDirty): sau lần gọi ML đầu tiên, F1-F14
             * thường đã bật hết nên Raise() không còn cơ hội set dirty lại,
             * nếu để vectorDirty chặn thì lịch retry này không bao giờ chạy.
             */
            if (ml.lastVerdict == Verdict::Benign && ml.callCount < cfg::ML_MAX_SCHEDULED_CALLS) {
                if (sinceLast >= cfg::ML_RETRY_INTERVAL_MS) return true;
            }

            if (!ml.vectorDirty) return false;

            /* Gọi lại khi có bằng chứng mới so với lần phán quyết trước */
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

           "pid" giữ nguyên nghĩa cũ (thực chất là rootPid) để không phá
           tương thích với Flask hiện có; root_pid/process_start_time/
           total_score gửi kèm riêng để phục vụ truy vết. */
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
                .UInt("affected_ext_count",(uint64_t)affectedExts.size())
                .Int("new_ext_max",        MaxNewExtCount())
                .UInt("backup_entries",    (uint64_t)entries.size())
                .UInt("t_ms",              AgeMs())
                .End();
            return j.Get();
        }

        /*
           ToTrainingJson — bản ghi dùng để train, không phải để suy luận lúc
           chạy. Khác ToJson() ở ba điểm, và cả ba đều cần thiết:

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
           để tách train/test theo phiên — nếu hai snapshot cách nhau 1 giây
           của cùng một lần chạy rơi vào cả train lẫn test thì accuracy sẽ
           đẹp một cách vô nghĩa. */
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