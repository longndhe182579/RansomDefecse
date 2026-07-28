/*
 * FeatureExport.h — Xuất feature ra CSV để train ML.
 *
 * ===========================================================================
 * NGUYÊN TẮC SỐ MỘT: KHÔNG ĐỤNG VÀO ĐƯỜNG NÓNG
 * ===========================================================================
 * Toàn bộ file này chỉ được gọi từ MaintenanceThread (tick 1 giây). Không có
 * hàm nào ở đây được phép gọi từ OnEvent, OnFirstTouch, hay bất kỳ chỗ nào
 * nằm trong ngân sách 200ms của driver.
 *
 * Và ngay cả trong MaintenanceThread: CHỤP dữ liệu dưới lock thật nhanh, rồi
 * ĐỊNH DẠNG + GHI FILE ngoài lock. Giữ g_Mtx trong lúc ghi đĩa là cách chắc
 * chắn nhất để làm nghẽn cả hệ thống.
 *
 * ===========================================================================
 * GHI CHÚ VỀ DỮ LIỆU — đọc trước khi train
 * ===========================================================================
 *  1. Tách train/test THEO run_id, không phải theo dòng. Hai snapshot cách
 *     nhau 1 giây của cùng một lần chạy gần như giống hệt nhau; để chúng rơi
 *     vào cả train lẫn test thì accuracy sẽ đẹp một cách vô nghĩa.
 *
 *  2. Nhãn ở mức RUN, không phải mức dòng. Trong một lần chạy mẫu độc hại vẫn
 *     có hàng chục tiến trình sạch. Dùng cột is_target (khớp --target-name)
 *     để lọc, hoặc tự lọc theo image_sha256 trong pandas.
 *
 *  3. Ô TRỐNG = NaN, không phải 0. daa_min trống nghĩa là chưa từng tính được
 *     DAA cho tiến trình đó, khác hẳn với "đã tính và ra 0". Tương tự
 *     entropy_delta_mean. Đừng fillna(0) một cách máy móc.
 *
 *  4. f1..f14 là LATCH (đã từng bật), f9_now..f14_now là trạng thái trong cửa
 *     sổ 30 giây hiện tại. Có cả hai để lúc train thử được cả hai giả thuyết.
 *
 *  5. cow_files / cow_failed là MẶT NẠ HỢP LỆ cho f12/f13. Không có backup
 *     hoặc pre-metadata thì hai feature đó không thể bật, nên f13=0 lúc
 *     cow_files=0 mang nghĩa khác hẳn f13=0 lúc cow_files=50.
 * ===========================================================================
 */
#pragma once

#include "Util.h"
#include "Config.h"
#include "Features.h"

#include <map>
#include <mutex>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdint>
#include <io.h>
#include <fcntl.h>

namespace rw {

    class FeatureExporter {
    public:
        /* runId rỗng -> tự sinh theo thời gian. targetName: chuỗi con của tên
           file thực thi mẫu đang test (không phân biệt hoa thường), dùng để
           đánh dấu cột is_target. */
        bool Init(const std::wstring& csvPath,
            const std::string& runId,
            const std::string& label,
            const std::wstring& targetName)
        {
            std::lock_guard<std::mutex> lk(mtx_);

            path_ = csvPath;
            label_ = label.empty() ? "unknown" : label;
            target_ = ToLower(targetName);

            if (runId.empty()) {
                char b[64];
                snprintf(b, sizeof(b), "run_%llu", (unsigned long long)UnixNow());
                runId_ = b;
            }
            else runId_ = runId;

            // File của run trước được đặt Read-only khi đóng. Gỡ cờ đó trước
            // khi append run mới; trong lúc tiến trình đang chạy, khóa chia sẻ
            // bên dưới mới là lớp bảo vệ chính.
            DWORD attrs = GetFileAttributesW(path_.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES &&
                (attrs & FILE_ATTRIBUTE_READONLY)) {
                SetFileAttributesW(path_.c_str(),
                    attrs & ~FILE_ATTRIBUTE_READONLY);
            }

            // Mở bằng WinAPI để kiểm soát share mode trên cả x64 và ARM64.
            // Chỉ chia sẻ quyền đọc: tiến trình khác không thể mở để ghi,
            // xóa hoặc đổi tên file trong khi exporter đang giữ handle.
            HANDLE h = CreateFileW(
                path_.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ,
                nullptr,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);

            if (h == INVALID_HANDLE_VALUE) {
                LOG_E("[CSV] CreateFileW that bai: %s (err=%lu)",
                    ws2s(path_).c_str(), GetLastError());
                return false;
            }

            LARGE_INTEGER fileSize{};
            const bool isNew = GetFileSizeEx(h, &fileSize) && fileSize.QuadPart == 0;

            LARGE_INTEGER zero{};
            if (!SetFilePointerEx(h, zero, nullptr, FILE_END)) {
                LOG_E("[CSV] Khong seek duoc cuoi file: %s (err=%lu)",
                    ws2s(path_).c_str(), GetLastError());
                CloseHandle(h);
                return false;
            }

            // Chuyển HANDLE sang FILE* để giữ nguyên phần fwrite/fflush hiện có.
            // Sau khi chuyển thành công, fclose(f_) sẽ đóng cả descriptor và HANDLE.
            int fd = _open_osfhandle(
                reinterpret_cast<intptr_t>(h),
                _O_APPEND | _O_BINARY);
            if (fd == -1) {
                LOG_E("[CSV] _open_osfhandle that bai: %s",
                    ws2s(path_).c_str());
                CloseHandle(h);
                return false;
            }

            f_ = _fdopen(fd, "ab");
            if (!f_) {
                LOG_E("[CSV] _fdopen that bai: %s", ws2s(path_).c_str());
                _close(fd); // đồng thời đóng HANDLE đã chuyển quyền sở hữu
                return false;
            }

            if (isNew) {
                std::string h = Header();
                fwrite(h.data(), 1, h.size(), f_);
                fflush(f_);
                headerFields_ = CountFields(h);
            }
            else {
                headerFields_ = CountFields(Header());
            }

            LOG_I("[CSV] Ghi feature vao %s  run_id=%s  label=%s%s",
                ws2s(path_).c_str(), runId_.c_str(), label_.c_str(),
                target_.empty() ? "" : "  (co --target-name)");
            return true;
        }

        bool Enabled() const { return f_ != nullptr; }
        const std::string& RunId() const { return runId_; }
        uint64_t RowsWritten() const { return rows_; }

        /*
         * Snapshot — gọi mỗi tick từ MaintenanceThread.
         *
         * quietStride: tiến trình "im lặng" (score 0, không I/O) chỉ lấy mẫu
         * mỗi quietStride lần gọi, để CSV không phình vì vài chục tiến trình
         * hệ thống ngồi yên. Đặt 1 nếu muốn lấy hết.
         */
        void Snapshot(std::mutex& collectorMtx,
            std::map<DWORD, ProcessFeature>& collector,
            int quietStride = 10)
        {
            if (!f_) return;
            uint64_t tick = ++tick_;

            /* ---- GIAI ĐOẠN 1: chụp dưới lock, KHÔNG format, KHÔNG ghi ---- */
            std::vector<Row> batch;
            {
                std::lock_guard<std::mutex> lk(collectorMtx);
                batch.reserve(collector.size());

                for (auto& kv : collector) {
                    ProcessFeature& pf = kv.second;

                    bool active = pf.totalScore > 0 || pf.ioOps.Count() > 0 ||
                        pf.dirEntries.Count() > 0 || pf.renames.Count() > 0;
                    if (!active && quietStride > 1 && (tick % (uint64_t)quietStride) != 0)
                        continue;

                    batch.push_back(Capture(kv.first, pf));
                }
            }

            /* ---- GIAI ĐOẠN 2: format + ghi, NGOÀI lock ---- */
            std::string out;
            out.reserve(batch.size() * 320);
            uint64_t now = UnixNow();
            for (const Row& r : batch) out += Format(r, now);

            if (out.empty()) return;

            std::lock_guard<std::mutex> lk(mtx_);
            if (!f_) return;
            fwrite(out.data(), 1, out.size(), f_);
            rows_ += batch.size();
            if (++flushCtr_ >= 10) { fflush(f_); flushCtr_ = 0; }
        }

        void Close() {
            std::lock_guard<std::mutex> lk(mtx_);
            if (f_) {
                fflush(f_);
                fclose(f_);
                f_ = nullptr;

                // Sau khi hoàn tất run, đặt Read-only để tránh ghi nhầm và
                // giảm khả năng một mẫu thông thường sửa file khi exporter
                // không còn giữ khóa. Đây là lớp phụ, không thay thế ACL/VM.
                DWORD attrs = GetFileAttributesW(path_.c_str());
                if (attrs != INVALID_FILE_ATTRIBUTES) {
                    if (!SetFileAttributesW(path_.c_str(),
                        attrs | FILE_ATTRIBUTE_READONLY)) {
                        LOG_W("[CSV] Khong dat duoc Read-only: %s (err=%lu)",
                            ws2s(path_).c_str(), GetLastError());
                    }
                }

                LOG_I("[CSV] Da ghi %llu dong vao %s (da khoa Read-only)",
                    rows_, ws2s(path_).c_str());
            }
        }

        ~FeatureExporter() { Close(); }

    private:
        /* Bản chụp POD — không giữ tham chiếu vào collector sau khi nhả lock */
        struct Row {
            DWORD    pid = 0, rootPid = 0;
            uint64_t startTime = 0, ageMs = 0;
            std::string imageName, imageSha;
            int      score = 0;
            bool     f[14]{};
            bool     now6[6]{};
            double   ioRate = 0, renRate = 0, dirRate = 0;
            double   entMean = 0, entMax = 0, daaMin = 0;
            uint64_t entN = 0;
            size_t   extCount = 0;
            int      newExtMax = 0;
            uint64_t cowFiles = 0, cowFailed = 0, quotaUsed = 0;
            size_t   entries = 0;
            bool     frozen = false, exited = false;
            int      tier = 0;
            bool     isTarget = false;
        };

        Row Capture(DWORD pid, ProcessFeature& pf) {
            Row r;
            r.pid = pid;
            r.rootPid = pf.rootPid ? pf.rootPid : pid;
            r.startTime = pf.startTime;
            r.ageMs = pf.AgeMs();
            r.imageName = ws2s(GetFileNameOnly(pf.processImage));
            r.imageSha = pf.imageSha256;
            r.score = pf.totalScore;

            const Latch* L[14] = {
                &pf.f1_unsigned, &pf.f2_packed, &pf.f3_suspStrings,
                &pf.f4_honeyModified, &pf.f5_cryptoApi, &pf.f6_safeModeDisable,
                &pf.f7_shadowDeleted, &pf.f8_registryPersist, &pf.f9_dirEnum,
                &pf.f10_highIo, &pf.f11_extChanged, &pf.f12_fingerprintMismatch,
                &pf.f13_highEntropy, &pf.f14_daa
            };
            for (int i = 0; i < 14; i++) r.f[i] = L[i]->value;
            for (int i = 0; i < 6; i++) r.now6[i] = ActiveNow(*L[8 + i]);

            r.ioRate = pf.ioOps.Rate();
            r.renRate = pf.renames.Rate();
            r.dirRate = pf.dirEntries.Rate();
            r.entMean = pf.entropyDelta.Mean();
            r.entN = pf.entropyDelta.n;
            r.entMax = pf.entropyDeltaMax;
            r.daaMin = pf.daaMin;
            r.extCount = pf.affectedExts.size();
            r.newExtMax = pf.MaxNewExtCount();
            r.cowFiles = pf.cowFiles;
            r.cowFailed = pf.cowFailed;
            r.entries = pf.entries.size();
            r.quotaUsed = pf.quotaUsed;
            r.frozen = pf.backupFrozen;
            r.exited = pf.exited;
            r.tier = (int)pf.quotaTier;

            if (!target_.empty()) {
                std::wstring low = ToLower(pf.processImage);
                r.isTarget = low.find(target_) != std::wstring::npos;
            }
            return r;
        }

        static std::string Header() {
            return
                "run_id,label,is_target,ts_unix,root_pid,pid,process_start_time,"
                "image_name,image_sha256,t_ms,total_score,"
                "f1_unsigned,f2_packed,f3_susp_strings,f4_honey,f5_crypto_api,"
                "f6_safe_mode,f7_shadow_del,f8_reg_persist,f9_dir_enum,f10_high_io,"
                "f11_ext_changed,f12_fingerprint,f13_entropy,f14_daa,"
                "f9_now,f10_now,f11_now,f12_now,f13_now,f14_now,"
                "io_rate,rename_rate,dirent_rate,"
                "entropy_delta_mean,entropy_delta_max,entropy_samples,daa_min,"
                "affected_ext_count,new_ext_max,"
                "cow_files,cow_failed,backup_entries,backup_frozen,quota_tier,"
                "quota_used,exited\n";
        }

        std::string Format(const Row& r, uint64_t now) {
            char b[1024];
            std::string s;

            s += Esc(runId_);          s += ',';
            s += Esc(label_);          s += ',';
            s += r.isTarget ? "1," : "0,";

            snprintf(b, sizeof(b), "%llu,%lu,%lu,%llu,",
                (unsigned long long)now, r.rootPid, r.pid,
                (unsigned long long)r.startTime);
            s += b;

            s += Esc(r.imageName);     s += ',';
            s += Esc(r.imageSha);      s += ',';

            snprintf(b, sizeof(b), "%llu,%d,", (unsigned long long)r.ageMs, r.score);
            s += b;

            for (int i = 0; i < 14; i++) { s += r.f[i] ? '1' : '0'; s += ','; }
            for (int i = 0; i < 6; i++) { s += r.now6[i] ? '1' : '0'; s += ','; }

            snprintf(b, sizeof(b), "%.4f,%.4f,%.4f,", r.ioRate, r.renRate, r.dirRate);
            s += b;

            /* entropy_delta_mean: trống nếu chưa có mẫu nào -> NaN, khong phai 0 */
            if (r.entN == 0) s += ',';
            else { snprintf(b, sizeof(b), "%.4f,", r.entMean); s += b; }

            snprintf(b, sizeof(b), "%.4f,%llu,", r.entMax, (unsigned long long)r.entN);
            s += b;

            /* daa_min: 9999 la sentinel "chua tinh duoc" -> de trong */
            if (r.daaMin >= 9998.0) s += ',';
            else { snprintf(b, sizeof(b), "%.4f,", r.daaMin); s += b; }

            snprintf(b, sizeof(b), "%zu,%d,%llu,%llu,%zu,%d,%d,%llu,%d\n",
                r.extCount, r.newExtMax,
                (unsigned long long)r.cowFiles, (unsigned long long)r.cowFailed,
                r.entries, r.frozen ? 1 : 0, r.tier,
                (unsigned long long)r.quotaUsed, r.exited ? 1 : 0);
            s += b;

            if (headerFields_ && CountFields(s) != headerFields_) {
                LogThrottledMismatch(CountFields(s));
            }
            return s;
        }

        void LogThrottledMismatch(size_t got) {
            if (mismatchLogged_) return;
            mismatchLogged_ = true;
            LOG_E("[CSV] SO COT KHONG KHOP: header=%zu row=%zu. "
                "Sua Header() va Format() cho khop roi xoa file CSV cu.",
                headerFields_, got);
        }

        static size_t CountFields(const std::string& line) {
            size_t n = 1; bool q = false;
            for (char c : line) {
                if (c == '"') q = !q;
                else if (c == ',' && !q) n++;
                else if (c == '\n' && !q) break;
            }
            return n;
        }

        static std::string Esc(const std::string& v) {
            bool need = v.find_first_of(",\"\n\r") != std::string::npos;
            if (!need) return v;
            std::string o = "\"";
            for (char c : v) { if (c == '"') o += '"'; o += c; }
            o += '"';
            return o;
        }

        std::mutex   mtx_;
        FILE* f_ = nullptr;
        std::wstring path_;
        std::string  runId_, label_;
        std::wstring target_;
        uint64_t     rows_ = 0;
        uint64_t     tick_ = 0;
        int          flushCtr_ = 0;
        size_t       headerFields_ = 0;
        bool         mismatchLogged_ = false;
    };

} // namespace rw