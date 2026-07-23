/*
 * Util.h — Tiện ích dùng chung. Header-only.
 *   - Logger thread-safe (v3.0 dùng std::cout đa luồng -> log xen kẽ)
 *   - Entropy Shannon
 *   - SHA-256 qua BCrypt (không cần thư viện ngoài)
 *   - Chuyển kernel path -> DOS path
 *   - JSON tối giản (writer + parser) — tránh phụ thuộc nlohmann
 */
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <shlobj.h>
#include <knownfolders.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <cmath>
#include <cstdio>
#include <cstdarg>
#include <algorithm>
#include <filesystem>
#include <chrono>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "psapi.lib")

namespace rw {

    namespace fs = std::filesystem;
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    /* ======================================================================
       CHUYỂN ĐỔI CHUỖI
       ====================================================================== */
    inline std::string ws2s(const std::wstring& ws) {
        if (ws.empty()) return {};
        int sz = WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(),
            nullptr, 0, nullptr, nullptr);
        std::string out(sz, 0);
        WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), out.data(), sz, nullptr, nullptr);
        return out;
    }
    inline std::wstring s2ws(const std::string& s) {
        if (s.empty()) return {};
        int sz = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
        std::wstring out(sz, 0);
        MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), sz);
        return out;
    }
    inline std::wstring ToLower(std::wstring s) {
        std::transform(s.begin(), s.end(), s.begin(), ::towlower);
        return s;
    }
    inline std::string ToLowerA(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)::tolower(c); });
        return s;
    }

    /* ======================================================================
       LOGGER — thread-safe
       ====================================================================== */
    enum class LogLevel { Debug, Info, Warn, Error, Alert };

    /* ======================================================================
       LOGGER  v4.5
       ======================================================================
       [FIX 19] BA VẤN ĐỀ CỦA BẢN CŨ:

       1. min_ KHÔNG BAO GIỜ ĐƯỢC KIỂM TRA trong Log() -> SetMinLevel() vô
          tác dụng, mọi dòng DEBUG đều in ra console.

       2. Không tách mức console và file. Console cần gọn để người dùng theo
          dõi; file cần đầy đủ để phân tích sau.

       3. Không gộp dòng lặp. Đo được: 109 dòng "Honey bi cham boi tien trinh
          whitelist" liên tiếp khi Search Indexer quét 110 honey file mới tạo.
          Cộng thêm hàng trăm dòng [PROC] ... -> tra cay.

       GIẢI PHÁP:
         - ConsoleLevel mặc định Info, FileLevel mặc định Debug
           -> console sạch, file vẫn đủ dữ liệu
         - Gộp dòng LẶP LIÊN TIẾP giống hệt nhau thành 1 dòng + "(x N)"
         - LOG_T(ms, ...) cho thông điệp biết trước là ồn
       ====================================================================== */
    class Logger {
    public:
        static Logger& I() { static Logger l; return l; }

        /* Gọi một lần lúc khởi động để bật ghi file */
        void SetLogFile(const std::wstring& path) {
            std::lock_guard<std::mutex> lock(m_);
            if (f_) { fclose(f_); f_ = nullptr; }
            /* Dùng "a" thuần — không kèm ccs= để tránh CRT assertion trên Debug ARM64.
             * Log ghi UTF-8 thủ công vì printf đã SetConsoleOutputCP(CP_UTF8). */
            _wfopen_s(&f_, path.c_str(), L"a");
        }

        void Log(LogLevel lv, const char* fmt, ...) {
            /* Dưới cả hai ngưỡng -> khỏi format, tiết kiệm CPU trên đường nóng */
            if (lv < consoleLv_ && lv < fileLv_) return;

            char buf[2048];
            va_list ap; va_start(ap, fmt);
            vsnprintf(buf, sizeof(buf), fmt, ap);
            va_end(ap);

            std::lock_guard<std::mutex> lock(m_);

            /* ---- Gộp dòng lặp liên tiếp ---- */
            if (lastMsg_ == buf && lastLv_ == lv) {
                repeat_++;
                return;                       /* nuốt, đếm lại */
            }
            FlushRepeat();                    /* xả bộ đếm của thông điệp trước */
            lastMsg_ = buf;
            lastLv_ = lv;

            Emit(lv, buf);
        }

        /*
         * LogThrottled — chỉ in tối đa 1 lần mỗi periodMs cho cùng một 'key'.
         * Dùng cho thông điệp biết trước là ồn nhưng vẫn muốn thấy thỉnh thoảng.
         * key nên là chuỗi hằng (địa chỉ tĩnh), ví dụ __FUNCTION__ hoặc nhãn riêng.
         */
        void LogThrottled(LogLevel lv, const char* key, unsigned periodMs,
            const char* fmt, ...) {
            if (lv < consoleLv_ && lv < fileLv_) return;

            uint64_t now = GetTickCount64();
            {
                std::lock_guard<std::mutex> lock(m_);
                auto it = throttle_.find(key);
                if (it != throttle_.end()) {
                    if (now - it->second.last < periodMs) { it->second.skipped++; return; }
                    /* Đã qua chu kỳ — báo luôn số lần bị nuốt */
                    if (it->second.skipped > 0) {
                        char note[128];
                        snprintf(note, sizeof(note),
                            "  (da bo qua %llu dong tuong tu trong %ums qua)",
                            it->second.skipped, periodMs);
                        FlushRepeat();
                        Emit(LogLevel::Debug, note);
                        it->second.skipped = 0;
                    }
                    it->second.last = now;
                }
                else {
                    throttle_[key] = { now, 0 };
                }
            }

            char buf[2048];
            va_list ap; va_start(ap, fmt);
            vsnprintf(buf, sizeof(buf), fmt, ap);
            va_end(ap);

            std::lock_guard<std::mutex> lock(m_);
            FlushRepeat();
            lastMsg_ = buf;
            lastLv_ = lv;
            Emit(lv, buf);
        }

        /* Mặc định: console gọn (Info), file đầy đủ (Debug).
           Muốn console im hơn nữa: SetConsoleLevel(LogLevel::Warn) */
        void SetConsoleLevel(LogLevel lv) { consoleLv_ = lv; }
        void SetFileLevel(LogLevel lv) { fileLv_ = lv; }

        /* Giữ tương thích với code cũ — đặt cả hai */
        void SetMinLevel(LogLevel lv) { consoleLv_ = lv; fileLv_ = lv; }

        /* Gọi trước khi thoát để không mất dòng lặp cuối */
        void Flush() {
            std::lock_guard<std::mutex> lock(m_);
            FlushRepeat();
            if (f_) fflush(f_);
        }

    private:
        struct ThrottleState { uint64_t last; uint64_t skipped; };

        std::mutex  m_;
        LogLevel    consoleLv_ = LogLevel::Info;    /* console: gọn */
        LogLevel    fileLv_ = LogLevel::Debug;   /* file: đầy đủ */
        FILE* f_ = nullptr;

        std::string lastMsg_;
        LogLevel    lastLv_ = LogLevel::Info;
        uint64_t    repeat_ = 0;
        std::map<std::string, ThrottleState> throttle_;

        /* Gọi KHI ĐANG GIỮ m_ */
        void FlushRepeat() {
            if (repeat_ == 0) return;
            char note[160];
            snprintf(note, sizeof(note), "  ^ dong tren lap lai them %llu lan", repeat_);
            uint64_t n = repeat_;
            repeat_ = 0;
            (void)n;
            EmitRaw(lastLv_, note);
        }

        /* Gọi KHI ĐANG GIỮ m_ */
        void Emit(LogLevel lv, const char* msg) { EmitRaw(lv, msg); }

        void EmitRaw(LogLevel lv, const char* msg) {
            auto stamp = Stamp();

            if (lv >= consoleLv_) {
                SetColor(lv);
                printf("[%s] %s %s\n", stamp.c_str(), Tag(lv), msg);
                SetColor(LogLevel::Info);
                fflush(stdout);
            }
            if (f_ && lv >= fileLv_) {
                fprintf(f_, "[%s] %s %s\n", stamp.c_str(), Tag(lv), msg);
                /* Chỉ flush khi WARN trở lên để đảm bảo log quan trọng không mất */
                if (lv >= LogLevel::Warn) fflush(f_);
            }
        }

        static const char* Tag(LogLevel lv) {
            switch (lv) {
            case LogLevel::Debug: return "[DBG ]";
            case LogLevel::Info:  return "[INFO]";
            case LogLevel::Warn:  return "[WARN]";
            case LogLevel::Error: return "[ERR ]";
            case LogLevel::Alert: return "[!!!!]";
            }
            return "[????]";
        }
        static void SetColor(LogLevel lv) {
            HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
            WORD c = 7;
            switch (lv) {
            case LogLevel::Debug: c = 8;  break;
            case LogLevel::Info:  c = 7;  break;
            case LogLevel::Warn:  c = 14; break;
            case LogLevel::Error: c = 12; break;
            case LogLevel::Alert: c = 79; break;
            }
            SetConsoleTextAttribute(h, c);
        }
        static std::string Stamp() {
            SYSTEMTIME st; GetLocalTime(&st);
            char b[32];
            snprintf(b, sizeof(b), "%02d:%02d:%02d.%03d", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
            return b;
        }
    };

#define LOG_D(...) rw::Logger::I().Log(rw::LogLevel::Debug, __VA_ARGS__)
#define LOG_I(...) rw::Logger::I().Log(rw::LogLevel::Info , __VA_ARGS__)
#define LOG_W(...) rw::Logger::I().Log(rw::LogLevel::Warn , __VA_ARGS__)
#define LOG_E(...) rw::Logger::I().Log(rw::LogLevel::Error, __VA_ARGS__)
#define LOG_A(...) rw::Logger::I().Log(rw::LogLevel::Alert, __VA_ARGS__)

    /* Throttle: tối đa 1 dòng mỗi <ms> cho mỗi <key>. Dùng cho chỗ biết trước là ồn. */
#define LOG_TD(key, ms, ...) rw::Logger::I().LogThrottled(rw::LogLevel::Debug, key, ms, __VA_ARGS__)
#define LOG_TI(key, ms, ...) rw::Logger::I().LogThrottled(rw::LogLevel::Info , key, ms, __VA_ARGS__)

    /* ======================================================================
       ENTROPY
       ====================================================================== */
    inline double CalculateEntropy(const uint8_t* data, size_t size) {
        if (size == 0) return 0.0;
        size_t cnt[256] = {};
        for (size_t i = 0; i < size; ++i) cnt[data[i]]++;
        double h = 0.0;
        for (int i = 0; i < 256; ++i) {
            if (!cnt[i]) continue;
            double p = (double)cnt[i] / (double)size;
            h -= p * std::log2(p);
        }
        return h;
    }

    /*
     * Đọc N byte đầu file. MẶC ĐỊNH 4096.
     *
     * LỖI v3.0: đọc magic[16] rồi tính entropy và so > 7.0.
     * Entropy của 16 byte tối đa là log2(16) = 4.0 -> điều kiện KHÔNG BAO GIỜ đúng.
     * Đây là dead code toán học.
     */
    inline std::vector<uint8_t> ReadHead(const std::wstring& path, size_t n = 4096) {
        std::vector<uint8_t> buf;
        HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return buf;
        buf.resize(n);
        DWORD got = 0;
        if (!ReadFile(h, buf.data(), (DWORD)n, &got, nullptr)) got = 0;
        CloseHandle(h);
        buf.resize(got);
        return buf;
    }

    inline double FileEntropy(const std::wstring& path, size_t n = 4096) {
        auto b = ReadHead(path, n);
        return b.empty() ? 0.0 : CalculateEntropy(b.data(), b.size());
    }

    /* 16 byte đầu dạng hex — dùng cho F12 (so magic_before vs magic_now) */
    inline std::string FileMagicHex(const std::wstring& path) {
        auto b = ReadHead(path, 16);
        std::ostringstream os;
        for (uint8_t c : b) os << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        return os.str();
    }


    /* ======================================================================
       DIFFERENTIAL AREA ANALYSIS (DAA)
       Davies et al., "Differential Area Analysis for Ransomware Attack
       Detection within Mixed File Datasets", arXiv:2106.14418, 2021.

       Đo độ tương đồng giữa entropy curve của header file với đường chuẩn
       của dữ liệu ngẫu nhiên thuần túy (random data reference curve).

       Phương pháp:
         1. Đọc 256 byte đầu file
         2. Tính Shannon entropy tại 32 điểm (8,16,24...256 byte)
         3. Tính diện tích chênh lệch giữa curve file và random curve
            bằng Composite Trapezoidal Rule
         4. Diện tích nhỏ → gần random → khả năng cao bị mã hoá

       Ưu điểm so với F13 (ΔH):
         - Không cần CoW baseline (entropy_before)
         - Phân biệt được file nén vs file mã hoá (ZIP header thấp, AES header cao)
         - Bắt được file mới tạo ra (Cerber, LockBit) ngay lập tức
         - Chỉ đọc 256 byte → nhanh hơn 1000x so với full-file entropy

       Ngưỡng 56 Bit-Bytes tại 256 byte header cho accuracy 99.96%
       (Davies et al. Table 7)
       ====================================================================== */

       /*
        * kRandCurve — entropy của file chứa pure random bytes tại 8..256 byte.
        * Tính trước từ os.urandom(1000 files) theo Algorithm 1 của bài báo.
        * Index i → entropy tại (i+1)*8 byte.
        */
    inline const double* GetRandCurve() {
        static const double kRandCurve[32] = {
            2.976, 3.941, 4.496, 4.878, 5.171, 5.418, 5.633, 5.820,
            5.985, 6.130, 6.259, 6.373, 6.475, 6.567, 6.650, 6.724,
            6.791, 6.852, 6.907, 6.957, 7.003, 7.045, 7.084, 7.119,
            7.152, 7.182, 7.210, 7.236, 7.261, 7.283, 7.305, 7.325
        };
        return kRandCurve;
    }

    /*
     * DifferentialAreaAnalysis — trả về diện tích Bit-Bytes.
     * Giá trị thấp → header ngẫu nhiên → khả năng cao bị mã hoá bởi ransomware.
     * Ngưỡng khuyến nghị: < 56 Bit-Bytes (Davies et al., header 256 byte).
     * Trả về 9999.0 nếu không đọc được file.
     */
    inline double DifferentialAreaAnalysis(const std::wstring& path) {
        auto buf = ReadHead(path, 256);
        if (buf.size() < 32) return 9999.0;   /* quá ngắn để phân tích */

        const double* kRand = GetRandCurve();

        /* Tính entropy tại 32 điểm: 8, 16, 24 ... 256 byte */
        double fileCurve[32] = {};
        for (int i = 0; i < 32; i++) {
            size_t len = (size_t)(i + 1) * 8;
            if (len > buf.size()) len = buf.size();
            fileCurve[i] = CalculateEntropy(buf.data(), len);
        }

        /* Curve chênh lệch = random - file */
        double diff[32] = {};
        for (int i = 0; i < 32; i++)
            diff[i] = kRand[i] - fileCurve[i];

        /*
         * Composite Trapezoidal Rule với h=8 (bước đều):
         * I = h/2 * [diff[0] + 2*Σdiff[1..30] + diff[31]]
         */
        double area = diff[0] + diff[31];
        for (int i = 1; i < 31; i++) area += 2.0 * diff[i];
        area *= 4.0;   /* h/2 = 8/2 = 4 */

        /* Lấy giá trị tuyệt đối — diện tích luôn dương */
        return area < 0 ? -area : area;
    }

    /* ======================================================================
       SHA-256 qua BCrypt
       ====================================================================== */
    inline std::string BytesToHex(const uint8_t* p, size_t n) {
        static const char* k = "0123456789abcdef";
        std::string s; s.reserve(n * 2);
        for (size_t i = 0; i < n; i++) { s += k[p[i] >> 4]; s += k[p[i] & 0xF]; }
        return s;
    }

    inline std::string Sha256File(const std::wstring& path) {
        HANDLE hf = CreateFileW(path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (hf == INVALID_HANDLE_VALUE) return {};

        BCRYPT_ALG_HANDLE alg = nullptr; BCRYPT_HASH_HANDLE hash = nullptr;
        std::string result;
        do {
            if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) break;
            DWORD objLen = 0, cb = 0;
            if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cb, 0) != 0) break;
            std::vector<uint8_t> obj(objLen);
            if (BCryptCreateHash(alg, &hash, obj.data(), objLen, nullptr, 0, 0) != 0) break;

            std::vector<uint8_t> buf(64 * 1024);
            DWORD got = 0;
            while (ReadFile(hf, buf.data(), (DWORD)buf.size(), &got, nullptr) && got > 0)
                BCryptHashData(hash, buf.data(), got, 0);

            uint8_t digest[32];
            if (BCryptFinishHash(hash, digest, sizeof(digest), 0) != 0) break;
            result = BytesToHex(digest, sizeof(digest));
        } while (false);

        if (hash) BCryptDestroyHash(hash);
        if (alg)  BCryptCloseAlgorithmProvider(alg, 0);
        CloseHandle(hf);
        return result;
    }

    /* ======================================================================
       ĐƯỜNG DẪN
       ====================================================================== */
    inline std::wstring GetKnownFolder(REFKNOWNFOLDERID id) {
        PWSTR p = nullptr; std::wstring r;
        if (SUCCEEDED(SHGetKnownFolderPath(id, 0, nullptr, &p))) { r = p; CoTaskMemFree(p); }
        return r;
    }
    inline std::wstring Desktop() { return GetKnownFolder(FOLDERID_Desktop); }
    inline std::wstring Downloads() { return GetKnownFolder(FOLDERID_Downloads); }
    inline std::wstring Documents() { return GetKnownFolder(FOLDERID_Documents); }
    inline std::wstring Pictures() { return GetKnownFolder(FOLDERID_Pictures); }

    /* \Device\HarddiskVolume3\Users\x\a.txt  ->  C:\Users\x\a.txt */
    inline std::wstring NormalizeKernelPath(const std::wstring& kp) {
        if (kp.rfind(L"\\Device\\", 0) != 0) return kp;

        wchar_t drives[512] = {};
        if (!GetLogicalDriveStringsW(511, drives)) return kp;

        for (wchar_t* p = drives; *p; p += wcslen(p) + 1) {
            wchar_t letter[3] = { p[0], L':', L'\0' };
            wchar_t dev[MAX_PATH] = {};
            if (!QueryDosDeviceW(letter, dev, MAX_PATH)) continue;
            std::wstring d(dev);
            if (kp.size() > d.size() && ToLower(kp.substr(0, d.size())) == ToLower(d))
                return std::wstring(letter) + kp.substr(d.size());
        }
        return kp;
    }

    inline std::wstring GetExtension(const std::wstring& path) {
        size_t slash = path.find_last_of(L"\\/");
        size_t dot = path.find_last_of(L'.');
        if (dot == std::wstring::npos) return {};
        if (slash != std::wstring::npos && dot < slash) return {};
        return ToLower(path.substr(dot));
    }
    inline std::wstring GetFileNameOnly(const std::wstring& path) {
        size_t p = path.find_last_of(L"\\/");
        return (p == std::wstring::npos) ? path : path.substr(p + 1);
    }

    /* ======================================================================
       TIẾN TRÌNH
       ====================================================================== */
    inline std::wstring GetProcessImagePath(DWORD pid) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h) return {};
        wchar_t buf[MAX_PATH * 2] = {};
        DWORD sz = MAX_PATH * 2;
        std::wstring r;
        if (QueryFullProcessImageNameW(h, 0, buf, &sz)) r = buf;
        CloseHandle(h);
        return r;
    }
    inline std::wstring GetProcessName(DWORD pid) {
        return ToLower(GetFileNameOnly(GetProcessImagePath(pid)));
    }
    inline bool IsProcessAlive(DWORD pid) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h) return false;
        DWORD code = 0;
        bool alive = GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
        CloseHandle(h);
        return alive;
    }

    /*
     * ProcessStartTime — chống PID reuse.
     * Windows CẤP LẠI PID. C:\RansomWall_Backup\4812\ của Word đã chết
     * có thể bị sample.exe kế thừa, kèm cả quota_used.
     * Cặp (PID, StartTime) là duy nhất trong toàn bộ vòng đời OS.
     */
    inline uint64_t GetProcessStartTime(DWORD pid) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h) return 0;
        FILETIME c{}, e{}, k{}, u{};
        uint64_t r = 0;
        if (GetProcessTimes(h, &c, &e, &k, &u))
            r = ((uint64_t)c.dwHighDateTime << 32) | c.dwLowDateTime;
        CloseHandle(h);
        return r;
    }

    /* Khoá định danh thư mục backup: "4812_133651847291840000" */
    inline std::wstring MakeProcKey(DWORD pid, uint64_t startTime) {
        return std::to_wstring(pid) + L"_" + std::to_wstring(startTime);
    }

    /* ======================================================================
       CÂY TIẾN TRÌNH — chống đệ quy vô hạn
       ======================================================================
       RansomWall spawn diec.exe -> driver báo "process create"
       -> RansomWall phân tích diec.exe -> spawn diec.exe ĐỂ QUÉT diec.exe
       -> driver báo "process create" -> ... VÒNG LẶP VÔ HẠN.

       conhost.exe cũng vậy: mỗi console app sinh một conhost.
       ====================================================================== */
    inline DWORD GetParentPID(DWORD pid) {
        DWORD parent = 0;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return 0;
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                if (pe.th32ProcessID == pid) { parent = pe.th32ParentProcessID; break; }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        return parent;
    }

    /* Tiến trình này có phải hậu duệ của CHÍNH RansomWall không? */
    inline bool IsDescendantOfSelf(DWORD pid, int maxDepth = 5) {
        DWORD self = GetCurrentProcessId();
        if (pid == self) return true;
        DWORD cur = pid;
        for (int i = 0; i < maxDepth; i++) {
            cur = GetParentPID(cur);
            if (cur == 0) return false;
            if (cur == self) return true;
        }
        return false;
    }

    /*
     * GetRootPidFromTree — leo ngược cây tiến trình Windows thật (qua Toolhelp),
     * tìm tổ tiên GẦN NHẤT có mặt trong tập watchedPids.
     *
     * Nếu watchedPids rỗng → trả về parent trực tiếp của pid (dùng cho
     * fallback khi g_Collector chưa có entry cho tiến trình cha).
     *
     * maxDepth = 8: đủ cho chuỗi ransomware -> cmd -> vssadmin (3 cấp).
     */
    inline DWORD GetRootPidFromTree(DWORD pid,
        const std::vector<DWORD>& watchedPids,
        int maxDepth = 8)
    {
        /* Xây map pid->parent một lần duy nhất từ snapshot */
        std::map<DWORD, DWORD> parentOf;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    parentOf[pe.th32ProcessID] = pe.th32ParentProcessID;
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }

        /* Khi watchedPids rỗng: trả về parent trực tiếp */
        if (watchedPids.empty()) {
            auto it = parentOf.find(pid);
            if (it != parentOf.end() && it->second > 4)
                return it->second;
            return 0;
        }

        /* Leo ngược, tìm tổ tiên gần nhất có trong watchedPids */
        DWORD best = 0;
        DWORD cur = pid;
        for (int depth = 0; depth < maxDepth; depth++) {
            auto it = parentOf.find(cur);
            if (it == parentOf.end() || it->second == 0 || it->second == cur) break;
            cur = it->second;
            for (DWORD w : watchedPids) {
                if (w == cur) { best = cur; break; }
            }
            if (best) break;
        }
        return best;
    }

    /* ======================================================================
       THỜI GIAN
       ====================================================================== */
    inline std::string IsoNow() {
        SYSTEMTIME st; GetSystemTime(&st);
        char b[40];
        snprintf(b, sizeof(b), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        return b;
    }
    inline uint64_t UnixNow() {
        return (uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    /* ======================================================================
       JSON TỐI GIẢN  (đủ cho manifest + ML payload, không cần thư viện ngoài)
       ====================================================================== */
    class JsonW {
    public:
        JsonW& Begin() { os_ << '{'; first_ = true; return *this; }
        JsonW& End() { os_ << '}'; return *this; }
        JsonW& BeginArr(const char* k) { Key(k); os_ << '['; first_ = true; return *this; }
        JsonW& EndArr() { os_ << ']'; first_ = false; return *this; }
        JsonW& BeginObj() { Comma(); os_ << '{'; first_ = true; return *this; }
        JsonW& EndObj() { os_ << '}'; first_ = false; return *this; }

        JsonW& Str(const char* k, const std::string& v) { Key(k); os_ << '"' << Esc(v) << '"'; return *this; }
        JsonW& Str(const char* k, const std::wstring& v) { return Str(k, ws2s(v)); }
        JsonW& Num(const char* k, double v) { Key(k); os_ << std::fixed << std::setprecision(4) << v; return *this; }
        JsonW& Int(const char* k, long long v) { Key(k); os_ << v; return *this; }
        JsonW& UInt(const char* k, uint64_t v) { Key(k); os_ << v; return *this; }
        JsonW& Bool01(const char* k, bool v) { Key(k); os_ << (v ? 1 : 0); return *this; }

        std::string Get() const { return os_.str(); }

    private:
        std::ostringstream os_;
        bool first_ = true;
        void Comma() { if (!first_) os_ << ','; first_ = false; }
        void Key(const char* k) { Comma(); os_ << '"' << k << "\":"; }
        static std::string Esc(const std::string& s) {
            std::string o; o.reserve(s.size() + 8);
            for (char c : s) {
                switch (c) {
                case '"':  o += "\\\""; break;
                case '\\': o += "\\\\"; break;
                case '\n': o += "\\n";  break;
                case '\r': o += "\\r";  break;
                case '\t': o += "\\t";  break;
                default:
                    if ((unsigned char)c < 0x20) { char b[8]; snprintf(b, 8, "\\u%04x", c); o += b; }
                    else o += c;
                }
            }
            return o;
        }
    };

    /* --- Parser tối giản: chỉ đủ đọc lại manifest do chính ta ghi --- */
    struct JsonVal;
    using JsonObj = std::map<std::string, JsonVal>;
    using JsonArr = std::vector<JsonVal>;

    struct JsonVal {
        enum Type { Null, Num, Str, Bool, Obj, Arr } type = Null;
        double      num = 0;
        std::string str;
        bool        bl = false;
        std::shared_ptr<JsonObj> obj;
        std::shared_ptr<JsonArr> arr;

        std::string  S(const char* k, const std::string& d = "") const {
            if (!obj) return d; auto i = obj->find(k);
            return (i != obj->end() && i->second.type == Str) ? i->second.str : d;
        }
        double       N(const char* k, double d = 0) const {
            if (!obj) return d; auto i = obj->find(k);
            return (i != obj->end() && i->second.type == Num) ? i->second.num : d;
        }
        const JsonArr* A(const char* k) const {
            if (!obj) return nullptr; auto i = obj->find(k);
            return (i != obj->end() && i->second.arr) ? i->second.arr.get() : nullptr;
        }
    };

    class JsonP {
    public:
        static bool Parse(const std::string& s, JsonVal& out) {
            JsonP p(s);
            p.Ws();
            bool ok = p.Value(out);
            return ok;
        }
    private:
        const std::string& s_; size_t i_ = 0;
        explicit JsonP(const std::string& s) : s_(s) {}
        void Ws() { while (i_ < s_.size() && isspace((unsigned char)s_[i_])) i_++; }
        bool Lit(const char* l) {
            size_t n = strlen(l);
            if (s_.compare(i_, n, l) != 0) return false;
            i_ += n; return true;
        }
        bool Value(JsonVal& v) {
            Ws();
            if (i_ >= s_.size()) return false;
            char c = s_[i_];
            if (c == '{') return Object(v);
            if (c == '[') return Array(v);
            if (c == '"') { v.type = JsonVal::Str; return String(v.str); }
            if (Lit("true")) { v.type = JsonVal::Bool; v.bl = true;  return true; }
            if (Lit("false")) { v.type = JsonVal::Bool; v.bl = false; return true; }
            if (Lit("null")) { v.type = JsonVal::Null; return true; }
            return Number(v);
        }
        bool Object(JsonVal& v) {
            v.type = JsonVal::Obj; v.obj = std::make_shared<JsonObj>();
            i_++; Ws();
            if (i_ < s_.size() && s_[i_] == '}') { i_++; return true; }
            for (;;) {
                Ws();
                std::string k;
                if (!String(k)) return false;
                Ws();
                if (i_ >= s_.size() || s_[i_] != ':') return false;
                i_++;
                JsonVal child;
                if (!Value(child)) return false;
                (*v.obj)[k] = std::move(child);
                Ws();
                if (i_ < s_.size() && s_[i_] == ',') { i_++; continue; }
                if (i_ < s_.size() && s_[i_] == '}') { i_++; return true; }
                return false;
            }
        }
        bool Array(JsonVal& v) {
            v.type = JsonVal::Arr; v.arr = std::make_shared<JsonArr>();
            i_++; Ws();
            if (i_ < s_.size() && s_[i_] == ']') { i_++; return true; }
            for (;;) {
                JsonVal child;
                if (!Value(child)) return false;
                v.arr->push_back(std::move(child));
                Ws();
                if (i_ < s_.size() && s_[i_] == ',') { i_++; continue; }
                if (i_ < s_.size() && s_[i_] == ']') { i_++; return true; }
                return false;
            }
        }
        bool String(std::string& out) {
            if (i_ >= s_.size() || s_[i_] != '"') return false;
            i_++;
            out.clear();
            while (i_ < s_.size() && s_[i_] != '"') {
                if (s_[i_] == '\\' && i_ + 1 < s_.size()) {
                    i_++;
                    switch (s_[i_]) {
                    case 'n': out += '\n'; break;
                    case 'r': out += '\r'; break;
                    case 't': out += '\t'; break;
                    case 'u': {
                        if (i_ + 4 >= s_.size()) return false;
                        int cp = std::stoi(s_.substr(i_ + 1, 4), nullptr, 16);
                        i_ += 4;
                        out += (char)(cp & 0xFF);
                        break;
                    }
                    default: out += s_[i_];
                    }
                }
                else out += s_[i_];
                i_++;
            }
            if (i_ >= s_.size()) return false;
            i_++;
            return true;
        }
        bool Number(JsonVal& v) {
            size_t st = i_;
            while (i_ < s_.size() && (isdigit((unsigned char)s_[i_]) ||
                s_[i_] == '-' || s_[i_] == '+' || s_[i_] == '.' ||
                s_[i_] == 'e' || s_[i_] == 'E')) i_++;
            if (st == i_) return false;
            try { v.num = std::stod(s_.substr(st, i_ - st)); }
            catch (...) { return false; }
            v.type = JsonVal::Num;
            return true;
        }
    };

    /* Atomic write — chống manifest hỏng khi mất điện giữa chừng */
    inline bool AtomicWriteFile(const std::wstring& path, const std::string& data) {
        std::wstring tmp = path + L".tmp";
        HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        DWORD w = 0;
        BOOL ok = WriteFile(h, data.data(), (DWORD)data.size(), &w, nullptr);
        FlushFileBuffers(h);
        CloseHandle(h);
        if (!ok || w != data.size()) { DeleteFileW(tmp.c_str()); return false; }
        return MoveFileExW(tmp.c_str(), path.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
    }

    inline std::string ReadTextFile(const std::wstring& path) {
        HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return {};
        LARGE_INTEGER sz{};
        GetFileSizeEx(h, &sz);
        std::string s;
        if (sz.QuadPart > 0 && sz.QuadPart < 64ll * 1024 * 1024) {
            s.resize((size_t)sz.QuadPart);
            DWORD got = 0;
            if (!ReadFile(h, s.data(), (DWORD)s.size(), &got, nullptr)) s.clear();
            else s.resize(got);
        }
        CloseHandle(h);
        return s;
    }

} // namespace rw