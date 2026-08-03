/*
 * main.cpp — RansomWall v4.5 User-Space Engine
 *
 * ===========================================================================
 * BẢN VÁ v4.5 — THU THẬP FEATURE ĐỂ TRAIN ML
 * ===========================================================================
 *   [FIX 20] Tích hợp FeatureExport.h.
 *
 *            Snapshot toàn bộ collector ra CSV mỗi tick MaintenanceThread.
 *            KHÔNG gọi từ OnEvent — không đụng đường nóng của driver.
 *
 *            Tham số dòng lệnh:
 *              --csv <duong_dan>     bật ghi CSV (bắt buộc để thu dữ liệu)
 *              --label <chuoi>       nhãn mức run: malware / benign
 *              --target-name <chuoi> chuỗi con tên file mẫu -> cột is_target
 *              --run-id <chuoi>      để trống thì tự sinh theo thời gian
 *              --stride <n>          tiến trình im lặng lấy mẫu mỗi n tick
 *              --observe             KHÔNG kill, chỉ quan sát (xem FIX 21)
 *
 *   [FIX 21] --observe: score >= SCORE_ML_TRIGGER KHÔNG kill nữa.
 *
 *            Mục đích: để mẫu chạy trọn vòng đời, thu được feature ở giai
 *            đoạn mã hoá thật sự chứ không phải cắt ngang lúc mới 6 điểm.
 *
 *            Chế độ này tắt luôn 2 cơ chế phòng thủ khác vì chúng làm MÉO
 *            dữ liệu:
 *              - DENY IRP  -> mẫu nhận ACCESS_DENIED sẽ đổi hành vi.
 *              - backupFrozen -> đóng băng backup ở SCORE_FREEZE nghĩa là
 *                không còn BackupEntry mới, mà F12/F13 đều dựa vào
 *                FindEntry() -> hai feature quan trọng nhất tắt đúng lúc
 *                mẫu mã hoá mạnh nhất.
 *
 *            *** CHỈ CHẠY TRONG VM CÓ SNAPSHOT. Máy sau run là máy đã bị
 *            mã hoá — không có restore, không có CleanRansomArtifacts. ***
 *
 *   [FIX 22] Cập nhật các trường mà FeatureExport đọc nhưng code cũ không
 *            bao giờ ghi: entropyDeltaMax, daaMin, exited.
 *            Khi bật --csv thì bỏ chặn latch cho F13/F14 để entropy và DAA
 *            tiếp tục được tính sau khi feature đã bật (biến liên tục có giá
 *            trị nhất cho ML). Latch vẫn giữ nguyên cho việc Raise().
 *
 * ===========================================================================
 * BẢN VÁ CŨ (giữ nguyên)
 * ===========================================================================
 *   [FIX 11] Xử lý RwActionRead — sự kiện MỞ ĐỌC file giá trị.
 *   [FIX 12] KHÔNG BACKUP HONEY FILE.
 *   [FIX 10] Truyền disposition xuống CoW + PROBE chẩn đoán err=2.
 *   [TẠM]    RW_BYPASS_ML — score >= SCORE_ML_TRIGGER là kill ngay.
 *   [CHẶN]   Không kill explorer/svchost/services...
 * ===========================================================================
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <objbase.h>

#include "Util.h"
#include "Config.h"
#include "Features.h"
#include "Featureexporter.h"      /* [FIX 20] */
#include "FilterClient.h"
#include "CowEngine.h"
#include "StaticAnalyzer.h"
#include "HoneyFiles.h"
#include "MLClient.h"
#include "Cleanup.h"

#include <thread>
#include <atomic>
#include <mutex>
#include <map>
#include <set>
#include <regex>
#include <cstdlib>

using namespace rw;

/* ============================================================
   [FIX 26] LOG MAU SAC CHO KET QUA ML
   BENIGN  : chu xanh la sang (10) tren nen den -> de nhan ra "an toan"
   MALWARE : nhu LOG_A nhung them === border -> bat mat hon
   ============================================================ */
static void LogMlBenign(const char* fmt, ...) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    SYSTEMTIME st; GetLocalTime(&st);
    char buf[512]; va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    SetConsoleTextAttribute(h, FOREGROUND_GREEN | FOREGROUND_INTENSITY);  /* bright green */
    printf("[%02d:%02d:%02d.%03d] [ML>>] %s\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, buf);
    SetConsoleTextAttribute(h, 7);
    fflush(stdout);
    rw::Logger::I().Log(rw::LogLevel::Info, "[ML>>] %s", buf);
}

static void LogMlMalware(const char* fmt, ...) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    SYSTEMTIME st; GetLocalTime(&st);
    char buf[512]; va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    /* Nen do tuoi (0xC0) + chu trang sang (0x0F) = 0xCF */
    SetConsoleTextAttribute(h, 0xCF);
    printf("[%02d:%02d:%02d.%03d] [ML!!] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    printf("[%02d:%02d:%02d.%03d] [ML!!] %s\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, buf);
    printf("[%02d:%02d:%02d.%03d] [ML!!] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    SetConsoleTextAttribute(h, 7);
    fflush(stdout);
    rw::Logger::I().Log(rw::LogLevel::Alert, "[ML!!] %s", buf);
}



/* ==========================================================================
   [TẠM THỜI] BỎ QUA ML
   ========================================================================== */
#define RW_BYPASS_ML 0   /* [FIX 26] Tat bypass — dung LightGBM qua Flask server */

   /* ==========================================================================
      TRẠNG THÁI TOÀN CỤC
      ========================================================================== */
static std::mutex                      g_Mtx;
static std::map<DWORD, ProcessFeature> g_Collector;
static std::atomic<bool>               g_Running{ true };
static std::atomic<bool>               g_DriverMode{ false };
static std::atomic<uint64_t> g_EvTotal{ 0 };
static std::atomic<uint64_t> g_EvPend{ 0 };
static std::atomic<uint64_t> g_EvRead{ 0 };     /* [FIX 11] đếm event mở đọc */

static std::atomic<uint64_t> g_CowFail{ 0 };
static std::atomic<uint64_t> g_CowDeny{ 0 };

/* [FIX 20] [FIX 21] Xuất feature + chế độ quan sát */
static FeatureExporter       g_Csv;
static std::atomic<bool>     g_Observe{ false };
static int                   g_CsvStride = 10;

static std::mutex                          g_StaticMtx;
static std::map<std::string, StaticResult> g_StaticCache;
static std::set<std::string>               g_StaticInFlight;

static bool IsOwnTool(const std::wstring& imagePath) {
    static const std::wstring toolDir = ToLower(GetModuleDir());
    if (toolDir.empty()) return false;
    std::wstring low = ToLower(imagePath);
    if (low.rfind(toolDir, 0) != 0) return false;

    std::wstring name = GetFileNameOnly(low);
    return name == L"diec.exe" || name == L"die.exe" ||
        name == L"floss.exe" || name == L"ransomwall.exe";
}

static std::unique_ptr<CowEngine>     g_Cow;
static std::unique_ptr<CleanupEngine> g_Clean;
static std::unique_ptr<FilterClient>  g_Filter;
static HoneyFiles                     g_Honey;
static MLClient                       g_ML;

/* ==========================================================================
   HELPER
   ========================================================================== */
static ProcessFeature& EnsurePf(DWORD pid, DWORD rootPid) {   /* gọi DƯỚI lock */
    auto& pf = g_Collector[pid];
    if (pf.pid == 0) {
        pf.pid = pid;
        pf.rootPid = rootPid ? rootPid : pid;
        pf.startTime = GetProcessStartTime(pid);
        pf.processImage = GetProcessImagePath(pid);
        pf.createdAt = Clock::now();
    }
    return pf;
}

static int ScoreOf(DWORD pid) {
    std::lock_guard<std::mutex> lk(g_Mtx);
    auto it = g_Collector.find(pid);
    return (it != g_Collector.end()) ? it->second.totalScore : 0;
}

static bool IsCriticalSystemProcess(const std::wstring& imagePath) {
    std::wstring n = ToLower(GetFileNameOnly(imagePath));
    bool nameMatch = n == L"explorer.exe" || n == L"svchost.exe" ||
        n == L"services.exe" || n == L"lsass.exe" ||
        n == L"winlogon.exe" || n == L"csrss.exe" ||
        n == L"wininit.exe" || n == L"smss.exe" ||
        n == L"dwm.exe" || n == L"taskhostw.exe";
    if (!nameMatch) return false;

    /* [FIX] Tên trùng KHÔNG đủ — ransomware tự đặt tên "svchost.exe" chạy
       ngoài System32 để lợi dụng đúng bộ lọc này. PHẢI xác nhận đường dẫn
       nằm trong thư mục hệ thống thật, không chỉ trùng tên file.
       Log thật: PID=15348 "svchost.exe" chạy từ ngoài System32, score=6,
       bị NO-ML bỏ qua vì code cũ chỉ so tên. */
    std::wstring low = ToLower(imagePath);
    bool inSystemDir =
        low.find(L"\\windows\\system32\\") != std::wstring::npos ||
        low.find(L"\\windows\\syswow64\\") != std::wstring::npos;
    if (!inSystemDir) {
        LOG_W("[!] Ten trung he thong nhung SAI DUONG DAN (gia mao): %s",
            ws2s(imagePath).c_str());
        return false;
    }
    return true;
}

/* ==========================================================================
   [FIX 15] SeDebugPrivilege — BỎ QUA KIỂM TRA DACL KHI MỞ TIẾN TRÌNH
   ==========================================================================
   Đo được trong log thực tế (mẫu 000_PP0_100-43.exe):

       Kill PID=3356 ... Kill PID=1160        <- 10 tien trinh con chet
       Khong mo duoc PID=7940 de kill (err=5) <- CHINH RANSOMWARE KHONG CHET

   err=5 = ACCESS_DENIED. OpenProcess(PROCESS_TERMINATE) bị chặn vì ransomware
   TỰ ĐẶT DACL từ chối PROCESS_TERMINATE — kỹ thuật tự bảo vệ phổ biến.
   Chạy Administrator KHÔNG tự động vượt qua DACL.

   SeDebugPrivilege thì có: bật lên, OpenProcess bỏ qua kiểm tra DACL hoàn
   toàn. Đây là cách Task Manager / Process Explorer / debugger mở mọi tiến trình.

   Đặc quyền này CÓ trong token Administrator nhưng mặc định ở trạng thái
   DISABLED — Windows không tự bật vì nó rất mạnh (bật rồi mở được cả lsass).
   Ứng dụng phải chủ động yêu cầu.

   GIỚI HẠN: không vượt được Protected Process Light (PPL). Ransomware hiếm
   khi đạt PPL vì cần chữ ký Microsoft, nên trong thực tế không phải vấn đề.
   ========================================================================== */
static bool EnableDebugPrivilege() {
    HANDLE hTok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok))
        return false;

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        CloseHandle(hTok);
        return false;
    }

    AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    /* AdjustTokenPrivileges trả TRUE cả khi KHÔNG bật được đặc quyền nào.
       Phải kiểm GetLastError. */
    bool ok = (GetLastError() == ERROR_SUCCESS);
    CloseHandle(hTok);
    return ok;
}

/*
 * CheckHoneyTouch — Honey tripwire.
 *
 * [FIX 11] Giờ được gọi từ CẢ HAI đường: mở ghi (pend) VÀ mở đọc (không pend).
 * Đọc honey file là đủ để kết luận — nó là bẫy, không ai có lý do chính đáng
 * để mở nó ra xem.
 *
 * Gọi KHÔNG dưới g_Mtx (tự lock bên trong).
 */
static bool CheckHoneyTouch(DWORD pid, DWORD root, const std::wstring& path,
    const char* how) {
    if (!g_Honey.IsHoney(path)) return false;
    if (HoneyFiles::IsWhitelisted(pid)) {
        /* [FIX 19] Throttle: Search Indexer quet 110 honey file moi tao ->
           109 dong giong het nhau lien tiep. Chi can biet no CO xay ra. */
        LOG_TD("honey_wl", 10000,
            "      Honey bi cham boi tien trinh whitelist (PID=%lu) -> bo qua", pid);
        return false;
    }
    std::lock_guard<std::mutex> lk(g_Mtx);
    auto& pf = EnsurePf(root, root);
    pf.Raise(pf.f4_honeyModified, "F4 honey file bi cham");
    LOG_A("      *** HONEY (%s): %s *** PID=%lu root=%lu",
        how, ws2s(GetFileNameOnly(path)).c_str(), pid, root);
    return true;
}

static void ApplyStatic(ProcessFeature& pf, const StaticResult& r) {
    if (r.unsignedImage) pf.Raise(pf.f1_unsigned, "F1 chu ky so khong hop le");
    if (r.packed)        pf.Raise(pf.f2_packed, "F2 packer/cryptor");
    if (r.suspStrings)   pf.Raise(pf.f3_suspStrings, "F3 suspicious strings");
    if (r.cryptoApi)     pf.Raise(pf.f5_cryptoApi, "F5 crypto API import");
    if (r.safeModeStr)   pf.Raise(pf.f6_safeModeDisable, "F6 safe mode disable (string)");
    pf.imageSha256 = r.imageSha256;
}

static int StaticScore(const StaticResult& r) {
    return (r.unsignedImage ? 1 : 0) + (r.packed ? 1 : 0) +
        (r.suspStrings ? 1 : 0) + (r.cryptoApi ? 1 : 0) +
        (r.safeModeStr ? 1 : 0);
}

static std::vector<std::wstring> StaticScanDirs() {
    std::vector<std::wstring> dirs;
    std::wstring lad = GetKnownFolder(FOLDERID_LocalAppData);
    for (auto& d : { Downloads(), Desktop(), Documents(),
                     lad.empty() ? std::wstring() : lad + L"\\Temp" }) {
        std::error_code ec;
        if (!d.empty() && fs::exists(d, ec)) dirs.push_back(d);
    }
    return dirs;
}

/*
 * CẢNH BÁO: VerifySignature đang trả FALSE cho cmd.exe, conhost.exe,
 * vssadmin.exe... — không đọc được catalog signature. Hệ quả: bộ lọc này
 * gần như vô hiệu và F1 bật cho 100% tiến trình. Cần sửa trong Util.h.
 */
static bool ShouldAnalyzeStatically(const std::wstring& img) {
    std::wstring low = ToLower(img);
    bool inSystemDir = false;
    for (const auto& d : cfg::SYSTEM_DIRS)
        if (low.rfind(d, 0) == 0) { inSystemDir = true; break; }

    if (!inSystemDir) return true;
    if (VerifySignature(img)) return false;
    return true;
}

static bool AnalyzeImageCached(const std::wstring& img, StaticResult& out) {
    std::string hash = Sha256File(img);
    if (hash.empty()) return false;

    {
        std::lock_guard<std::mutex> lk(g_StaticMtx);
        auto it = g_StaticCache.find(hash);
        if (it != g_StaticCache.end()) { out = it->second; return true; }
        if (g_StaticInFlight.count(hash)) return false;
        g_StaticInFlight.insert(hash);
    }

    out = AnalyzeStatic(img);          /* NGOÀI mọi lock */

    std::lock_guard<std::mutex> lk(g_StaticMtx);
    g_StaticCache[hash] = out;
    g_StaticInFlight.erase(hash);
    return true;
}

/* ==========================================================================
   GIAI ĐOẠN 2 — TIẾN TRÌNH KHỞI ĐỘNG
   ========================================================================== */
static void RunStaticForPid(DWORD pid) {
    std::wstring img = GetProcessImagePath(pid);
    if (img.empty()) return;

    if (IsOwnTool(img)) return;
    if (IsDescendantOfSelf(pid)) return;

    if (!ShouldAnalyzeStatically(img)) {
        LOG_TD("static_skip", 30000, "[STATIC] Bo qua (he thong + da ky): %s",
            ws2s(GetFileNameOnly(img)).c_str());
        return;
    }

    std::string hash = Sha256File(img);
    bool hit = false;
    StaticResult r;
    if (!hash.empty()) {
        std::lock_guard<std::mutex> lk(g_StaticMtx);
        auto it = g_StaticCache.find(hash);
        if (it != g_StaticCache.end()) { r = it->second; hit = true; }
    }

    if (hit) {
        LOG_I("[STATIC] Cache HIT: %s -> ap diem tinh %d/5 NGAY (0ms)",
            ws2s(GetFileNameOnly(img)).c_str(), StaticScore(r));
    }
    else {
        LOG_W("[STATIC] Cache MISS: %s — quet BAY GIO (tien trinh DA chay, muon)",
            ws2s(GetFileNameOnly(img)).c_str());
        if (!AnalyzeImageCached(img, r)) return;
    }

    std::lock_guard<std::mutex> lk(g_Mtx);

    DWORD rootForStatic = 0;
    {
        auto eit = g_Collector.find(pid);
        if (eit != g_Collector.end()) rootForStatic = eit->second.rootPid;
    }
    auto& pf = EnsurePf(pid, rootForStatic);
    ApplyStatic(pf, r);

    DWORD rootPid = (pf.rootPid != 0 && pf.rootPid != pid) ? pf.rootPid : 0;
    if (rootPid == 0) {
        std::vector<DWORD> watched;
        watched.reserve(g_Collector.size());
        for (auto& [p, f] : g_Collector) watched.push_back(p);
        rootPid = GetRootPidFromTree(pid, watched);
        if (rootPid == 0) rootPid = GetRootPidFromTree(pid, {});
    }
    if (rootPid != 0 && rootPid != pid) {
        auto& root = EnsurePf(rootPid, rootPid);
        bool anyNew = false;
        if (r.unsignedImage && root.Raise(root.f1_unsigned, "F1 merge tu tien trinh con")) anyNew = true;
        if (r.packed && root.Raise(root.f2_packed, "F2 merge tu tien trinh con")) anyNew = true;
        if (r.suspStrings && root.Raise(root.f3_suspStrings, "F3 merge tu tien trinh con")) anyNew = true;
        if (r.cryptoApi && root.Raise(root.f5_cryptoApi, "F5 merge tu tien trinh con")) anyNew = true;
        if (r.safeModeStr && root.Raise(root.f6_safeModeDisable, "F6 merge tu tien trinh con")) anyNew = true;
        if (anyNew)
            LOG_I("[MERGE] Static PID=%lu -> RootPid=%lu  score root=%d",
                pid, rootPid, root.totalScore);
    }
}

/* ==========================================================================
   XỬ LÝ PHÁN QUYẾT MALWARE
   ========================================================================== */
static void HandleMalwareVerdict(DWORD pid, double conf) {
    LogMlMalware("MALWARE (conf=%.2f) PID=%lu", conf, pid);

    {
        std::vector<DWORD> tree;
        tree.push_back(pid);
        DWORD selfPid = GetCurrentProcessId();
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            std::map<DWORD, std::vector<DWORD>> children;
            PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    if (pe.th32ProcessID > 4 && pe.th32ParentProcessID > 4)
                        children[pe.th32ParentProcessID].push_back(pe.th32ProcessID);
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
            for (size_t i = 0; i < tree.size() && tree.size() < 64; i++) {
                auto cit = children.find(tree[i]);
                if (cit != children.end())
                    for (DWORD child : cit->second)
                        if (child != pid && child != selfPid)
                            tree.push_back(child);
            }
        }

        {
            std::set<std::string> badHashes;
            {
                std::lock_guard<std::mutex> lk(g_Mtx);
                for (auto& [p, f] : g_Collector) {
                    if ((p == pid || f.rootPid == pid) && !f.imageSha256.empty())
                        badHashes.insert(f.imageSha256);
                }
            }
            if (!badHashes.empty()) {
                std::lock_guard<std::mutex> lk(g_Mtx);
                for (auto& [p, f] : g_Collector) {
                    if (p == selfPid || !badHashes.count(f.imageSha256)) continue;
                    if (std::find(tree.begin(), tree.end(), p) != tree.end()) continue;
                    tree.push_back(p);
                    LOG_A("   [!] Cung hash voi mau: PID=%lu %s",
                        p, ws2s(GetFileNameOnly(f.processImage)).c_str());
                }
            }
        }

        {
            std::vector<DWORD> safe;
            for (DWORD p : tree) {
                std::wstring img;
                {
                    std::lock_guard<std::mutex> lk(g_Mtx);
                    auto it = g_Collector.find(p);
                    if (it != g_Collector.end()) img = it->second.processImage;
                }
                if (img.empty()) img = GetProcessImagePath(p);

                if (IsCriticalSystemProcess(img)) {
                    LOG_W("   [BO QUA] KHONG kill %s (PID=%lu) — tien trinh he thong.",
                        ws2s(GetFileNameOnly(img)).c_str(), p);
                    continue;
                }
                safe.push_back(p);
            }
            tree.swap(safe);
        }

        if (tree.empty()) {
            LOG_W("   [!] Sau khi loc, khong con PID nao de kill. Dung lai.");
            return;
        }

        LOG_I("   [1/4] Deny IRP + kill %zu tien trinh trong cay PID=%lu",
            tree.size(), pid);
        if (g_Filter && g_Filter->IsConnected())
            for (DWORD p : tree) g_Filter->DenyPid(p);
        for (auto it = tree.rbegin(); it != tree.rend(); ++it) {
            HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, *it);
            if (h) {
                TerminateProcess(h, 1); CloseHandle(h);
                LOG_I("      Kill PID=%lu", *it);
            }
            else {
                DWORD e = GetLastError();
                if (e == ERROR_INVALID_PARAMETER)
                    LOG_D("      PID=%lu da thoat tu truoc", *it);
                else
                    LOG_W("      Khong mo duoc PID=%lu de kill (err=%lu)", *it, e);
            }
        }
    }
    Sleep(500);

    {
        bool explorerRunning = false;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe))
                do {
                    if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
                        explorerRunning = true; break;
                    }
                } while (Process32NextW(snap, &pe));
            CloseHandle(snap);
        }
        if (!explorerRunning) {
            LOG_I("   [2b] Khoi dong lai explorer.exe");
            STARTUPINFOW si{}; si.cb = sizeof(si);
            PROCESS_INFORMATION pi{};
            wchar_t cmd[] = L"explorer.exe";
            if (CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE,
                0, nullptr, nullptr, &si, &pi)) {
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
                Sleep(1500);
            }
        }
    }

    LOG_I("   [3/4] So hash + restore co dieu kien...");
    auto st = g_Clean->RestoreFiles(pid);
    int cleaned = g_Clean->CleanRansomArtifacts(pid);
    g_Clean->OnMalware(pid);

    LOG_A("   [3/4] KET QUA RESTORE: khoi phuc=%d  can xem lai=%d  xoa rac=%d",
        st.overwritten + st.missing, st.sidelined, cleaned);

    std::wstring msg = L"RansomWall phat hien RANSOMWARE!\n\n"
        L"PID: " + std::to_wstring(pid) + L"\n"
        L"Da khoi phuc: " + std::to_wstring(st.overwritten + st.missing) + L" file\n"
        L"Can ban xem lai: " + std::to_wstring(st.sidelined) + L" file\n"
        L"Da xoa " + std::to_wstring(cleaned) + L" file rac ma hoa\n\n"
        L"Bang chung da luu tai " + cfg::QUARANTINE_ROOT;
    LOG_I("   [4/4] Bao nguoi dung");
    MessageBoxW(nullptr, msg.c_str(), L"RansomWall — MALWARE", MB_OK | MB_ICONSTOP);
}

/* ==========================================================================
   ML
   ========================================================================== */
static void CallML(DWORD pid) {
    std::string body;
    int callNo = 0;
    {
        std::lock_guard<std::mutex> lk(g_Mtx);
        auto it = g_Collector.find(pid);
        if (it == g_Collector.end()) return;
        body = it->second.ToJson();
        callNo = it->second.ml.callCount;
    }

    LOG_A("[ML] Goi ML cho PID=%lu (lan %d)", pid, callNo);
    LOG_D("[ML] payload: %s", body.c_str());

    MLResponse resp = g_ML.Predict(body);

    bool handleMalware = false, handleBenign = false;
    {
        std::lock_guard<std::mutex> lk(g_Mtx);
        auto it = g_Collector.find(pid);
        if (it == g_Collector.end()) return;
        auto& pf = it->second;
        pf.ml.inFlight = false;
        pf.ml.lastVerdict = resp.verdict;

        if (resp.verdict == Verdict::Malware && !pf.ml.verdictHandled) {
            pf.ml.verdictHandled = true;
            handleMalware = true;
        }
        else if (resp.verdict == Verdict::Benign) {
            handleBenign = true;
        }
    }

    /* [FIX 21] Trong che do quan sat, ML co ket luan gi cung khong kill. */
    if (handleMalware && g_Observe) {
        LOG_A("[OBSERVE] ML bao MALWARE cho PID=%lu — KHONG kill (che do quan sat).", pid);
        return;
    }

    if (handleMalware) {
        HandleMalwareVerdict(pid, resp.confidence);
        return;
    }

    if (handleBenign) {
        int curScore = ScoreOf(pid);

        if (curScore < cfg::SCORE_FREEZE) {
            LogMlBenign("[ML] BENIGN (conf=%.2f) PID=%lu score=%d -> unblock, xoa backup",
                resp.confidence, pid, curScore);
            if (g_Filter && g_Filter->IsConnected()) g_Filter->UndenyPid(pid);
            g_Clean->OnBenign(pid);
        }
        else {
            LogMlBenign("[ML] BENIGN (conf=%.2f) PID=%lu score=%d — GIU BACKUP (score van cao)",
                resp.confidence, pid, curScore);
            if (g_Filter && g_Filter->IsConnected()) g_Filter->UndenyPid(pid);
        }
        return;
    }

    if (resp.verdict == Verdict::Unknown)
        LOG_W("[ML] Ket qua khong ro cho PID=%lu: %s", pid, resp.raw.c_str());
}

static void MaybeCallML(DWORD pid) {
    bool go = false;
    {
        std::lock_guard<std::mutex> lk(g_Mtx);
        auto it = g_Collector.find(pid);
        if (it == g_Collector.end()) return;
        auto& pf = it->second;

        if (pf.ml.inFlight)       return;
        if (pf.ml.verdictHandled) return;
        if (!pf.ShouldCallML())   return;

        pf.ml.inFlight = true;
        pf.ml.callCount++;
        pf.ml.lastCall = Clock::now();
        pf.ml.scoreAtLastCall = pf.totalScore;
        pf.ml.ioRateAtLastCall = pf.ioOps.Rate();
        pf.ml.vectorDirty = false;
        go = true;
    }
    if (go) std::thread([pid] { CallML(pid); }).detach();
}

static void MaybeTriggerNoML(DWORD pid) {
    bool go = false;
    int  score = 0;
    {
        std::lock_guard<std::mutex> lk(g_Mtx);
        auto it = g_Collector.find(pid);
        if (it == g_Collector.end()) return;
        auto& pf = it->second;

        if (pf.ml.verdictHandled) return;
        if (pf.totalScore < cfg::SCORE_ML_TRIGGER) return;

        if (IsCriticalSystemProcess(pf.processImage)) {
            LOG_W("[NO-ML] PID=%lu score=%d nhung la %s — BO QUA.",
                pid, pf.totalScore, ws2s(GetFileNameOnly(pf.processImage)).c_str());
            pf.ml.verdictHandled = true;
            return;
        }

        /* ==================================================================
           [FIX 21] CHE DO QUAN SAT — KHONG KILL
           ==================================================================
           KHONG set verdictHandled: tien trinh tiep tuc duoc cham diem va
           tiep tuc xuat hien trong CSV cho den khi no tu thoat.

           Chi log khi score TANG, neu khong se spam moi event mot dong.
           s_logged duoc truy cap DUOI g_Mtx nen an toan.
           ================================================================== */
        if (g_Observe) {
            static std::map<DWORD, int> s_logged;
            int& last = s_logged[pid];
            if (pf.totalScore > last) {
                last = pf.totalScore;
                LOG_A("[OBSERVE] PID=%lu score=%d/14 — KHONG kill, tiep tuc ghi feature. %s",
                    pid, pf.totalScore,
                    ws2s(GetFileNameOnly(pf.processImage)).c_str());
            }
            return;
        }

        pf.ml.verdictHandled = true;
        score = pf.totalScore;
        go = true;
    }
    if (go) {
        LOG_A("[NO-ML] PID=%lu dat score=%d >= %d -> XU LY NHU MALWARE (bo qua ML)",
            pid, score, cfg::SCORE_ML_TRIGGER);
        std::thread([pid] { HandleMalwareVerdict(pid, 1.0); }).detach();
    }
}

static inline void TriggerVerdict(DWORD pid) {
#if RW_BYPASS_ML
    MaybeTriggerNoML(pid);
#else
    MaybeCallML(pid);
#endif
}

/* ==========================================================================
   DYNAMIC ANALYSIS ENGINE
   ========================================================================== */

static bool IsKnownRansomExt(const std::wstring& ext) {
    static const std::set<std::wstring> k = {
        L".locked", L".enc", L".encrypted", L".crypt", L".crypto", L".wncry",
        L".wcry",   L".cerber", L".zepto",  L".odin",  L".thor",   L".aesir",
        L".locky",  L".ryuk",   L".conti",  L".lockbit", L".ecc",  L".ezz",
    };
    return k.count(ext) > 0;
}

static bool IsMassNewExtension(ProcessFeature& pf, const std::wstring& ext) {
    if (ext.empty() || ext.size() > 12) return false;
    if (cfg::VALUABLE_EXTS.count(ext) || cfg::EXECUTABLE_EXTS.count(ext)) return false;

    // Tăng đếm và lấy số lượng sự kiện trong window
    pf.newExtHistogram[ext].Add(1);
    size_t n = pf.newExtHistogram[ext].Count();

    return n >= 5;
}

static bool CheckFingerprint(ProcessFeature& pf, const std::wstring& path) {
    const BackupEntry* e = g_Cow->FindEntry(pf, path);
    if (!e || e->magicBefore.empty()) return false;

    std::string now = FileMagicHex(path);
    if (now.empty() || now == e->magicBefore) return false;

    LOG_D("      F12: magic %s -> %s  (%s)",
        e->magicBefore.substr(0, 8).c_str(), now.substr(0, 8).c_str(),
        ws2s(GetFileNameOnly(path)).c_str());
    return true;
}

static void HandleProcessCreate(const RW_EVENT& ev) {
    std::wstring cmd = ToLower(std::wstring(ev.CommandLine));
    if (cmd.empty()) return;

    DWORD root = ev.RootPid ? ev.RootPid : ev.Pid;

    if (root == ev.Pid) {
        std::vector<DWORD> watched;
        {
            std::lock_guard<std::mutex> lk(g_Mtx);
            watched.reserve(g_Collector.size());
            for (auto& [p, pf] : g_Collector) watched.push_back(p);
        }
        DWORD found = GetRootPidFromTree(ev.Pid, watched);
        if (found == 0) found = GetRootPidFromTree(ev.Pid, {});
        if (found != 0) {
            root = found;
            LOG_TD("proc_tree", 15000,
                "[PROC] PID=%lu RootPid=0 -> tra cay -> RootPid=%lu", ev.Pid, root);
        }
    }

    bool shadow =
        (cmd.find(L"vssadmin") != std::wstring::npos && cmd.find(L"delete") != std::wstring::npos) ||
        (cmd.find(L"wmic") != std::wstring::npos && cmd.find(L"shadowcopy") != std::wstring::npos) ||
        (cmd.find(L"wbadmin") != std::wstring::npos && cmd.find(L"delete") != std::wstring::npos) ||
        (cmd.find(L"win32_shadowcopy") != std::wstring::npos) ||
        (cmd.find(L"delete shadows") != std::wstring::npos) ||
        (cmd.find(L"net stop") != std::wstring::npos && (
            cmd.find(L"vss") != std::wstring::npos ||
            cmd.find(L"backup") != std::wstring::npos ||
            cmd.find(L"wbengine") != std::wstring::npos ||
            cmd.find(L"sqlwriter") != std::wstring::npos)) ||
        (cmd.find(L"sc config") != std::wstring::npos &&
            cmd.find(L"disabled") != std::wstring::npos) ||
        (cmd.find(L"powershell") != std::wstring::npos &&
            cmd.find(L"win32_shadowcopy") != std::wstring::npos) ||
        /*
         * [FIX 16] powercfg -h off — tắt hibernate, XOÁ hiberfil.sys.
         * Akira và nhiều họ khác dùng để phá đường khôi phục và giải phóng
         * chỗ trống. Log mẫu 000_PP0_100-43.exe spawn hàng chục powercfg.exe
         * mà F7 im lặng hoàn toàn vì thiếu mẫu này.
         */
        (cmd.find(L"powercfg") != std::wstring::npos && (
            cmd.find(L"-h ") != std::wstring::npos ||
            cmd.find(L"/h ") != std::wstring::npos ||
            cmd.find(L"hibernate") != std::wstring::npos)) ||
        /* Xoá lịch sử khôi phục hệ thống / catalog backup */
        (cmd.find(L"wmic") != std::wstring::npos &&
            cmd.find(L"systemrestore") != std::wstring::npos) ||
        (cmd.find(L"bcdedit") != std::wstring::npos &&
            cmd.find(L"ignoreallfailures") != std::wstring::npos);

    bool safeMode =
        (cmd.find(L"bcdedit") != std::wstring::npos) ||
        (cmd.find(L"safeboot") != std::wstring::npos) ||
        (cmd.find(L"recoveryenabled no") != std::wstring::npos) ||
        (cmd.find(L"bootstatuspolicy") != std::wstring::npos) ||
        (cmd.find(L"disablerealtimemonitoring") != std::wstring::npos);

    if (!shadow && !safeMode) return;

    {
        std::lock_guard<std::mutex> lk(g_Mtx);
        auto& pf = EnsurePf(root, root);
        if (shadow) {
            pf.Raise(pf.f7_shadowDeleted, "F7 xoa Shadow Copy (tu cmdline con)");
            LOG_I("      cmdline: %s", ws2s(cmd.substr(0, 120)).c_str());
        }
        if (safeMode) {
            pf.Raise(pf.f6_safeModeDisable, "F6 vo hieu Safe Mode (tu cmdline con)");
            LOG_I("      cmdline: %s", ws2s(cmd.substr(0, 120)).c_str());
        }
    }

    TriggerVerdict(root);
}

/* ==========================================================================
   XỬ LÝ EVENT — điểm vào từ driver
   ========================================================================== */
static ULONG OnEvent(const RW_EVENT& ev) {
    g_EvTotal++;
    if (ev.IsPending) g_EvPend++;

    if (ev.Action == RwActionProcessCreate) {
        HandleProcessCreate(ev);
        DWORD pid = ev.Pid;
        std::thread([pid] { RunStaticForPid(pid); }).detach();
        return RwReplyContinue;
    }
    if (ev.Action == RwActionProcessExit) {
        /* [FIX 22] Danh dau exited TRUOC khi Cleanup dong vao — cot `exited`
           trong CSV la mot trong nhung tin hieu manh nhat (mau ransomware
           thuong tu thoat sau khi ma hoa xong). */
        {
            std::lock_guard<std::mutex> lk(g_Mtx);
            auto it = g_Collector.find(ev.Pid);
            if (it != g_Collector.end()) it->second.exited = true;
        }
        g_Clean->OnProcessExit(ev.Pid);
        return RwReplyContinue;
    }

    std::wstring path = NormalizeKernelPath(std::wstring(ev.FilePath));
    DWORD pid = ev.Pid;
    DWORD root = ev.RootPid ? ev.RootPid : ev.Pid;

    /* =====================================================================
       [FIX 11] NHÁNH 0 — MỞ ĐỌC (KHÔNG PEND)
       =====================================================================
       Chaos đọc file gốc rồi ghi ra file mới. Đây là tín hiệu duy nhất đến
       ĐÚNG LÚC. Không backup, không DENY — chỉ tính điểm.

       Honey file: chạm là đủ. Không ai có lý do chính đáng để mở nó.
       ===================================================================== */
    if (ev.Action == RwActionRead) {
        g_EvRead++;

        /* Honey tripwire — tín hiệu nhanh nhất của cả hệ thống */
        CheckHoneyTouch(pid, root, path, "doc");

        /* Đếm mật độ đọc vào F10: ransomware đọc hàng loạt file giá trị */
        {
            std::lock_guard<std::mutex> lk(g_Mtx);
            auto& pf = EnsurePf(root, root);
            pf.ioOps.Add();
            if (pf.ioOps.Rate() > cfg::RATE_IO_THRESHOLD)
                pf.Raise(pf.f10_highIo, "F10 doc/ghi file mat do cao");

            std::wstring ext = GetExtension(path);
            if (!ext.empty()) pf.affectedExts.insert(ext);
        }

        TriggerVerdict(root);
        return RwReplyContinue;   /* event này vốn không pend, reply bị bỏ qua */
    }

    /* =====================================================================
       NHÁNH 1 — CoW ENGINE (IRP đang pend)
       ===================================================================== */
    if (ev.IsPending) {
        LOG_D("[COW-PEND] pid=%lu act=%lu disp=%lu key=%lld %s",
            pid, ev.Action, ev.DirEntryCount, ev.FileRef,
            ws2s(GetFileNameOnly(path)).c_str());

        bool isHoney = CheckHoneyTouch(pid, root, path, "ghi");

        /*
         * [FIX 12] KHÔNG BACKUP HONEY FILE.
         * 110 honey file đều là .txt/.xlsx/.pdf -> nằm trong VALUABLE_EXTS.
         * Backup chúng chỉ ngốn quota của tiến trình thật. Honey là BẪY,
         * mất cũng không sao — điểm đã được cộng rồi.
         */
        if (isHoney) {
            LOG_D("[COW-SKIP] honey_file      %s", ws2s(path).c_str());
            TriggerVerdict(root);
            return RwReplyContinue;
        }

        bool ok = g_Cow->OnFirstTouch(pid, path, root, ev.DirEntryCount);

        TriggerVerdict(root);

        if (!ok) {
            g_CowFail++;
            int score = ScoreOf(root);
            /* [FIX 21] Che do quan sat KHONG DENY: mau nhan ACCESS_DENIED se
               doi hanh vi (retry / bo file / thoat som) -> feature thu duoc
               khong giong luc chay that. */
            if (score >= cfg::SCORE_FREEZE && !g_Observe) {
                g_CowDeny++;
                LOG_W("[COW] KHONG CO BAN SAO + score=%d -> DENY IRP: %s",
                    score, ws2s(GetFileNameOnly(path)).c_str());
                return RwReplyDeny;
            }
        }
        return RwReplyContinue;
    }

    /* =====================================================================
       NHÁNH 2 — DYNAMIC ANALYSIS ENGINE (song song, không chặn I/O)
       ===================================================================== */
    {
        std::lock_guard<std::mutex> lk(g_Mtx);
        auto& childPf = EnsurePf(pid, root);
        ProcessFeature& pf = (root != pid)
            ? EnsurePf(root, root)
            : childPf;

        /* ---- F9: Directory enumeration ---- */
        if (ev.Action == RwActionDirQuery) {
            pf.dirEntries.Add((int)ev.DirEntryCount);
            if (pf.dirEntries.Rate() > cfg::RATE_DIRENT_THRESHOLD)
                pf.Raise(pf.f9_dirEnum, "F9 liet ke thu muc hang loat");
            return RwReplyContinue;
        }

        /* ---- F8: Registry persistence ---- */
        if (ev.Action == RwActionRegPersist) {
            auto it = g_Collector.find(root);
            if (it != g_Collector.end() && it->second.totalScore > 0) {
                it->second.Raise(it->second.f8_registryPersist, "F8 registry persistence");
                LOG_I("      key: %s", ws2s(path.substr(0, 100)).c_str());
            }
            else {
                LOG_TD("f8_skip", 20000,
                    "[F8] Bo qua PID=%lu (khong theo doi / score=0) key: %s",
                    root, ws2s(path.substr(0, 80)).c_str());
            }
            return RwReplyContinue;
        }

        bool isHoney = g_Honey.IsHoney(path);
        std::wstring ext = GetExtension(path);

        /* ---- F4: Honey file ---- */
        if (isHoney) {
            if (HoneyFiles::IsWhitelisted(pid)) {
                LOG_TD("honey_wl2", 10000,
                    "      Honey bi cham boi tien trinh whitelist (PID=%lu) -> bo qua", pid);
                return RwReplyContinue;
            }
            pf.Raise(pf.f4_honeyModified, "F4 honey file bi cham");
            LOG_A("      *** HONEY: %s *** PID=%lu",
                ws2s(GetFileNameOnly(path)).c_str(), pid);
        }

        /* ---- F10: High I/O ---- */
        if (!isHoney) {
            pf.ioOps.Add();
            if (pf.ioOps.Rate() > cfg::RATE_IO_THRESHOLD)
                pf.Raise(pf.f10_highIo, "F10 thao tac file mat do cao");
        }
        if (!ext.empty()) pf.affectedExts.insert(ext);

        /* ---- F11: Rename / đổi đuôi ---- */
        if (ev.Action == RwActionRename) {
            pf.renames.Add();
            bool massExt = IsMassNewExtension(pf, ext);
            if (IsKnownRansomExt(ext)) {
                pf.Raise(pf.f11_extChanged, "F11 duoi ransomware da biet");
            }
            else if (pf.renames.Rate() > cfg::RATE_RENAME_THRESHOLD && massExt) {
                pf.Raise(pf.f11_extChanged, "F11 doi duoi hang loat");
            }
        }

        /* ---- F12 + F13 ---- */
        if ((ev.Action == RwActionWrite || ev.Action == RwActionRename) && !isHoney) {
            if (!pf.f12_fingerprintMismatch.value && CheckFingerprint(childPf, path))
                pf.Raise(pf.f12_fingerprintMismatch, "F12 dau van tay file khong khop");

            /*
             * [FIX 22] Khi dang thu du lieu (--csv) thi KHONG dung tinh
             * entropy sau khi latch da bat. entropy_delta_mean / _max /
             * entropy_samples la bien lien tuc — dong bang chung tai thoi
             * diem phat hien thi ML gan nhu khong con gi de hoc.
             * Latch van duoc dung de quyet dinh co Raise() hay khong.
             */
            const bool wantEntropy = g_Csv.Enabled() || !pf.f13_highEntropy.value;
            if (wantEntropy) {
                const BackupEntry* e = g_Cow->FindEntry(childPf, path);
                if (e) {
                    double hNow = FileEntropy(path, cfg::ENTROPY_SAMPLE_BYTES);
                    if (hNow > 0) {
                        double d = hNow - e->entropyBefore;

                        childPf.entropyDelta.Add(d);
                        if (d > childPf.entropyDeltaMax) childPf.entropyDeltaMax = d;
                        if (&pf != &childPf) {
                            pf.entropyDelta.Add(d);
                            if (d > pf.entropyDeltaMax) pf.entropyDeltaMax = d;
                        }

                        bool hit = (d > cfg::ENTROPY_DELTA_THRESHOLD) ||
                            (hNow > cfg::ENTROPY_ABS_THRESHOLD && d > 0.5);
                        if (hit && !pf.f13_highEntropy.value) {
                            LOG_D("      F13: H %.2f -> %.2f  (dH=+%.2f)  %s",
                                e->entropyBefore, hNow, d, ws2s(GetFileNameOnly(path)).c_str());
                            pf.Raise(pf.f13_highEntropy, "F13 delta entropy cao (ma hoa)");
                        }
                    }
                }
            }

            /* F14 — Differential Area Analysis (Davies et al., arXiv:2106.14418) */
            const bool wantDaa = (g_Csv.Enabled() || !pf.f14_daa.value) &&
                cfg::VALUABLE_EXTS.count(ext) > 0;
            if (wantDaa) {
                double daa = DifferentialAreaAnalysis(path);

                /* [FIX 22] daaMin truoc gio khong bao gio duoc ghi -> cot
                   daa_min trong CSV luon trong (sentinel 9999). */
                if (daa < childPf.daaMin) childPf.daaMin = daa;
                if (daa < pf.daaMin)      pf.daaMin = daa;

                if (daa < cfg::DAA_THRESHOLD && !pf.f14_daa.value) {
                    LOG_D("      F14: DAA=%.2f Bit-Bytes  %s",
                        daa, ws2s(GetFileNameOnly(path)).c_str());
                    pf.Raise(pf.f14_daa, "F14 DAA: header ngau nhien (ma hoa AES)");
                }
            }
        }

        /*
         * [FIX 21] Che do quan sat KHONG dong bang backup.
         * backupFrozen o SCORE_FREEZE nghia la tu do khong con BackupEntry
         * moi, ma ca F12 lan F13 deu goi FindEntry() -> hai feature quan
         * trong nhat tat dung luc mau bat dau ma hoa manh nhat.
         */
        if (pf.totalScore >= cfg::SCORE_FREEZE && !pf.backupFrozen && !g_Observe)
            pf.backupFrozen = true;

        if (pf.totalScore >= 4 && pf.totalScore < cfg::SCORE_ML_TRIGGER) {
            static std::atomic<uint64_t> lastDanger{ 0 };
            uint64_t now = GetTickCount64(), prev = lastDanger.load();
            if (now - prev > 1000 &&
                lastDanger.compare_exchange_strong(prev, now)) {
                int sc = pf.totalScore; DWORD r = root;
                LOG_W("[DANGER] PID=%lu score=%d/14", r, sc);
            }
        }
    }

    TriggerVerdict(root);
    return RwReplyContinue;
}

/* ==========================================================================
   GIAI ĐOẠN 1 — NEW EXECUTABLE WATCHER
   ========================================================================== */
enum class SettleResult { Ready, Gone, Timeout };

static SettleResult WaitFileSettled(const std::wstring& path, int timeoutMs) {
    ULONGLONG start = GetTickCount64();
    ULONGLONG deadline = start + timeoutMs;
    uint64_t  last = UINT64_MAX;
    int  stable = 0;
    int  missing = 0;
    bool logged = false;

    while (GetTickCount64() < deadline) {
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) {
            DWORD e = GetLastError();
            if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) {
                if (++missing >= 4) return SettleResult::Gone;
            }
            Sleep(500);
            continue;
        }
        missing = 0;
        uint64_t sz = ((uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;

        if (sz > 0 && sz == last) {
            stable++;
            if (stable >= 2) {
                HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, 0, nullptr,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return SettleResult::Ready; }
            }
            if (stable >= 8) {
                LOG_D("[NEWEXE] %s: size on dinh nhung con bi giu handle "
                    "-> phan tich bang doc chia se.",
                    ws2s(GetFileNameOnly(path)).c_str());
                return SettleResult::Ready;
            }
        }
        else {
            stable = 0;
        }

        if (!logged && GetTickCount64() - start > 5000) {
            LOG_I("[NEWEXE] Dang cho %s ghi xong (%llu KB)...",
                ws2s(GetFileNameOnly(path)).c_str(), sz / 1024);
            logged = true;
        }
        last = sz;
        Sleep(500);
    }
    return SettleResult::Timeout;
}

static bool IsToolUnpackDir(const std::wstring& path) {
    std::wstring low = ToLower(path);
    if (low.find(L"\\_mei") != std::wstring::npos) return true;
    if (low.find(L"\\onefile_") != std::wstring::npos) return true;
    return false;
}

static void OnNewExecutable(std::wstring path) {
    if (IsOwnTool(path) || IsToolUnpackDir(path)) return;

    SettleResult sr = WaitFileSettled(path, cfg::NEWEXE_SETTLE_TIMEOUT_MS);
    if (sr == SettleResult::Gone) {
        LOG_D("[NEWEXE] File bi xoa truoc khi quet: %s",
            ws2s(GetFileNameOnly(path)).c_str());
        return;
    }
    if (sr == SettleResult::Timeout) {
        LOG_W("[NEWEXE] HET GIO CHO (%ds) — KHONG quet duoc: %s",
            cfg::NEWEXE_SETTLE_TIMEOUT_MS / 1000, ws2s(path).c_str());
        return;
    }
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) return;
    uint64_t sz = ((uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
    if (sz == 0 || sz > cfg::NEWEXE_MAX_SIZE) return;

    StaticResult r;
    if (!AnalyzeImageCached(path, r)) return;

    int pre = StaticScore(r);

    if (pre == 0) {
        LOG_D("[NEWEXE] %s: 0/5 — sach.", ws2s(GetFileNameOnly(path)).c_str());
        return;
    }
    if (pre < 3) {
        LOG_I("[NEWEXE] %s: diem tinh = %d/5 — da cache.",
            ws2s(GetFileNameOnly(path)).c_str(), pre);
        return;
    }
    LOG_A("[NEWEXE] !!! %s co %d/5 dau hieu tinh — DA CACHE truoc khi chay.",
        ws2s(GetFileNameOnly(path)).c_str(), pre);
}

static void NewExecutableWatcher(const std::wstring& dir) {
    HANDLE h = CreateFileW(dir.c_str(), FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        LOG_W("[NEWEXE] Khong mo duoc %s", ws2s(dir).c_str());
        return;
    }
    LOG_I("[NEWEXE] Theo doi file thuc thi moi: %s", ws2s(dir).c_str());

    std::vector<uint8_t> buf(64 * 1024);
    while (g_Running) {
        DWORD ret = 0;
        if (!ReadDirectoryChangesW(h, buf.data(), (DWORD)buf.size(),
            TRUE, FILE_NOTIFY_CHANGE_FILE_NAME,
            &ret, nullptr, nullptr)) break;
        if (ret == 0) continue;

        uint8_t* p = buf.data();
        while (p < buf.data() + ret) {
            auto* n = (FILE_NOTIFY_INFORMATION*)p;
            std::wstring name(n->FileName, n->FileNameLength / sizeof(WCHAR));
            std::wstring full = dir + L"\\" + name;

            if ((n->Action == FILE_ACTION_ADDED ||
                n->Action == FILE_ACTION_RENAMED_NEW_NAME) &&
                cfg::EXECUTABLE_EXTS.count(GetExtension(full)))
            {
                std::thread(OnNewExecutable, full).detach();
            }
            if (n->NextEntryOffset == 0) break;
            p += n->NextEntryOffset;
        }
    }
    CloseHandle(h);
}

/* ==========================================================================
   CHẾ ĐỘ SIMULATION
   ========================================================================== */
static void SimulationWatcher(const std::wstring& dir) {
    HANDLE h = CreateFileW(dir.c_str(), FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        LOG_W("[SIM] Khong mo duoc %s", ws2s(dir).c_str());
        return;
    }
    LOG_I("[SIM] Theo doi: %s", ws2s(dir).c_str());

    std::vector<uint8_t> buf(64 * 1024);
    while (g_Running) {
        DWORD ret = 0;
        if (!ReadDirectoryChangesW(h, buf.data(), (DWORD)buf.size(), TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE |
            FILE_NOTIFY_CHANGE_SIZE,
            &ret, nullptr, nullptr)) break;

        uint8_t* p = buf.data();
        while (p < buf.data() + ret) {
            auto* n = (FILE_NOTIFY_INFORMATION*)p;
            std::wstring name(n->FileName, n->FileNameLength / sizeof(WCHAR));
            std::wstring full = dir + L"\\" + name;

            RW_EVENT ev{};
            ev.Pid = GetCurrentProcessId();
            ev.RootPid = ev.Pid;
            ev.IsPending = 0;
            wcsncpy_s(ev.FilePath, full.c_str(), _TRUNCATE);

            switch (n->Action) {
            case FILE_ACTION_MODIFIED:         ev.Action = RwActionWrite;  break;
            case FILE_ACTION_RENAMED_NEW_NAME: ev.Action = RwActionRename; break;
            case FILE_ACTION_REMOVED:          ev.Action = RwActionDelete; break;
            case FILE_ACTION_ADDED:            ev.Action = RwActionWrite;  break;
            default: ev.Action = RwActionNone;
            }
            if (ev.Action != RwActionNone) {
                /* [FIX 12] honey không cần backup */
                if (!g_Honey.IsHoney(full))
                    g_Cow->OnFirstTouch(ev.Pid, full);
                OnEvent(ev);
            }
            if (n->NextEntryOffset == 0) break;
            p += n->NextEntryOffset;
        }
    }
    CloseHandle(h);
}

/* ==========================================================================
   THREAD NỀN
   ========================================================================== */
static void MaintenanceThread() {
    int tick = 0;
    while (g_Running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        tick++;

        /* [FIX 20] Chup feature moi giay. Chup duoi lock roi format + ghi
           NGOAI lock — xem dau FeatureExport.h. */
        if (g_Csv.Enabled()) g_Csv.Snapshot(g_Mtx, g_Collector, g_CsvStride);

        if (tick % cfg::HEARTBEAT_INTERVAL_SEC == 0) CleanupEngine::WriteHeartbeat();
        if (tick % 5 == 0) g_Cow->FlushDirtyManifests();
        if (tick % cfg::EARLY_CLEANUP_INTERVAL_SEC == 0) g_Clean->EarlyCleanupPass();
        if (tick % 15 == 0) g_Clean->ExitCleanupPass();

        if (tick % cfg::DISK_RECHECK_SEC == 0) {
            g_Cow->RefreshBudget();
            if (g_Filter && g_Filter->IsConnected()) {
                if (g_Cow->BelowReserve()) g_Filter->PauseCow();
                else                       g_Filter->ResumeCow();
            }
        }
    }
}

static void StatusThread() {
    while (g_Running) {
        std::this_thread::sleep_for(std::chrono::seconds(20));
        size_t tracked = 0, backed = 0;
        uint64_t bytes = 0;
        int maxScore = 0; DWORD maxPid = 0;
        {
            std::lock_guard<std::mutex> lk(g_Mtx);
            tracked = g_Collector.size();

            /*
             * [FIX 17] ĐẾM THEO ĐƯỜNG DẪN DUY NHẤT.
             *
             * OnFirstTouch đăng ký MỖI entry HAI LẦN khi rootPid != pid:
             * một lần vào PID con, một lần vào RootPid (để RestoreFiles tìm
             * thấy). Cộng dồn entries.size() qua mọi PID -> đếm gấp đôi.
             *
             * Log Akira báo backup=128 nhưng thực tế chỉ ~64 file.
             * quotaUsed thì đúng (chỉ cộng ở PID con) nên không đổi.
             */
            std::set<std::wstring> uniq;
            for (auto& [pid, pf] : g_Collector) {
                for (auto& e : pf.entries) uniq.insert(ToLower(e.originalPath));
                bytes += pf.quotaUsed;
                if (pf.totalScore > maxScore) { maxScore = pf.totalScore; maxPid = pid; }
            }
            backed = uniq.size();
        }
        uint64_t ghost = g_Cow ? g_Cow->GhostMissCount() : 0;
        uint64_t lateRep = g_Filter ? g_Filter->LateReplyCount() : 0;
        uint64_t badRep = g_Filter ? g_Filter->ReplyFailCount() : 0;

        LOG_I("[STATUS] tien-trinh=%zu  backup=%zu file (%llu MB)  score cao nhat=%d (PID=%lu)  "
            "events=%llu pend=%llu read=%llu  cow-fail=%llu cow-deny=%llu  ghost-miss=%llu  "
            "reply-muon=%llu reply-loi=%llu",
            tracked, backed, bytes / 1048576, maxScore, maxPid,
            g_EvTotal.load(), g_EvPend.load(), g_EvRead.load(),
            g_CowFail.load(), g_CowDeny.load(), ghost, lateRep, badRep);

        /* [FIX 20] Bao tien do thu du lieu ngay trong dong STATUS. */
        if (g_Csv.Enabled()) {
            LOG_I("[STATUS] CSV run_id=%s  da ghi %llu dong%s",
                g_Csv.RunId().c_str(),
                (unsigned long long)g_Csv.RowsWritten(),
                g_Observe.load() ? "  [OBSERVE: khong kill]" : "");
        }

        if (ghost > 0) {
            LOG_E("[STATUS] *** GHOST-MISS=%llu *** getattr tra err=2 cho file CO THAT. "
                "Doc cac dong [PROBE] de biet nguyen nhan chinh xac.", ghost);
        }
        if (badRep > 0) {
            LOG_E("[STATUS] *** REPLY-LOI=%llu *** co IRP pend khong duoc tra loi dung. "
                "CoW dang thung.", badRep);
        }

        /* ==============================================================
           [FIX 26] GOI LAI ML TU TIMER - KHONG PHU THUOC IRP EVENT
           ==============================================================
           Van de: ShouldCallML() chi duoc evaluate khi co IRP event moi.
           Neu ransomware da xong ma hoa (Cerber, Rhysida sau pha 1) thi
           khong con IRP -> retry 30/60/90s khong bao gio duoc kich hoat.

           Fix: StatusThread chay moi 20s -> sau moi lan sleep, quet tat ca
           PID dang theo doi co score >= SCORE_ML_TRIGGER va lastVerdict ==
           Benign -> goi MaybeCallML() -> ShouldCallML() se kiem tra timer
           va goi lai ML neu da du 30/60/90s.
           ============================================================== */
#if !RW_BYPASS_ML
        {
            std::vector<DWORD> toRetry;
            {
                std::lock_guard<std::mutex> lk(g_Mtx);
                for (auto& [pid, pf] : g_Collector) {
                    if (pf.totalScore >= cfg::SCORE_ML_TRIGGER &&
                        pf.ml.lastVerdict == Verdict::Benign &&
                        !pf.ml.inFlight &&
                        pf.ml.callCount > 0 && pf.ml.callCount < 4) {
                        toRetry.push_back(pid);
                    }
                }
            }
            for (DWORD pid : toRetry) {
                LOG_D("[STATUS] Kiem tra retry ML cho PID=%lu...", pid);
                MaybeCallML(pid);
            }
        }
#endif
    }
}

/* ==========================================================================
   [FIX 20] THAM SỐ DÒNG LỆNH
   ========================================================================== */
static void PrintUsage() {
    printf("  Tham so:\n");
    printf("    --csv <duong_dan>      Bat ghi feature ra CSV\n");
    printf("    --label <chuoi>        Nhan muc run: malware / benign\n");
    printf("    --target-name <chuoi>  Chuoi con ten file mau -> cot is_target\n");
    printf("    --run-id <chuoi>       De trong thi tu sinh theo thoi gian\n");
    printf("    --stride <n>           Tien trinh im lang lay mau moi n tick (mac dinh 10)\n");
    printf("    --observe              KHONG kill — chay het vong doi de thu feature\n");
    printf("                           *** CHI CHAY TRONG VM CO SNAPSHOT ***\n");
    printf("    --stop-file <duong_dan> Dung khi file nay xuat hien, thay vi cho Enter\n");
    printf("                           (bat buoc khi chay tu harness / khong co console)\n\n");
}

/* ==========================================================================
   MAIN
   ========================================================================== */
int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    /* ---------------- Doc tham so ---------------- */
    std::wstring csvPath, targetName;
    std::wstring stopFile;              /* [FIX 23] */
    std::string  label = "unknown", runId;
    bool         wantHelp = false;

    for (int i = 1; i < argc; i++) {
        std::wstring a = argv[i];
        auto nextW = [&](std::wstring& out) { if (i + 1 < argc) out = argv[++i]; };
        auto nextA = [&](std::string& out) {
            if (i + 1 < argc) out = ws2s(std::wstring(argv[++i]));
            };

        if (a == L"--csv")              nextW(csvPath);
        else if (a == L"--target-name") nextW(targetName);
        else if (a == L"--label")       nextA(label);
        else if (a == L"--run-id")      nextA(runId);
        else if (a == L"--observe")     g_Observe = true;
        else if (a == L"--stop-file")   nextW(stopFile);   /* [FIX 23] */
        else if (a == L"--stride") {
            std::wstring v; nextW(v);
            g_CsvStride = _wtoi(v.c_str());
            if (g_CsvStride < 1) g_CsvStride = 1;
        }
        else if (a == L"--help" || a == L"-h" || a == L"/?") wantHelp = true;
    }

    rw::Logger::I().SetLogFile(GetModuleDir() + L"\\ransomwall.log");

    /* ======================================================================
       [FIX 19] MỨC LOG TÁCH RIÊNG CONSOLE VÀ FILE
       ======================================================================
       Console: Info trở lên — người dùng theo dõi, không cần thấy DEBUG.
       File   : Debug đầy đủ — để phân tích sau khi chạy xong.

       Đổi RW_QUIET_CONSOLE thành 1 nếu muốn console CHỈ hiện cảnh báo trở lên
       (dùng khi chạy mẫu nhanh liên tiếp, console cuộn quá nhanh để đọc).

       Muốn file cũng gọn (log nhỏ hơn nhiều): SetFileLevel(LogLevel::Info).
       ====================================================================== */
#define RW_QUIET_CONSOLE 0

#if RW_QUIET_CONSOLE
    rw::Logger::I().SetConsoleLevel(rw::LogLevel::Warn);
#else
    rw::Logger::I().SetConsoleLevel(rw::LogLevel::Info);
#endif
    rw::Logger::I().SetFileLevel(rw::LogLevel::Debug);

    printf("\n");
    printf("  ==========================================\n");
    printf("        RansomWall v4.5\n");
    printf("     CoW Engine + 14 Features + ML\n");
#if RW_BYPASS_ML
    printf("     *** CHE DO BO QUA ML (score>=%d = KILL) ***\n", cfg::SCORE_ML_TRIGGER);
#endif
    printf("  ==========================================\n\n");

    if (wantHelp) { PrintUsage(); return 0; }

#if RW_BYPASS_ML
    LOG_W("[!] RW_BYPASS_ML=1 — score >= %d se KILL NGAY khong hoi ML.",
        cfg::SCORE_ML_TRIGGER);
#endif

    BOOL isAdmin = FALSE;
    PSID adminGrp = nullptr;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGrp)) {
        CheckTokenMembership(nullptr, adminGrp, &isAdmin);
        FreeSid(adminGrp);
    }
    if (!isAdmin) {
        LOG_E("Can chay voi quyen Administrator. Thoat.");
        printf("\nNhan Enter de thoat...");
        (void)getchar();
        return 1;
    }
    SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);

    /* ---------------- [FIX 20] Khoi tao CSV ---------------- */
    if (!csvPath.empty()) {
        if (!g_Csv.Init(csvPath, runId, label, targetName)) {
            LOG_E("[CSV] Init that bai — chay tiep nhung KHONG ghi feature.");
        }
        else {
            LOG_I("[CSV] stride=%d (tien trinh im lang lay mau moi %d tick)",
                g_CsvStride, g_CsvStride);
        }
    }
    else {
        LOG_I("[CSV] Khong co --csv -> khong ghi feature. Dung --help de xem tham so.");
    }

    /* ---------------- [FIX 21] Canh bao che do quan sat ---------------- */
    if (g_Observe) {
        LOG_W("[!] ============================================================");
        LOG_W("[!] --observe: score >= %d se KHONG kill.", cfg::SCORE_ML_TRIGGER);
        LOG_W("[!] DENY IRP tat. Dong bang backup tat.");
        LOG_W("[!] KHONG co restore, KHONG co CleanRansomArtifacts.");
        LOG_W("[!] May sau khi chay la may DA BI MA HOA.");
        LOG_W("[!] CHI CHAY TRONG VM CO SNAPSHOT — revert sau moi mau.");
        LOG_W("[!] ============================================================");
    }

    /* [FIX 15] Bắt buộc phải bật TRƯỚC khi có bất kỳ lần kill nào.
       Không có nó, ransomware tự đặt DACL sẽ sống sót (err=5). */
    if (EnableDebugPrivilege()) {
        LOG_I("[*] Da bat SeDebugPrivilege — kill duoc ca tien trinh tu bao ve.");
    }
    else {
        LOG_W("[!] KHONG bat duoc SeDebugPrivilege (err=%lu). Tien trinh dat DACL "
            "tu choi PROCESS_TERMINATE se KHONG kill duoc.", GetLastError());
    }

    g_Cow = std::make_unique<CowEngine>(g_Mtx, g_Collector);
    g_Clean = std::make_unique<CleanupEngine>(g_Mtx, g_Collector, *g_Cow);
    g_Filter = std::make_unique<FilterClient>();

    LOG_I("[*] Quet backup mo coi tu phien truoc...");
    g_Clean->OrphanSweep();
    CleanupEngine::ClearHeartbeat();

    LOG_I("[*] Tao honey files...");
    g_Honey.Create();

    for (auto& d : StaticScanDirs())
        std::thread(NewExecutableWatcher, d).detach();

    LOG_I("[*] Ket noi kernel driver...");
    if (g_Filter->Connect()) {
        g_DriverMode = true;
        g_Filter->SetSelfPid(GetCurrentProcessId());
        LOG_I("[*] Whitelist chinh minh: PID=%lu", GetCurrentProcessId());
        g_Filter->StartListening(OnEvent, 4);
        LOG_I("[+] CHE DO KERNEL — CoW dong bo qua pend IRP. Bao ve day du.");
    }
    else {
        g_DriverMode = false;
        LOG_W("[!] CHE DO SIMULATION — driver chua load.");
        LOG_W("    De bat kernel mode:  sc start RansomWallDriver");

        for (auto& d : { Downloads(), Documents(), Desktop() })
            if (!d.empty()) std::thread(SimulationWatcher, d).detach();
    }

    std::thread(MaintenanceThread).detach();
    std::thread(StatusThread).detach();

    printf("\n");
    if (stopFile.empty()) {
        LOG_I("=== RansomWall dang giam sat. Nhan Enter de thoat. ===");
        printf("\n");
        (void)getchar();
    }
    else {
        /* ==================================================================
           [FIX 23] TIN HIEU DUNG BANG FILE
           ==================================================================
           Khi duoc goi tu harness (prlctl exec / scheduled task) thi KHONG co
           console tuong tac: getchar() tra EOF NGAY LAP TUC va tien trinh
           thoat truoc khi thu duoc bat ky feature nao.

           Harness tao file nay khi muon dung -> Close() cua CSV chay day du
           (fflush + fclose) thay vi bi taskkill giua duong.
           ================================================================== */
        std::error_code ec;
        fs::remove(stopFile, ec);          /* xoa tin hieu cu neu con */
        LOG_I("=== RansomWall dang giam sat. Cho tin hieu dung: %s ===",
            ws2s(stopFile).c_str());
        printf("\n");
        while (g_Running) {
            if (fs::exists(stopFile, ec)) {
                LOG_I("[STOP] Nhan duoc tin hieu dung.");
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
        }
    }

    g_Running = false;
    if (g_Filter) g_Filter->Disconnect();
    if (g_Cow)    g_Cow->FlushDirtyManifests();
    CleanupEngine::ClearHeartbeat();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    /* [FIX 20] Dong CSV SAU khi cac thread da dung — Close() se fflush,
       fclose va dat Read-only. */
    g_Csv.Close();

    CoUninitialize();
    LOG_I("Da thoat.");
    rw::Logger::I().Flush();   /* [FIX 19] xa bo dem dong lap cuoi cung */
    return 0;
}