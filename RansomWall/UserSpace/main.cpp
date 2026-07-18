/*
 * main.cpp — RansomWall v4.0 User-Space Engine
 *
 * KIẾN TRÚC (mục 2 của báo cáo):
 *
 *   Event từ driver
 *        │
 *        ├──> CoW ENGINE ────> backup ────> CMD_CONTINUE ────> KẾT THÚC
 *        │    (không chờ điểm, không gọi ML, không phụ thuộc Flask)
 *        │
 *        └──> DYNAMIC ANALYSIS ──> 13 features ──> score >= 6 ──> ML
 *             (song song, không chặn I/O)
 *
 * HAI NHÁNH ĐỘC LẬP VỀ ĐIỀU KHIỂN, CỘNG HƯỞNG VỀ DỮ LIỆU:
 *   CoW lưu entropy_before/magic_before -> F12/F13 dùng lại MIỄN PHÍ.
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

using namespace rw;

/* ==========================================================================
   TRẠNG THÁI TOÀN CỤC
   ========================================================================== */
static std::mutex                      g_Mtx;
static std::map<DWORD, ProcessFeature> g_Collector;
static std::atomic<bool>               g_Running{ true };
static std::atomic<bool>               g_DriverMode{ false };

/* Cache kết quả tĩnh theo IMAGE HASH — sửa lỗi slot 9999 đơn của v3.0.
   v3.0: hai .exe rơi vào Downloads gần nhau -> file sau ghi đè processName,
   file trước MẤT ĐIỂM TĨNH VĨNH VIỄN. */
static std::mutex                          g_StaticMtx;
static std::map<std::string, StaticResult> g_StaticCache;   // key = SHA-256 image
static std::set<std::string>               g_StaticInFlight; // chống thundering herd

/*
 * IsOwnTool — file này có phải công cụ của CHÍNH RansomWall không?
 * Phân tích diec.exe bằng diec.exe = đệ quy vô hạn.
 */
static bool IsOwnTool(const std::wstring& imagePath) {
    static const std::wstring toolDir = ToLower(GetModuleDir());
    if (toolDir.empty()) return false;
    std::wstring low = ToLower(imagePath);
    if (low.rfind(toolDir, 0) != 0) return false;   // không nằm trong thư mục của ta

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

/* Áp kết quả tĩnh vào một PID — gọi DƯỚI lock */
static void ApplyStatic(ProcessFeature& pf, const StaticResult& r) {
    if (r.unsignedImage) pf.Raise(pf.f1_unsigned, "F1 chu ky so khong hop le");
    if (r.packed)        pf.Raise(pf.f2_packed, "F2 packer/cryptor");
    if (r.suspStrings)   pf.Raise(pf.f3_suspStrings, "F3 suspicious strings");
    if (r.cryptoApi)     pf.Raise(pf.f5_cryptoApi, "F5 crypto API import");
    if (r.safeModeStr)   pf.Raise(pf.f6_safeModeDisable, "F6 safe mode disable (string)");
    pf.imageSha256 = r.imageSha256;
}

/* Tính điểm tĩnh 0-5 từ StaticResult */
static int StaticScore(const StaticResult& r) {
    return (r.unsignedImage ? 1 : 0) + (r.packed ? 1 : 0) +
        (r.suspStrings ? 1 : 0) + (r.cryptoApi ? 1 : 0) +
        (r.safeModeStr ? 1 : 0);
}

/* Thư mục cần quét tĩnh — dùng chung cho quét ban đầu và watcher */
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
 * ShouldAnalyzeStatically — LỌC TRƯỚC KHI QUÉT
 *
 * LỖI ĐÃ SỬA (máy lag): quét tĩnh MỌI tiến trình Windows khởi động.
 *   svchost.exe, RuntimeBroker.exe, taskhostw.exe, backgroundTaskHost.exe,
 *   SoftLandingTask.exe... Windows đẻ hàng chục cái mỗi phút.
 *   Mỗi cái = SHA-256 toàn file + parse PE + DIE + FLOSS.
 *
 * File trong C:\Windows / Program Files mà CÓ chữ ký hợp lệ -> bỏ qua hẳn.
 * KHÔNG có chữ ký dù nằm trong đó -> vẫn quét (dấu hiệu bị thay thế).
 */
static bool ShouldAnalyzeStatically(const std::wstring& img) {
    std::wstring low = ToLower(img);
    bool inSystemDir = false;
    for (const auto& d : cfg::SYSTEM_DIRS)
        if (low.rfind(d, 0) == 0) { inSystemDir = true; break; }

    if (!inSystemDir) return true;          /* ngoài vùng hệ thống -> luôn quét */
    if (VerifySignature(img)) return false; /* trong vùng hệ thống + đã ký -> bỏ qua */
    return true;                            /* trong vùng hệ thống mà KHÔNG ký -> đáng ngờ */
}

/*
 * AnalyzeImageCached — quét một image, cache theo SHA-256.
 * Dùng chung cho cả watcher (trước khi chạy) và process-create (khi chạy).
 */
static bool AnalyzeImageCached(const std::wstring& img, StaticResult& out) {
    std::string hash = Sha256File(img);
    if (hash.empty()) return false;

    {
        std::lock_guard<std::mutex> lk(g_StaticMtx);
        auto it = g_StaticCache.find(hash);
        if (it != g_StaticCache.end()) { out = it->second; return true; }
        if (g_StaticInFlight.count(hash)) return false;   /* luồng khác đang quét */
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
   ==========================================================================
   Cache HIT  -> áp điểm tĩnh NGAY (0ms). Đây là đường đi mong muốn:
                 giai đoạn 1 đã quét file này rồi.
   Cache MISS -> file đến từ vùng không được watcher phủ (mạng, USB, ổ khác).
                 Quét ngay bây giờ = MUỘN: ransomware đã chạy rồi.
                 Đây là lưới vét, không phải đường chính.
   ========================================================================== */
static void RunStaticForPid(DWORD pid) {
    std::wstring img = GetProcessImagePath(pid);
    if (img.empty()) return;

    /*
     * ---- CHẶN ĐỆ QUY ----
     * RansomWall spawn diec.exe -> process create -> phan tich diec.exe
     * -> spawn diec.exe QUET diec.exe -> ... vô hạn
     */
    if (IsOwnTool(img)) return;
    if (IsDescendantOfSelf(pid)) return;

    /* ---- LỌC HIỆU NĂNG ---- */
    if (!ShouldAnalyzeStatically(img)) {
        LOG_D("[STATIC] Bo qua (he thong + da ky): %s",
            ws2s(GetFileNameOnly(img)).c_str());
        return;
    }

    /* Cache hit? -> giai đoạn 1 đã quét, áp ngay */
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

    /*
     * Dùng EnsurePf thay vì find() để tránh race condition:
     * nếu static thread thắng trước event đầu tiên từ kernel,
     * entry chưa tồn tại → find() trả về end() → điểm tĩnh mất.
     * EnsurePf tạo entry nếu chưa có, giữ nguyên nếu đã có.
     */
    DWORD rootForStatic = 0;
    {
        auto eit = g_Collector.find(pid);
        if (eit != g_Collector.end()) rootForStatic = eit->second.rootPid;
    }
    auto& pf = EnsurePf(pid, rootForStatic);
    ApplyStatic(pf, r);

    /*
     * F6 từ static (safeModeStr): chuỗi "bcdedit" thấy trong binary.
     * Tiến trình con của ransomware (vd: @WanaDecryptor@.exe) có thể
     * chứa chuỗi này nhưng điểm phải về RootPid — tiến trình gốc.
     *
     * Lưu ý: F6 thật (runtime) đã được HandleProcessCreate quy RootPid đúng.
     * Ở đây chỉ xử lý trường hợp static tìm thấy trước khi runtime bắt được.
     */
    if (r.safeModeStr) {
        /* pf.rootPid đã được EnsurePf điền sẵn — dùng trực tiếp */
        DWORD rootPid = (pf.rootPid != 0 && pf.rootPid != pid) ? pf.rootPid : 0;

        if (rootPid != 0) {
            /* Chỉ quy về root nếu root KHÁC pid — tức là đây là tiến trình con */
            auto& rootPf = EnsurePf(rootPid, rootPid);
            rootPf.Raise(rootPf.f6_safeModeDisable,
                "F6 vo hieu Safe Mode (static string, quy ve RootPid)");
            LOG_I("[STATIC] F6 string tu PID=%lu -> quy ve RootPid=%lu", pid, rootPid);
        }
    }
}

/* ==========================================================================
   ML — chạy trên thread riêng, KHÔNG BAO GIỜ chặn CoW
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

    /* Nhả quyền + kiểm tra đã xử lý phán quyết chưa — TẤT CẢ dưới một lock */
    bool handleMalware = false, handleBenign = false;
    {
        std::lock_guard<std::mutex> lk(g_Mtx);
        auto it = g_Collector.find(pid);
        if (it == g_Collector.end()) return;
        auto& pf = it->second;
        pf.ml.inFlight = false;
        pf.ml.lastVerdict = resp.verdict;

        if (resp.verdict == Verdict::Malware && !pf.ml.verdictHandled) {
            pf.ml.verdictHandled = true;   /* CHỈ MỘT luồng đi tiếp */
            handleMalware = true;
        }
        else if (resp.verdict == Verdict::Benign) {
            handleBenign = true;
        }
    }

    if (handleMalware) {
        LOG_A("[ML] === MALWARE (conf=%.2f) PID=%lu ===", resp.confidence, pid);

        /* THỨ TỰ QUAN TRỌNG (v3.0 làm ngược):
           1. deny IRP TRƯỚC — taskkill không tức thời, I/O đang bay vẫn hoàn tất
           2. kill
           3. so hash + restore có điều kiện
           4. báo user */
        if (g_Filter && g_Filter->IsConnected()) {
            g_Filter->DenyPid(pid);
            LOG_I("   [1/4] Driver deny moi IRP cua PID=%lu", pid);
        }

        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (h) { TerminateProcess(h, 1); CloseHandle(h); LOG_I("   [2/4] Kill PID=%lu", pid); }
        else     LOG_W("   [2/4] Khong mo duoc handle de kill PID=%lu", pid);

        /* Chờ tiến trình chết hẳn rồi mới restore — nếu không nó còn ghi đè lại */
        Sleep(500);

        LOG_I("   [3/4] So hash + restore co dieu kien...");
        auto st = g_Clean->RestoreFiles(pid);
        int cleaned = g_Clean->CleanRansomArtifacts(pid);
        g_Clean->OnMalware(pid);

        std::wstring msg = L"RansomWall phat hien RANSOMWARE!\n\n"
            L"PID: " + std::to_wstring(pid) + L"\n"
            L"Da khoi phuc: " + std::to_wstring(st.overwritten + st.missing) + L" file\n"
            L"Can ban xem lai: " + std::to_wstring(st.sidelined) + L" file\n"
            L"Da xoa " + std::to_wstring(cleaned) + L" file rac ma hoa\n\n"
            L"Bang chung da luu tai " + cfg::QUARANTINE_ROOT;
        LOG_I("   [4/4] Bao nguoi dung");
        MessageBoxW(nullptr, msg.c_str(), L"RansomWall — MALWARE", MB_OK | MB_ICONSTOP);
        return;
    }

    if (handleBenign) {
        LOG_I("[ML] BENIGN (conf=%.2f) PID=%lu -> unblock, xoa backup, VAN THEO DOI TIEP",
            resp.confidence, pid);
        if (g_Filter && g_Filter->IsConnected()) g_Filter->UndenyPid(pid);
        g_Clean->OnBenign(pid);
        /* KHÔNG khoá aiCalled. BENIGN chỉ là phán quyết TẠI THỜI ĐIỂM ĐÓ. */
        return;
    }

    if (resp.verdict == Verdict::Unknown)
        LOG_W("[ML] Ket qua khong ro cho PID=%lu: %s", pid, resp.raw.c_str());
}

/*
 * MaybeCallML — GIÀNH QUYỀN NGAY dưới lock, không phải trong thread con.
 * Đây là chỗ sửa bug stampede: cập nhật state TRƯỚC khi spawn.
 */
static void MaybeCallML(DWORD pid) {
    bool go = false;
    {
        std::lock_guard<std::mutex> lk(g_Mtx);
        auto it = g_Collector.find(pid);
        if (it == g_Collector.end()) return;
        auto& pf = it->second;

        if (pf.ml.inFlight)       return;   /* đang có luồng gọi ML */
        if (pf.ml.verdictHandled) return;   /* đã kết luận MALWARE, xong */
        if (!pf.ShouldCallML())   return;

        /* Giành quyền + cập nhật state NGAY TẠI ĐÂY, dưới cùng lock */
        pf.ml.inFlight = true;
        pf.ml.callCount++;
        pf.ml.lastCall = Clock::now();
        pf.ml.scoreAtLastCall = pf.totalScore;
        pf.ml.ioRateAtLastCall = pf.ioOps.Rate();
        go = true;
    }
    if (go) std::thread([pid] { CallML(pid); }).detach();
}

/* ==========================================================================
   DYNAMIC ANALYSIS ENGINE
   ========================================================================== */

   /* --- F11: phát hiện đuôi ransomware --- */
static bool IsKnownRansomExt(const std::wstring& ext) {
    static const std::set<std::wstring> k = {
        L".locked", L".enc", L".encrypted", L".crypt", L".crypto", L".wncry",
        L".wcry",   L".cerber", L".zepto",  L".odin",  L".thor",   L".aesir",
        L".locky",  L".ryuk",   L".conti",  L".lockbit", L".ecc",  L".ezz",
    };
    return k.count(ext) > 0;
}

/*
 * SỬA LỖI v3.0: heuristic "đuôi hex 3-8 ký tự" bắt nhầm .log, .cab, .dec, .bed,
 * .fee, .add, .ace... (đều là hex hợp lệ). Dương tính giả nặng.
 *
 * v4.0: cùng MỘT đuôi lạ xuất hiện trên >= 20 file khác nhau trong 30s.
 * Ransomware dùng chung một đuôi; hoạt động bình thường thì không.
 */
static bool IsMassNewExtension(ProcessFeature& pf, const std::wstring& ext) {
    if (ext.empty() || ext.size() > 12) return false;
    if (cfg::VALUABLE_EXTS.count(ext) || cfg::EXECUTABLE_EXTS.count(ext)) return false;
    int n = ++pf.newExtHistogram[ext];
    return n >= 20;
}

/* --- F12: so magic_before (từ manifest) vs magic_now --- */
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

/*
 * --- F13: DELTA entropy ---
 *
 * SỬA LỖI v3.0: ngưỡng tuyệt đối 7.5.
 *   .docx/.xlsx/.zip/.jpg GỐC đã có H ≈ 7.9  ->  bật cờ cho MỌI thao tác
 *   với file nén, kể cả 7-Zip hợp lệ.
 *
 * v4.0: ΔH = H_sau − H_trước, với H_trước lấy MIỄN PHÍ từ manifest của CoW.
 *   report.docx : 7.91 -> 7.99  ΔH=+0.08  -> khong bat (nhung F12 bat magic)
 *   notes.txt   : 4.21 -> 7.98  ΔH=+3.77  -> BAT
 *   backup.zip  : 7.94 -> 7.93  ΔH=-0.01  -> 7-Zip lanh tinh, khong bat
 */
static bool CheckEntropyDelta(ProcessFeature& pf, const std::wstring& path) {
    const BackupEntry* e = g_Cow->FindEntry(pf, path);
    if (!e) return false;

    double hNow = FileEntropy(path, cfg::ENTROPY_SAMPLE_BYTES);
    if (hNow <= 0) return false;

    double d = hNow - e->entropyBefore;
    pf.entropyDelta.Add(d);

    bool hit = (d > cfg::ENTROPY_DELTA_THRESHOLD) && (hNow > cfg::ENTROPY_ABS_THRESHOLD);
    if (hit)
        LOG_D("      F13: H %.2f -> %.2f  (dH=+%.2f)  %s",
            e->entropyBefore, hNow, d, ws2s(GetFileNameOnly(path)).c_str());
    return hit;
}

/* --- F6/F7: từ command line của tiến trình con, quy điểm về RootPid --- */
static void HandleProcessCreate(const RW_EVENT& ev) {
    std::wstring cmd = ToLower(std::wstring(ev.CommandLine));
    if (cmd.empty()) return;

    /*
     * Ưu tiên RootPid từ kernel PT table.
     * Nếu == 0 (RansomWall khởi động SAU ransomware → PT table trống),
     * tra ngược cây tiến trình Windows thật để tìm tổ tiên đang bị theo dõi.
     */
    DWORD root = ev.RootPid ? ev.RootPid : ev.Pid;
    if (ev.RootPid == 0 || ev.RootPid == ev.Pid) {
        /* Lấy danh sách PID đang theo dõi (dưới lock ngắn) */
        std::vector<DWORD> watched;
        {
            std::lock_guard<std::mutex> lk(g_Mtx);
            watched.reserve(g_Collector.size());
            for (auto& [pid, pf] : g_Collector) watched.push_back(pid);
        }
        DWORD found = GetRootPidFromTree(ev.Pid, watched);
        if (found != 0) {
            root = found;
            LOG_D("[PROC] PID=%lu ev.RootPid=0 -> tra cay thuc -> RootPid=%lu",
                ev.Pid, root);
        }
    }

    bool shadow =
        (cmd.find(L"vssadmin") != std::wstring::npos && cmd.find(L"delete") != std::wstring::npos) ||
        (cmd.find(L"wmic") != std::wstring::npos && cmd.find(L"shadowcopy") != std::wstring::npos) ||
        (cmd.find(L"wbadmin") != std::wstring::npos && cmd.find(L"delete") != std::wstring::npos) ||
        (cmd.find(L"win32_shadowcopy") != std::wstring::npos) ||
        (cmd.find(L"delete shadows") != std::wstring::npos);

    bool safeMode =
        (cmd.find(L"bcdedit") != std::wstring::npos) ||
        (cmd.find(L"safeboot") != std::wstring::npos) ||
        (cmd.find(L"recoveryenabled no") != std::wstring::npos) ||
        (cmd.find(L"bootstatuspolicy") != std::wstring::npos) ||
        (cmd.find(L"disablerealtimemonitoring") != std::wstring::npos);

    if (!shadow && !safeMode) return;

    /*
     * QUY ĐIỂM VỀ ROOTPID — sửa lỗi lớn của v3.0.
     * Ransomware gọi CreateProcess("vssadmin delete shadows").
     * v3.0 cộng điểm cho PID của vssadmin.exe — một tiến trình sống 200ms
     * rồi chết. Ransomware KHÔNG BAO GIỜ nhận được điểm này.
     */
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

/* ==========================================================================
   XỬ LÝ EVENT — điểm vào từ driver
   ========================================================================== */
static ULONG OnEvent(const RW_EVENT& ev) {
    /* ---------- Event tiến trình ---------- */
    if (ev.Action == RwActionProcessCreate) {
        HandleProcessCreate(ev);
        DWORD pid = ev.Pid;
        std::thread([pid] { RunStaticForPid(pid); }).detach();
        return RwReplyContinue;
    }
    if (ev.Action == RwActionProcessExit) {
        g_Clean->OnProcessExit(ev.Pid);
        return RwReplyContinue;
    }

    std::wstring path = NormalizeKernelPath(std::wstring(ev.FilePath));
    DWORD pid = ev.Pid;
    DWORD root = ev.RootPid ? ev.RootPid : ev.Pid;

    /* =====================================================================
       NHÁNH 1 — CoW ENGINE
       IRP đang pend => file GỐC CHƯA BỊ GHI. Backup ngay, rồi CONTINUE.
       Không chờ điểm. Không gọi ML. Không phụ thuộc Flask.
       ===================================================================== */
    if (ev.IsPending) {
        g_Cow->OnFirstTouch(pid, path);
        return RwReplyContinue;      /* <<< KẾT THÚC. Nhánh này không đi đâu nữa. */
    }

    /* =====================================================================
       NHÁNH 2 — DYNAMIC ANALYSIS ENGINE (song song, không chặn I/O)
       ===================================================================== */
    {
        std::lock_guard<std::mutex> lk(g_Mtx);
        auto& pf = EnsurePf(pid, root);
        /* ---- F9: Directory enumeration (nguồn THẬT: IRP_MJ_DIRECTORY_CONTROL) ---- */
        if (ev.Action == RwActionDirQuery) {
            pf.dirEntries.Add((int)ev.DirEntryCount);
            if (pf.dirEntries.Rate() > cfg::RATE_DIRENT_THRESHOLD)
                pf.Raise(pf.f9_dirEnum, "F9 liet ke thu muc hang loat");
            return RwReplyContinue;
        }

        /* ---- F8: Registry persistence (nguồn THẬT: CmRegisterCallbackEx) ---- */
        if (ev.Action == RwActionRegPersist) {
            auto& rpf = EnsurePf(root, root);
            rpf.Raise(rpf.f8_registryPersist, "F8 registry persistence");
            LOG_D("      key: %s", ws2s(path.substr(0, 100)).c_str());
            return RwReplyContinue;
        }

        bool isHoney = g_Honey.IsHoney(path);
        std::wstring ext = GetExtension(path);

        /* ---- F4: Honey file ---- */
        if (isHoney) {
            if (HoneyFiles::IsWhitelisted(pid)) {
                LOG_D("      Honey bi cham boi tien trinh whitelist -> bo qua");
                return RwReplyContinue;
            }
            pf.Raise(pf.f4_honeyModified, "F4 honey file bi sua doi");
            LOG_I("      honey: %s", ws2s(GetFileNameOnly(path)).c_str());
        }

        /* ---- F10: High I/O — theo TỐC ĐỘ, không phải tổng tích luỹ ---- */
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

        /* ---- F12 + F13: dùng metadata mà CoW đã lưu ---- */
        if ((ev.Action == RwActionWrite || ev.Action == RwActionRename) && !isHoney) {
            if (!pf.f12_fingerprintMismatch.value && CheckFingerprint(pf, path))
                pf.Raise(pf.f12_fingerprintMismatch, "F12 dau van tay file khong khop");
            if (CheckEntropyDelta(pf, path))
                pf.Raise(pf.f13_highEntropy, "F13 delta entropy cao (ma hoa)");
        }

        if (pf.totalScore >= cfg::SCORE_FREEZE && !pf.backupFrozen)
            pf.backupFrozen = true;      /* đóng băng LRU */

        if (pf.totalScore >= 4 && pf.totalScore < cfg::SCORE_ML_TRIGGER)
            LOG_W("[DANGER] PID=%lu score=%d/13 — vung nguy hiem, tiep tuc theo doi.",
                pid, pf.totalScore);
    }

    MaybeCallML(pid);      /* spawn thread riêng — KHÔNG chặn ở đây */
    return RwReplyContinue;
}

/* ==========================================================================
   GIAI ĐOẠN 1 — NEW EXECUTABLE WATCHER
   ==========================================================================
   Chỉ phân tích file thực thi XUẤT HIỆN SAU KHI RansomWall khởi động
   (tải về, giải nén, copy từ USB). File đã có sẵn từ trước KHÔNG quét.

   Giả định: RansomWall chạy TRƯỚC khi mối đe doạ tới — mô hình real-time
   protection tiêu chuẩn.

   VÌ SAO phải quét lúc file rơi xuống, không đợi nó chạy:
     Nếu chỉ dựa vào process create:
       t=0ms     ransomware.exe chạy
       t=5000ms  DIE xong
       t=25000ms FLOSS xong -> F1/F2/F3 mới bật
     25 giây đó ransomware đã mã hoá xong. Điểm tĩnh về vô nghĩa.
   ========================================================================== */

   /* ==========================================================================
      CHỜ FILE GHI XONG
      ==========================================================================
      LỖI ĐÃ SỬA (bỏ lỡ file giải nén từ zip có mật khẩu):
        - Timeout 4.5s là con số BỊA, không cơ sở. Gõ mật khẩu, file lớn, hay
          VM ARM64 emulated đều vượt xa.
        - GetFileAttributesEx fail -> return false NGAY, không phân biệt
          "file bị xoá thật" với "đang bị khoá một nhịp".
        - Size ổn định MỘT lần đã thử mở -> quá vội.
        - Thất bại là mất luôn, không có đường quay lại.
      ========================================================================== */
enum class SettleResult { Ready, Gone, Timeout };

static SettleResult WaitFileSettled(const std::wstring& path, int timeoutMs) {
    ULONGLONG start = GetTickCount64();
    ULONGLONG deadline = start + timeoutMs;
    uint64_t  last = UINT64_MAX;
    int  stable = 0;    /* số nhịp liên tiếp size không đổi */
    int  missing = 0;    /* số nhịp liên tiếp không thấy file */
    bool logged = false;

    while (GetTickCount64() < deadline) {
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) {
            DWORD e = GetLastError();
            /* Chỉ kết luận "biến mất" khi NOT_FOUND nhiều nhịp liên tiếp */
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
            /* Size đứng yên >= 2 nhịp -> thử mở ĐỘC QUYỀN: chắc không ai còn ghi */
            if (stable >= 2) {
                HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, 0, nullptr,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return SettleResult::Ready; }
            }
            /*
             * Vẫn bị giữ handle nhưng size đã đứng yên 4 giây.
             * Chấp nhận đọc chia sẻ — thà phân tích còn hơn bỏ lỡ.
             * (7-Zip / trình duyệt giữ handle lâu sau khi ghi xong)
             */
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

/*
 * IsToolUnpackDir — thư mục do CHÍNH công cụ của ta bung ra.
 *
 * LỖI ĐÃ SỬA (flood _MEI189322 trong log):
 *   floss.exe là app Python đóng gói bằng PyInstaller. Khi chạy, nó giải nén
 *   mấy chục DLL runtime vào %TEMP%\_MEI<pid>\ -> watcher thấy "file thuc thi
 *   MOI" cho từng cái -> phân tích hết -> ngập log.
 *   RansomWall lại tự gây nhiễu cho chính mình.
 *
 * IsOwnTool không bắt được vì _MEI nằm ở Temp, không nằm trong thư mục module.
 */
static bool IsToolUnpackDir(const std::wstring& path) {
    std::wstring low = ToLower(path);
    if (low.find(L"\\_mei") != std::wstring::npos) return true;   /* PyInstaller */
    if (low.find(L"\\onefile_") != std::wstring::npos) return true;   /* Nuitka */
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
        LOG_W("         File nay chi duoc quet KHI NO CHAY (muon).");
        return;
    }
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) return;
    uint64_t sz = ((uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
    if (sz == 0 || sz > cfg::NEWEXE_MAX_SIZE) return;

    StaticResult r;
    if (!AnalyzeImageCached(path, r)) return;

    int pre = StaticScore(r);

    /* File sạch: log mức DEBUG. Chỉ file đáng ngờ mới ALERT. */
    if (pre == 0) {
        LOG_D("[NEWEXE] %s: 0/5 — sach.", ws2s(GetFileNameOnly(path)).c_str());
        return;
    }
    if (pre < 3) {
        LOG_I("[NEWEXE] %s: diem tinh = %d/5 — da cache.",
            ws2s(GetFileNameOnly(path)).c_str(), pre);
        return;
    }
    LOG_A("[NEWEXE] !!! %s co %d/5 dau hieu tinh — DA CACHE truoc khi chay. "
        "Neu chay, no se dat nguong ML rat nhanh.",
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
            TRUE,   /* đệ quy — bắt cả file giải nén vào thư mục con */
            FILE_NOTIFY_CHANGE_FILE_NAME,
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
   CHẾ ĐỘ SIMULATION — khi driver chưa load
   ==========================================================================
   ReadDirectoryChangesW KHÔNG cho biết PID nào gây ra thay đổi, và KHÔNG
   pend được. Backup có thể chậm hơn ransomware (xem mục 3.2 của báo cáo).
   Chỉ dùng để TEST LOGIC, không phải bảo vệ thật.
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
            ev.Pid = GetCurrentProcessId();   /* SIM: không biết PID thật */
            ev.RootPid = ev.Pid;
            ev.IsPending = 0;
            wcsncpy_s(ev.FilePath, full.c_str(), _TRUNCATE);

            switch (n->Action) {
            case FILE_ACTION_MODIFIED:        ev.Action = RwActionWrite;  break;
            case FILE_ACTION_RENAMED_NEW_NAME:ev.Action = RwActionRename; break;
            case FILE_ACTION_REMOVED:         ev.Action = RwActionDelete; break;
            case FILE_ACTION_ADDED:           ev.Action = RwActionWrite;  break;
            default: ev.Action = RwActionNone;
            }
            if (ev.Action != RwActionNone) {
                /* SIM: giả lập first-touch bằng cách thử backup mọi file mới thấy */
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

        /* Heartbeat — phân biệt crash vs thoát sạch */
        if (tick % cfg::HEARTBEAT_INTERVAL_SEC == 0) CleanupEngine::WriteHeartbeat();

        /*
         * Ghi gộp manifest — NGOÀI đường pend.
         * Trước đây WriteManifest() chạy trong CowEngine::OnFirstTouch, dưới
         * global mutex, kèm FlushFileBuffers -> mỗi file backup ép flush đĩa
         * trong lúc IRP đang treo chờ. Đây là một trong các nguyên nhân máy lag.
         */
        if (tick % 5 == 0) g_Cow->FlushDirtyManifests();

        /* (1) Early cleanup */
        if (tick % cfg::EARLY_CLEANUP_INTERVAL_SEC == 0) g_Clean->EarlyCleanupPass();

        /* (2) Exit cleanup */
        if (tick % 15 == 0) g_Clean->ExitCleanupPass();

        /* Đo lại disk budget */
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
        std::lock_guard<std::mutex> lk(g_Mtx);
        size_t tracked = g_Collector.size(), backed = 0;
        uint64_t bytes = 0;
        int maxScore = 0; DWORD maxPid = 0;
        for (auto& [pid, pf] : g_Collector) {
            backed += pf.entries.size();
            bytes += pf.quotaUsed;
            if (pf.totalScore > maxScore) { maxScore = pf.totalScore; maxPid = pid; }
        }
        LOG_I("[STATUS] tien-trinh=%zu  backup=%zu file (%llu MB)  score cao nhat=%d (PID=%lu)",
            tracked, backed, bytes / 1048576, maxScore, maxPid);
    }
}

/* ==========================================================================
   MAIN
   ========================================================================== */
int wmain() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    printf("\n");
    printf("  ==========================================\n");
    printf("        RansomWall v4.0\n");
    printf("     CoW Engine + 13 Features + ML\n");
    printf("  ==========================================\n\n");

    /* --- Kiểm tra quyền admin --- */
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

    g_Cow = std::make_unique<CowEngine>(g_Mtx, g_Collector);
    g_Clean = std::make_unique<CleanupEngine>(g_Mtx, g_Collector, *g_Cow);
    g_Filter = std::make_unique<FilterClient>();

    /* --- (4) Orphan sweep: PHẢI chạy TRƯỚC khi nhận event --- */
    LOG_I("[*] Quet backup mo coi tu phien truoc...");
    g_Clean->OrphanSweep();
    CleanupEngine::ClearHeartbeat();

    /* --- Honey files --- */
    LOG_I("[*] Tao honey files...");
    g_Honey.Create();

    /* ================================================================
       GIAI ĐOẠN 1 — TĨNH: file trên đĩa, TRƯỚC khi chạy
       ================================================================
         1a. Quét ban đầu : file đã có sẵn lúc khởi động
         1b. Watcher      : file mới rơi xuống sau đó
       Cả hai cache theo SHA-256 -> khi tiến trình chạy, điểm tĩnh áp NGAY.
       ================================================================ */
    for (auto& d : StaticScanDirs())
        std::thread(NewExecutableWatcher, d).detach();

    /* --- Kết nối driver --- */
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
        LOG_W("    ReadDirectoryChangesW KHONG biet PID that va KHONG pend duoc.");
        LOG_W("    Backup co the CHAM HON ransomware. Chi dung de test logic.");
        LOG_W("    De bat kernel mode:  sc start RansomWallDriver");

        for (auto& d : { Downloads(), Documents(), Desktop() })
            if (!d.empty()) std::thread(SimulationWatcher, d).detach();
    }

    std::thread(MaintenanceThread).detach();
    std::thread(StatusThread).detach();

    printf("\n");
    LOG_I("=== RansomWall dang giam sat. Nhan Enter de thoat. ===");
    printf("\n");
    (void)getchar();

    g_Running = false;
    if (g_Filter) g_Filter->Disconnect();
    if (g_Cow)    g_Cow->FlushDirtyManifests();   /* ghi nốt trước khi thoát */
    CleanupEngine::ClearHeartbeat();   /* thoát sạch -> xoá .session */
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    CoUninitialize();
    LOG_I("Da thoat.");
    return 0;
}