/*
 * Config.h — Mọi hằng số ngưỡng tập trung một chỗ.
 * Sửa ở đây, không rải magic number khắp code.
 */
#pragma once
#include <string>
#include <vector>
#include <set>
#include <cstdint>

namespace rw::cfg {

    /* ---------- Chế độ chạy ---------- */
    /* Nếu driver chưa load, chương trình tự chuyển sang SIMULATION
       (ReadDirectoryChangesW). Chế độ này không pend được IRP nên chỉ dùng
       để test logic, không phải bảo vệ thật. */

    /* ---------- Đường dẫn ---------- */
    inline const std::wstring BACKUP_ROOT = L"C:\\RansomWall_Backup";
    inline const std::wstring QUARANTINE_ROOT = L"C:\\RansomWall_Quarantine";
    inline const std::wstring RESTORED_ROOT = L"C:\\RansomWall_Restored";
    inline const std::wstring SESSION_FILE = L"C:\\RansomWall_Backup\\.session";

    /* ---------- Ngưỡng điểm ---------- */
    constexpr int SCORE_ML_TRIGGER = 6;   // gọi ML
    constexpr int SCORE_FREEZE = 2;   // đóng băng backup, tắt LRU
    constexpr int SCORE_CLEANUP_MAX = 1;   // <= giá trị này thì early cleanup được phép
    constexpr int ML_MAX_SCHEDULED_CALLS = 4;   // đủ 4 lần Benign liên tiếp -> coi là sạch, xoá backup

    /* CoW: trần kích thước file backup, hai bậc theo score. Trần thấp (50MB)
       khi tiến trình còn sạch để tránh phình store; trần cao (512MB) khi đã
       nghi ngờ (score >= SCORE_FREEZE), vì một số wiper ghi đè file lớn bằng
       rác thay vì mã hoá — trần cứng 50MB sẽ bỏ lỡ hoàn toàn các file đó.
       Quota động (TIER0..TIER3) vẫn là hàng rào chặn phình dung lượng. */
    constexpr uint64_t MAX_BACKUP_FILE_SIZE = 512ull * 1024 * 1024;   // 512MB — score >= 2
    constexpr uint64_t MAX_BACKUP_FILE_SIZE_CLEAN = 50ull * 1024 * 1024;   //  50MB — score <= 1

    /* Retry copy khi file bị giữ handle (ransomware mở file với dwShareMode=0
       deny-all). Retry ngắn để vượt qua trường hợp file chỉ bị khoá một nhịp.
       Ngân sách thời gian bị giới hạn bởi driver timeout 200ms
       (RW_REPLY_TIMEOUT_100NS): 3 lần x 30ms = 90ms, chừa chỗ cho thao tác
       copy — vượt 200ms là driver fail-open và file mất. */
    constexpr int COW_COPY_RETRY_COUNT = 3;
    constexpr int COW_COPY_RETRY_SLEEP_MS = 30;

    /* VALUABLE_EXTS phải khớp gValuableExts trong Driver.c: driver chỉ pend
       IRP khi đuôi file nằm trong danh sách này, đuôi ngoài danh sách thì
       CoW không bao giờ chạy và file mất mà không có cảnh báo. Đây là mô
       hình whitelist (thua kém blacklist về độ phủ) — xem
       RW_COW_BLACKLIST_MODE trong Driver.c nếu muốn đổi. */
    inline const std::set<std::wstring> VALUABLE_EXTS = {
        /* --- Tài liệu --- */
        L".doc",  L".docx", L".docm", L".dot",  L".dotx", L".odt",
        L".xls",  L".xlsx", L".xlsm", L".xlt",  L".xltx", L".ods",
        L".ppt",  L".pptx", L".pptm", L".pps",  L".ppsx", L".odp",
        L".pdf",  L".txt",  L".rtf",  L".csv",  L".md",   L".tex",
        L".one",  L".pages",L".numbers",

        /* --- Ảnh / thiết kế --- */
        L".jpg",  L".jpeg", L".png",  L".gif",  L".bmp",  L".psd",
        L".raw",  L".tif",  L".tiff", L".webp", L".heic", L".svg",
        L".ico",  L".ai",   L".eps",  L".cr2",  L".nef",  L".arw", L".dng",

        /* --- Media --- */
        L".mp3",  L".mp4",  L".avi",  L".mov",  L".wav",  L".mkv",
        L".flac", L".m4a",  L".wmv",  L".flv",  L".webm", L".m4v",
        L".aac",  L".ogg",

        /* --- Nén / ảnh đĩa --- */
        L".zip",  L".rar",  L".7z",   L".tar",  L".gz",   L".bz2",
        L".xz",   L".iso",  L".cab",

        /* --- CSDL --- */
        L".sql",  L".db",   L".mdb",  L".accdb",L".sqlite", L".sqlite3",
        L".mdf",  L".ldf",  L".dbf",  L".frm",  L".myd",  L".bak",

        /* --- Dữ liệu / cấu hình --- */
        L".json", L".xml",  L".yaml", L".yml",  L".toml", L".ini",
        L".cfg",  L".conf", L".env",  L".log",

        /* --- Mã nguồn --- */
        L".cpp",  L".h",    L".c",    L".hpp",  L".cs",   L".py",
        L".js",   L".ts",   L".java", L".php",  L".html", L".css",
        L".go",   L".rs",   L".rb",   L".sh",   L".pl",   L".lua",
        L".swift",L".kt",   L".vb",   L".asm",  L".sln",  L".vcxproj",

        /* --- Khoá / chứng chỉ — mất là mất vĩnh viễn --- */
        L".pem",  L".key",  L".crt",  L".pfx",  L".p12",  L".kdbx", L".ovpn",

        /* --- Mail / lịch / danh bạ --- */
        L".pst",  L".ost",  L".eml",  L".msg",  L".vcf",  L".ics",

        /* --- CAD / 3D --- */
        L".vsd",  L".dwg",  L".dxf",  L".skp",  L".stl",  L".obj",
        L".fbx",  L".blend",

        /* --- Máy ảo — một file = cả hệ thống --- */
        L".vmdk", L".vdi",  L".vhd",  L".vhdx", L".ova",
    };

    /* Không backup file thực thi — chúng không phải mục tiêu của ransomware */
    inline const std::set<std::wstring> EXECUTABLE_EXTS = {
        L".exe", L".dll", L".sys", L".bat", L".cmd", L".ps1",
        L".msi", L".vbs", L".com", L".scr", L".hta", L".pif", L".cpl",
    };

    /* ---------- Quota động (mục 4.1.3) ---------- */
    constexpr uint64_t RESERVE_MIN_BYTES = 10ull * 1024 * 1024 * 1024;  // 10GB
    constexpr double   RESERVE_PCT_CAPACITY = 0.05;   // hoặc 5% dung lượng ổ
    constexpr double   BUDGET_PCT_OF_FREE = 0.30;   // trần store = 30% (free - reserve)

    constexpr uint64_t TIER0_CAP = 100ull * 1024 * 1024;        // score 0-1: 100MB
    constexpr double   TIER0_PCT = 0.02;
    constexpr uint64_t TIER1_CAP = 500ull * 1024 * 1024;        // score 2-3: 500MB
    constexpr double   TIER1_PCT = 0.10;
    constexpr uint64_t TIER2_CAP = 2ull * 1024 * 1024 * 1024;   // score 4-5: 2GB
    constexpr double   TIER2_PCT = 0.25;
    constexpr double   TIER3_PCT = 0.60;                        // score >=6: 60% BUDGET

    constexpr int DISK_RECHECK_SEC = 60;

    /* ---------- LRU theo giá trị (mục 4.1.4) ---------- */
    //  V(f) = 3*A + 2*P + 2*R - 4*J
    constexpr double W_AGE = 3.0;
    constexpr double W_PROVENANCE = 2.0;
    constexpr double W_RECENT = 2.0;
    constexpr double W_JUNK = 4.0;
    constexpr double V_PROTECT_THRESHOLD = 4.0;   // V > ngưỡng này thì thà ngừng backup còn hơn evict

    /* ---------- Sliding window (mục 4.2.1) ---------- */
    constexpr int    WINDOW_SEC = 30;
    constexpr double RATE_IO_THRESHOLD = 20.0;  // F10: ops/giây
    constexpr double RATE_RENAME_THRESHOLD = 5.0;   // F11: renames/giây
    constexpr double RATE_DIRENT_THRESHOLD = 30.0;  // F9:  entries/giây

    /* ---------- Entropy (mục 5.2) ---------- */
    constexpr double ENTROPY_DELTA_THRESHOLD = 2.0;   // F13: ΔH
    constexpr double ENTROPY_ABS_THRESHOLD = 6.5;   // F13: H sau
    constexpr double DAA_THRESHOLD = 56.0;  // F14: 56 Bit-Bytes (Davies 2021, Table 7)
    constexpr double ENTROPY_PACKED_SECTION = 7.0;   // F2:  section thực thi
    constexpr size_t ENTROPY_SAMPLE_BYTES = 4096;  // F12/F13 đọc 4KB

    /* ---------- Cleanup (mục 4.1.6) ---------- */
    constexpr int    EARLY_CLEANUP_INTERVAL_SEC = 30;
    constexpr int    EARLY_CLEANUP_AGE_SEC = 60;
    constexpr size_t EARLY_CLEANUP_KEEP_RECENT = 20;   // cửa sổ an toàn
    constexpr int    EXIT_GRACE_PERIOD_SEC = 600;  // 10 phút cho score 2-5
    constexpr int    ORPHAN_MAX_AGE_HOURS = 24;
    constexpr int    HEARTBEAT_INTERVAL_SEC = 10;

    /* ---------- ML ---------- */
    inline const std::wstring ML_HOST = L"127.0.0.1";
    constexpr int  ML_PORT = 5000;
    inline const std::wstring ML_PATH = L"/predict";
    constexpr int  ML_TIMEOUT_MS = 2000;
    constexpr int  ML_DEBOUNCE_MS = 500;
    constexpr int  ML_MIN_INTERVAL_MS = 1000;

    /* ---------- Công cụ ngoài (TUỲ CHỌN) ----------
       Đặt cạnh RansomWall.exe:
           <exe_dir>\die\diec.exe   +  <exe_dir>\die\db\
           <exe_dir>\floss.exe
       Không có thì tự động dùng phân tích PE thuần (native).
    */
    inline const std::wstring DIE_REL_PATH = L"\\die\\diec.exe";
    inline const std::wstring DIE_DB_REL_PATH = L"\\die\\db";
    inline const std::wstring FLOSS_REL_PATH = L"\\floss.exe";

    constexpr DWORD  DIE_TIMEOUT_MS = 8000;
    constexpr DWORD  FLOSS_TIMEOUT_MS = 15000;
    constexpr size_t TOOL_MAX_OUTPUT = 8 * 1024 * 1024;
    constexpr uint64_t FLOSS_MAX_FILE_SIZE = 10ull * 1024 * 1024;  // file > 10MB bỏ qua FLOSS

    /* ---------- Watcher file thực thi mới ---------- */
    constexpr int    NEWEXE_SETTLE_TIMEOUT_MS = 30000;
    constexpr uint64_t NEWEXE_MAX_SIZE = 200ull * 1024 * 1024;

    /* Thư mục hệ thống: KHÔNG quét tĩnh nếu file có chữ ký hợp lệ. */
    inline const std::vector<std::wstring> SYSTEM_DIRS = {
        L"c:\\windows\\",
        L"c:\\program files\\",
        L"c:\\program files (x86)\\",
        L"c:\\programdata\\microsoft\\",
    };

    /* ---------- Honey files ---------- */
    // Tiến trình được phép chạm honey file mà không bị tính điểm
    inline const std::set<std::wstring> HONEY_WHITELIST = {
        L"explorer.exe", L"searchindexer.exe", L"searchprotocolhost.exe",
        L"msmpeng.exe",  L"searchfilterhost.exe", L"dllhost.exe",
        L"backgroundtaskhost.exe", L"runtimebroker.exe",
    };

} // namespace rw::cfg