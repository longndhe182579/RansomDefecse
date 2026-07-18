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
    // Nếu driver chưa load, chương trình tự chuyển sang SIMULATION
    // (ReadDirectoryChangesW). Chế độ này KHÔNG pend được -> backup có thể
    // chậm hơn ransomware. Chỉ dùng để test logic, không phải bảo vệ thật.

    /* ---------- Đường dẫn ---------- */
    inline const std::wstring BACKUP_ROOT = L"C:\\RansomWall_Backup";
    inline const std::wstring QUARANTINE_ROOT = L"C:\\RansomWall_Quarantine";
    inline const std::wstring RESTORED_ROOT = L"C:\\RansomWall_Restored";
    inline const std::wstring SESSION_FILE = L"C:\\RansomWall_Backup\\.session";

    /* ---------- Ngưỡng điểm ---------- */
    constexpr int SCORE_ML_TRIGGER = 6;   // gọi ML
    constexpr int SCORE_FREEZE = 2;   // đóng băng backup, tắt LRU
    constexpr int SCORE_CLEANUP_MAX = 1;   // <= giá trị này thì early cleanup được phép

    /* ---------- CoW: điều kiện backup ---------- */
    constexpr uint64_t MAX_BACKUP_FILE_SIZE = 50ull * 1024 * 1024;   // 50MB

    inline const std::set<std::wstring> VALUABLE_EXTS = {
        L".doc",  L".docx", L".xls",  L".xlsx", L".ppt",  L".pptx",
        L".pdf",  L".txt",  L".rtf",  L".odt",  L".csv",  L".md",
        L".jpg",  L".jpeg", L".png",  L".gif",  L".bmp",  L".psd", L".raw",
        L".mp3",  L".mp4",  L".avi",  L".mov",  L".wav",
        L".zip",  L".rar",  L".7z",   L".tar",  L".gz",
        L".sql",  L".db",   L".mdb",  L".accdb",L".json", L".xml",
        L".cpp",  L".h",    L".c",    L".hpp",  L".cs",   L".py",
        L".js",   L".ts",   L".java", L".php",  L".html", L".css",
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
    constexpr double RATE_DIRENT_THRESHOLD = 100.0; // F9:  entries/giây

    /* ---------- Entropy (mục 5.2) ---------- */
    constexpr double ENTROPY_DELTA_THRESHOLD = 2.0;   // F13: ΔH
    constexpr double ENTROPY_ABS_THRESHOLD = 7.5;   // F13: H sau
    constexpr double ENTROPY_PACKED_SECTION = 7.0;   // F2:  section thực thi
    constexpr size_t ENTROPY_SAMPLE_BYTES = 4096;  // F12/F13 đọc 4KB, KHÔNG phải 16 byte

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

       Native bắt được packer LẠ (entropy theo section) mà DIE chưa biết.
       DIE bắt được packer ĐÃ BIẾT chính xác hơn (database hàng nghìn signature).
       FLOSS bóc được chuỗi dựng trên stack lúc chạy — thứ native KHÔNG làm được,
       và đó chính là kỹ thuật ransomware dùng để né quét chuỗi tĩnh.
    */
    inline const std::wstring DIE_REL_PATH = L"\\die\\diec.exe";
    inline const std::wstring DIE_DB_REL_PATH = L"\\die\\db";
    inline const std::wstring FLOSS_REL_PATH = L"\\floss.exe";

    constexpr DWORD  DIE_TIMEOUT_MS = 5000;
    constexpr DWORD  FLOSS_TIMEOUT_MS = 20000;   // FLOSS emulate, rất chậm
    constexpr size_t TOOL_MAX_OUTPUT = 8 * 1024 * 1024;

    /* ---------- Watcher file thực thi mới ----------
       Chỉ phân tích file thực thi XUẤT HIỆN SAU KHI RansomWall khởi động.
       File đã có sẵn từ trước KHÔNG quét — giả định: RansomWall chạy trước
       khi mối đe doạ tới. Đây là mô hình real-time protection tiêu chuẩn.

       Khi tiến trình chạy, điểm tĩnh đã sẵn trong cache -> áp ngay lập tức. */
       /* Thời gian chờ file ghi xong trước khi quét.
          120s: gõ mật khẩu zip, giải nén file lớn, copy qua mạng, VM emulated...
          Chờ trên thread nền nên không tốn gì; timeout ngắn thì MẤT file. */
    constexpr int    NEWEXE_SETTLE_TIMEOUT_MS = 120000;
    constexpr uint64_t NEWEXE_MAX_SIZE = 200ull * 1024 * 1024;

    /* Thư mục hệ thống: KHÔNG quét tĩnh nếu file có chữ ký hợp lệ.
       Ransomware không nằm ở đây; quét chúng chỉ tốn DIE/FLOSS vô ích. */
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