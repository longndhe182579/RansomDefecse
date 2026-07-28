/*
 * RwProtocol.h — Giao thức dùng chung giữa Kernel Driver và User-Space.
 *
 * File này được include bởi CẢ HAI phía. Không được dùng kiểu C++ hay STL ở đây.
 * Mọi struct phải POD và có layout ổn định.
 *
 * ===========================================================================
 * BẢN VÁ v4.4
 * ===========================================================================
 *   [FIX 11] Thêm RwActionRead — sự kiện MỞ ĐỌC file giá trị.
 *
 *            Lý do: Chaos KHÔNG ghi đè file gốc. Nó:
 *              1. Mở file gốc CHỈ ĐỌC        <- ta không thấy
 *              2. Mã hoá trong bộ nhớ
 *              3. Tạo file mới "<goc>.1bnp"  <- FILE_CREATE, không có gì để cứu
 *              4. Xoá file gốc
 *
 *            Toàn bộ diễn ra ngoài tầm hook cũ (chỉ bắt thao tác GHI).
 *            Bằng chứng: log không có một event rename/delete nào, và
 *            honey file không bao giờ bị chạm dù nằm đúng đường đi.
 *
 *            Event này gửi KHÔNG PEND (IsPending=0) — không chặn IRP, không
 *            round-trip 200ms. Chỉ để user-space kiểm honey file (F4) và
 *            đếm mật độ I/O.
 *
 * ===========================================================================
 * BẢN VÁ v4.5
 * ===========================================================================
 *   [FIX 21] SỬA MÔ TẢ SAI CỦA TRƯỜNG FileRef.
 *
 *            Comment cũ khai FileRef là "FileInternalInformation — bất biến
 *            khi rename". SAI. Driver.c::HandleMutation gán:
 *
 *                ev.FileRef = PathHash64(name);
 *
 *            Đây là BĂM ĐƯỜNG DẪN, không phải file ID của NTFS. Hệ quả thật:
 *              - Đổi tên file rồi ghi  -> key khác  -> first-touch lần hai
 *                -> backup thêm một bản. Tốn quota nhưng AN TOÀN.
 *              - Hard link / junction trỏ tới cùng file -> hai key khác nhau.
 *              - KHÔNG có chuyện "bất biến khi rename".
 *
 *            Nếu sau này muốn đúng nghĩa file ID, phải gọi
 *            FltQueryInformationFile(FileInternalInformation) trong pre-op —
 *            tốn thêm một round-trip xuống file system, cân nhắc kỹ với
 *            ngân sách 200ms.
 * ===========================================================================
 */

#pragma once

#define RW_PORT_NAME        L"\\RansomWallPort"
#define RW_MAX_PATH         520
#define RW_MAX_CMDLINE      520

 /* Số client tối đa kết nối vào port (chỉ 1 = RansomWall.exe) */
#define RW_MAX_CONNECTIONS  1

/* Timeout khi driver chờ user-space trả lời (đơn vị 100ns, số âm = relative) */
#define RW_REPLY_TIMEOUT_100NS  (-2000000LL)   /* 200ms */

/* ---------------------------------------------------------------------------
   Hành động mà driver báo lên
   --------------------------------------------------------------------------- */
typedef enum _RW_ACTION {
    RwActionNone = 0,
    RwActionWrite = 1,
    RwActionRename = 2,
    RwActionDelete = 3,
    RwActionDirQuery = 4,   /* IRP_MJ_DIRECTORY_CONTROL  -> F9 */
    RwActionProcessCreate = 5,   /* PsSetCreateProcessNotifyRoutineEx -> F6/F7 */
    RwActionProcessExit = 6,
    RwActionRegPersist = 7,   /* CmRegisterCallbackEx      -> F8 */

    /*
     * [FIX 11] MỞ ĐỌC file giá trị. LUÔN gửi với IsPending = 0.
     *
     * Honey file là BẪY: chạm vào là đủ, không cần chờ nó bị ghi.
     * Đây là tín hiệu NHANH NHẤT có được — ransomware phải đọc trước khi
     * mã hoá, nên event này đến sớm hơn mọi feature khác.
     *
     * LƯU Ý CHÍNH XÁC: event này sinh trong PreCreate khi DesiredAccess có
     * FILE_READ_DATA/GENERIC_READ. Đó là "MỞ file với ý định đọc", MỘT LẦN
     * cho mỗi handle — KHÔNG phải mỗi thao tác đọc. Driver KHÔNG hook
     * IRP_MJ_READ. Đừng mô tả F10 là "đếm số thao tác đọc".
     */
    RwActionRead = 8
} RW_ACTION;

/* ---------------------------------------------------------------------------
   Event: driver -> user-space
   --------------------------------------------------------------------------- */
#pragma pack(push, 8)
typedef struct _RW_EVENT {
    unsigned long   Pid;
    unsigned long   RootPid;        /* gốc cây tiến trình — điểm luôn quy về đây */
    unsigned long   Action;         /* RW_ACTION */

    unsigned char   IsPending;      /* 1 = IRP đang treo, BẮT BUỘC phải reply    */
    unsigned char   IsFirstTouch;   /* 1 = lần đầu cặp (Pid, FileRef)            */
    unsigned char   Reserved[2];

    unsigned long   DirEntryCount;  /* RwActionDirQuery: số entry
                                       RwActionWrite (pend): NT create disposition */

                                       /* [FIX 21] BĂM ĐƯỜNG DẪN (PathHash64), KHÔNG phải FileInternalInformation.
                                          Đổi tên file -> giá trị này ĐỔI THEO. Xem đầu file. */
    long long       FileRef;

    unsigned long long ProcessStartTime; /* FILETIME — chống PID reuse            */

    wchar_t         FilePath[RW_MAX_PATH];      /* kernel format \Device\Harddisk... */
    wchar_t         CommandLine[RW_MAX_CMDLINE];/* chỉ với RwActionProcessCreate     */
} RW_EVENT, * PRW_EVENT;
#pragma pack(pop)

/* ---------------------------------------------------------------------------
   Reply: user-space -> driver (trả lời cho event IsPending)
   --------------------------------------------------------------------------- */
typedef enum _RW_REPLY_CODE {
    RwReplyContinue = 0,   /* backup xong, cho IRP đi tiếp */
    RwReplyDeny = 1    /* chặn IRP này                 */
} RW_REPLY_CODE;

#pragma pack(push, 8)
typedef struct _RW_REPLY {
    unsigned long Code;    /* RW_REPLY_CODE */
} RW_REPLY, * PRW_REPLY;
#pragma pack(pop)

/* ---------------------------------------------------------------------------
   Command: user-space -> driver (qua FilterSendMessage)
   --------------------------------------------------------------------------- */
typedef enum _RW_CMD_CODE {
    RwCmdSetSelfPid = 1,   /* whitelist chính RansomWall.exe */
    RwCmdDenyPid = 2,   /* deny mọi IRP của PID này       */
    RwCmdUndenyPid = 3,
    RwCmdPauseCow = 4,   /* free disk < RESERVE -> fail-open, ngừng pend */
    RwCmdResumeCow = 5
} RW_CMD_CODE;

#pragma pack(push, 8)
typedef struct _RW_COMMAND {
    unsigned long Code;    /* RW_CMD_CODE */
    unsigned long Pid;
} RW_COMMAND, * PRW_COMMAND;
#pragma pack(pop)