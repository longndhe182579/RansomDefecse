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
 * ===========================================================================
 */

#pragma once

#define RW_PORT_NAME        L"\\RansomDefensePort"
#define RW_MAX_PATH         520
#define RW_MAX_CMDLINE      520

 /* Số client tối đa kết nối vào port (chỉ 1 = RansomDefense.exe) */
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
    long long       FileRef;        /* FileInternalInformation — bất biến khi rename */
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
    RwCmdSetSelfPid = 1,   /* whitelist chính RansomDefense.exe */
    RwCmdDenyPid = 2,   /* deny mọi IRP của PID này       */
    RwCmdUndenyPid = 3,
    RwCmdPauseCow = 4,   /* free disk < RESERVE -> fail-open, ngừng pend */
    RwCmdResumeCow = 5,
    RwCmdClearTouch = 6
} RW_CMD_CODE;

#pragma pack(push, 8)
typedef struct _RW_COMMAND {
    unsigned long Code;    /* RW_CMD_CODE */
    unsigned long Pid;
    long long FileRef;
} RW_COMMAND, * PRW_COMMAND;
#pragma pack(pop)
