/*
 * RwProtocol.h — Giao thức dùng chung giữa Kernel Driver và User-Space.
 *
 * File này được include bởi CẢ HAI phía. Không được dùng kiểu C++ hay STL ở đây.
 * Mọi struct phải POD và có layout ổn định.
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
    RwActionRegPersist = 7    /* CmRegisterCallbackEx      -> F8 */
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

    unsigned long   DirEntryCount;  /* chỉ có nghĩa với RwActionDirQuery         */
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
