/*
 * Driver.c — RansomWall Kernel Minifilter
 *
 * Chỉ hook thao tác GHI (write/rename/delete) là không đủ: một số họ
 * ransomware không ghi đè file gốc mà mở file CHỈ ĐỌC, mã hoá trong bộ nhớ,
 * ghi ra file mới với đuôi ngẫu nhiên (vd "RansomWall.pdb" -> "*.1bnp") rồi
 * xoá file gốc. Bước tạo file mới đi qua nhánh FILE_CREATE (được thả ngay vì
 * không có gì để cứu/bẫy), nên toàn bộ chuỗi này nằm ngoài tầm hook ghi và
 * honey file không bao giờ bị chạm tới.
 *
 * Vì vậy PreCreate còn gửi thêm event RwActionRead khi phát hiện mở đọc file
 * giá trị, dùng để user-space kiểm honey file và đếm mật độ I/O (không dùng
 * để backup — đọc không phá dữ liệu nên không cần backup). Event này KHÔNG
 * PEND (FltSendMessage với WaitReply = FALSE): IRP không bị chặn, không
 * round-trip chờ user-space, chi phí chỉ là băng thông message chứ không
 * phải độ trễ I/O. Nó dùng key FirstTouch riêng (XOR RW_READ_MARK) để không
 * đụng slot FirstTouch của thao tác ghi theo sau trên cùng file.
 *
 * gValuableExts PHẢI khớp cfg::VALUABLE_EXTS trong Config.h. Chuỗi cha-con
 * dùng để tính RootPid dừng lại tại các tiến trình shell (xem IsShellImage)
 * vì tiến trình con sinh ra từ shell không nên bị gộp vào cùng gốc với các
 * tiến trình khác mà shell từng sinh ra trước đó.
 *
 * CẢNH BÁO:
 *   - CHỈ chạy trong VM. Lỗi kernel = BSOD, không phải exception.
 *   - Cần: bcdedit /set testsigning on  + reboot
 *   - IRQL: FltSendMessage yêu cầu PASSIVE_LEVEL.
 *   - Paging I/O KHÔNG được pend (deadlock với memory manager).
 */

#include <fltKernel.h>
#include <dontuse.h>
#include <ntstrsafe.h>
#include "RwProtocol.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

 /*
  * RW_COW_BLACKLIST_MODE (tuỳ chọn, mặc định tắt): whitelist đuôi file là
  * mô hình thua trước đuôi file ngẫu nhiên — đuôi lạ không nằm trong danh
  * sách nên các bước tạo/xoá file mới đều vô hình với whitelist. Bật cờ này
  * để pend MỌI đuôi TRỪ file thực thi, giúp IsMassNewExtension bắt được
  * "cùng một đuôi lạ xuất hiện trên nhiều file" và cộng điểm sớm hơn. Đánh
  * đổi: tải I/O tăng đáng kể, nên đo tách biệt với việc bật theo dõi mở đọc
  * để không nhầm lẫn nguyên nhân gây lag.
  */
#define RW_COW_BLACKLIST_MODE 0

  /* Bật/tắt event mở đọc; đặt 0 nếu cần loại trừ nguyên nhân gây lag. */
#define RW_TRACK_READ_OPEN 1

   /* Marker XOR để tách không gian key đọc khỏi key ghi */
#define RW_READ_MARK 0x5245414400000000LL   /* "READ" */

/* ---- Globals ---- */

typedef struct _RW_GLOBALS {
    PFLT_FILTER     Filter;
    PFLT_PORT       ServerPort;
    PFLT_PORT       ClientPort;

    ULONG           SelfPid;
    BOOLEAN         CowPaused;

    LARGE_INTEGER   RegCookie;
    BOOLEAN         RegCallbackOn;
    BOOLEAN         ProcessNotifyOn;
} RW_GLOBALS;

RW_GLOBALS gRw = { 0 };

static BOOLEAN PathContainsCI(PCUNICODE_STRING Path, PCWSTR Needle);   /* fwd decl */

/* ---- FirstTouchTable: hash table (PID, Key) -> đã chạm chưa ---- */
#define FT_BUCKETS 1024

typedef struct _FT_ENTRY {
    LIST_ENTRY  Link;
    ULONG       Pid;
    LONGLONG    FileRef;
} FT_ENTRY, * PFT_ENTRY;

LIST_ENTRY  gFtBucket[FT_BUCKETS];
KSPIN_LOCK  gFtLock;

#define RW_TAG 'llWR'

static LONGLONG PathHash64(PCUNICODE_STRING p) {
    LONGLONG h = 1469598103934665603LL;
    USHORT n = p->Length / sizeof(WCHAR);
    for (USHORT i = 0; i < n; i++) {
        h ^= (LONGLONG)RtlUpcaseUnicodeChar(p->Buffer[i]);
        h *= 1099511628211LL;
    }
    return h;
}

static ULONG FtHash(ULONG Pid, LONGLONG FileRef) {
    ULONGLONG h = ((ULONGLONG)Pid * 2654435761ULL) ^ ((ULONGLONG)FileRef * 40503ULL);
    return (ULONG)(h % FT_BUCKETS);
}

static BOOLEAN FtTestAndSet(ULONG Pid, LONGLONG FileRef) {
    ULONG idx = FtHash(Pid, FileRef);
    KIRQL oldIrql;
    PLIST_ENTRY e;
    PFT_ENTRY entry;
    BOOLEAN isFirst = TRUE;

    PFT_ENTRY fresh = (PFT_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(FT_ENTRY), RW_TAG);
    if (fresh == NULL) return FALSE;

    KeAcquireSpinLock(&gFtLock, &oldIrql);
    for (e = gFtBucket[idx].Flink; e != &gFtBucket[idx]; e = e->Flink) {
        entry = CONTAINING_RECORD(e, FT_ENTRY, Link);
        if (entry->Pid == Pid && entry->FileRef == FileRef) { isFirst = FALSE; break; }
    }
    if (isFirst) {
        fresh->Pid = Pid;
        fresh->FileRef = FileRef;
        InsertHeadList(&gFtBucket[idx], &fresh->Link);
    }
    KeReleaseSpinLock(&gFtLock, oldIrql);

    if (!isFirst) ExFreePoolWithTag(fresh, RW_TAG);
    return isFirst;
}

/* Nhả lại MỘT slot First Touch — dùng khi backup thất bại nhưng IRP vẫn
   được cho đi tiếp (RwCmdClearTouch), để lần ghi kế tiếp vào đúng file
   được pend lại thay vì mất bảo vệ vĩnh viễn cho hết vòng đời tiến trình. */
static VOID FtRemoveEntry(ULONG Pid, LONGLONG FileRef) {
    ULONG idx = FtHash(Pid, FileRef);
    KIRQL oldIrql;
    KeAcquireSpinLock(&gFtLock, &oldIrql);
    for (PLIST_ENTRY e = gFtBucket[idx].Flink; e != &gFtBucket[idx]; e = e->Flink) {
        PFT_ENTRY entry = CONTAINING_RECORD(e, FT_ENTRY, Link);
        if (entry->Pid == Pid && entry->FileRef == FileRef) {
            RemoveEntryList(e);
            KeReleaseSpinLock(&gFtLock, oldIrql);
            ExFreePoolWithTag(entry, RW_TAG);
            return;
        }
    }
    KeReleaseSpinLock(&gFtLock, oldIrql);
}

static VOID FtRemovePid(ULONG Pid) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&gFtLock, &oldIrql);
    for (ULONG i = 0; i < FT_BUCKETS; i++) {
        PLIST_ENTRY e = gFtBucket[i].Flink;
        while (e != &gFtBucket[i]) {
            PFT_ENTRY entry = CONTAINING_RECORD(e, FT_ENTRY, Link);
            PLIST_ENTRY next = e->Flink;
            if (entry->Pid == Pid) {
                RemoveEntryList(e);
                ExFreePoolWithTag(entry, RW_TAG);
            }
            e = next;
        }
    }
    KeReleaseSpinLock(&gFtLock, oldIrql);
}

static VOID FtFlushAll(VOID) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&gFtLock, &oldIrql);
    for (ULONG i = 0; i < FT_BUCKETS; i++) {
        while (!IsListEmpty(&gFtBucket[i])) {
            PLIST_ENTRY e = RemoveHeadList(&gFtBucket[i]);
            ExFreePoolWithTag(CONTAINING_RECORD(e, FT_ENTRY, Link), RW_TAG);
        }
    }
    KeReleaseSpinLock(&gFtLock, oldIrql);
}

/* ---- Process tree: Pid -> RootPid (chuỗi dừng tại tiến trình shell) ---- */
#define PT_BUCKETS 256

typedef struct _PT_ENTRY {
    LIST_ENTRY Link;
    ULONG      Pid;
    ULONG      RootPid;
    BOOLEAN    IsRwDescendant;
    BOOLEAN    IsShell;
} PT_ENTRY, * PPT_ENTRY;

LIST_ENTRY gPtBucket[PT_BUCKETS];
KSPIN_LOCK gPtLock;

static ULONG PtHash(ULONG Pid) { return (Pid * 2654435761U) % PT_BUCKETS; }

static ULONG PtGetRoot(ULONG Pid) {
    KIRQL oldIrql; ULONG root = Pid;
    KeAcquireSpinLock(&gPtLock, &oldIrql);
    for (PLIST_ENTRY e = gPtBucket[PtHash(Pid)].Flink;
        e != &gPtBucket[PtHash(Pid)]; e = e->Flink) {
        PPT_ENTRY p = CONTAINING_RECORD(e, PT_ENTRY, Link);
        if (p->Pid == Pid) { root = p->RootPid; break; }
    }
    KeReleaseSpinLock(&gPtLock, oldIrql);
    return root;
}

static BOOLEAN PtIsRwDescendant(ULONG Pid) {
    KIRQL oldIrql; BOOLEAN r = FALSE;
    KeAcquireSpinLock(&gPtLock, &oldIrql);
    for (PLIST_ENTRY e = gPtBucket[PtHash(Pid)].Flink;
        e != &gPtBucket[PtHash(Pid)]; e = e->Flink) {
        PPT_ENTRY p = CONTAINING_RECORD(e, PT_ENTRY, Link);
        if (p->Pid == Pid) { r = p->IsRwDescendant; break; }
    }
    KeReleaseSpinLock(&gPtLock, oldIrql);
    return r;
}

static BOOLEAN PtIsShell(ULONG Pid) {
    KIRQL oldIrql; BOOLEAN r = FALSE;
    KeAcquireSpinLock(&gPtLock, &oldIrql);
    for (PLIST_ENTRY e = gPtBucket[PtHash(Pid)].Flink;
        e != &gPtBucket[PtHash(Pid)]; e = e->Flink) {
        PPT_ENTRY p = CONTAINING_RECORD(e, PT_ENTRY, Link);
        if (p->Pid == Pid) { r = p->IsShell; break; }
    }
    KeReleaseSpinLock(&gPtLock, oldIrql);
    return r;
}

static BOOLEAN IsShellImage(PCUNICODE_STRING Image) {
    if (Image == NULL || Image->Length == 0) return FALSE;
    return PathContainsCI(Image, L"\\EXPLORER.EXE") ||
        PathContainsCI(Image, L"\\CMD.EXE") ||
        PathContainsCI(Image, L"\\POWERSHELL.EXE") ||
        PathContainsCI(Image, L"\\PWSH.EXE") ||
        PathContainsCI(Image, L"\\SERVICES.EXE") ||
        PathContainsCI(Image, L"\\SVCHOST.EXE") ||
        PathContainsCI(Image, L"\\USERINIT.EXE") ||
        PathContainsCI(Image, L"\\WINLOGON.EXE") ||
        PathContainsCI(Image, L"\\TASKHOSTW.EXE") ||
        PathContainsCI(Image, L"\\RUNTIMEBROKER.EXE") ||
        PathContainsCI(Image, L"\\WERFAULT.EXE") ||
        PathContainsCI(Image, L"\\CONHOST.EXE");
}

static VOID PtInsert(ULONG Pid, ULONG ParentPid, PCUNICODE_STRING Image) {
    BOOLEAN meShell = IsShellImage(Image);

    ULONG root;
    if (ParentPid == 0) {
        root = Pid;
    }
    else if (PtIsShell(ParentPid) && PtGetRoot(ParentPid) == ParentPid) {
        root = Pid;                       /* chuỗi DỪNG ở shell */
    }
    else {
        ULONG pr = PtGetRoot(ParentPid);
        root = (pr == ParentPid) ? Pid : pr;
    }

    BOOLEAN isRwDesc = (gRw.SelfPid != 0) &&
        (ParentPid == gRw.SelfPid || PtIsRwDescendant(ParentPid));

    PPT_ENTRY fresh = (PPT_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PT_ENTRY), RW_TAG);
    if (!fresh) return;
    fresh->Pid = Pid;
    fresh->RootPid = root;
    fresh->IsRwDescendant = isRwDesc;
    fresh->IsShell = meShell;

    KIRQL oldIrql;
    KeAcquireSpinLock(&gPtLock, &oldIrql);
    InsertHeadList(&gPtBucket[PtHash(Pid)], &fresh->Link);
    KeReleaseSpinLock(&gPtLock, oldIrql);
}

static VOID PtRemove(ULONG Pid) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&gPtLock, &oldIrql);
    PLIST_ENTRY head = &gPtBucket[PtHash(Pid)];
    for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
        PPT_ENTRY p = CONTAINING_RECORD(e, PT_ENTRY, Link);
        if (p->Pid == Pid) {
            RemoveEntryList(e); KeReleaseSpinLock(&gPtLock, oldIrql);
            ExFreePoolWithTag(p, RW_TAG); return;
        }
    }
    KeReleaseSpinLock(&gPtLock, oldIrql);
}

static VOID PtFlushAll(VOID) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&gPtLock, &oldIrql);
    for (ULONG i = 0; i < PT_BUCKETS; i++)
        while (!IsListEmpty(&gPtBucket[i]))
            ExFreePoolWithTag(CONTAINING_RECORD(RemoveHeadList(&gPtBucket[i]), PT_ENTRY, Link), RW_TAG);
    KeReleaseSpinLock(&gPtLock, oldIrql);
}

/* ---- Denied PID list ---- */
#define MAX_DENIED 64
ULONG      gDenied[MAX_DENIED] = { 0 };
KSPIN_LOCK gDeniedLock;

static BOOLEAN IsDenied(ULONG Pid) {
    KIRQL o; BOOLEAN r = FALSE;
    KeAcquireSpinLock(&gDeniedLock, &o);
    for (int i = 0; i < MAX_DENIED; i++) if (gDenied[i] == Pid) { r = TRUE; break; }
    KeReleaseSpinLock(&gDeniedLock, o);
    return r;
}
static VOID AddDenied(ULONG Pid) {
    KIRQL o;
    KeAcquireSpinLock(&gDeniedLock, &o);
    for (int i = 0; i < MAX_DENIED; i++) if (gDenied[i] == 0) { gDenied[i] = Pid; break; }
    KeReleaseSpinLock(&gDeniedLock, o);
}
static VOID RemoveDenied(ULONG Pid) {
    KIRQL o;
    KeAcquireSpinLock(&gDeniedLock, &o);
    for (int i = 0; i < MAX_DENIED; i++) if (gDenied[i] == Pid) gDenied[i] = 0;
    KeReleaseSpinLock(&gDeniedLock, o);
}

/* ---- Bộ lọc trước khi pend ---- */

static const PCWSTR gSkipDirs[] = {
    L"\\WINDOWS\\",
    L"\\PROGRAM FILES\\",
    L"\\PROGRAM FILES (X86)\\",
    L"\\PROGRAMDATA\\MICROSOFT\\",
    L"\\PROGRAMDATA\\PACKAGES\\",
    L"\\APPDATA\\LOCAL\\TEMP\\",
    L"\\APPDATA\\LOCAL\\MICROSOFT\\WINDOWS\\",
    L"\\APPDATA\\LOCAL\\PACKAGES\\",
    L"\\APPDATA\\LOCALLOW\\",
    L"\\$RECYCLE.BIN\\",
    L"\\SYSTEM VOLUME INFORMATION\\",
    L"\\PAGEFILE.SYS",
    L"\\SWAPFILE.SYS",
    L"\\HIBERFIL.SYS",
    L"\\.GIT\\",
    L"\\NODE_MODULES\\",
};

static BOOLEAN IsSkippedPath(PCUNICODE_STRING Path) {
    for (int i = 0; i < ARRAYSIZE(gSkipDirs); i++)
        if (PathContainsCI(Path, gSkipDirs[i])) return TRUE;
    return FALSE;
}

/* PHẢI KHỚP cfg::VALUABLE_EXTS TRONG Config.h */
static const PCWSTR gValuableExts[] = {
    L".DOC",  L".DOCX", L".DOCM", L".DOT",  L".DOTX", L".ODT",
    L".XLS",  L".XLSX", L".XLSM", L".XLT",  L".XLTX", L".ODS",
    L".PPT",  L".PPTX", L".PPTM", L".PPS",  L".PPSX", L".ODP",
    L".PDF",  L".TXT",  L".RTF",  L".CSV",  L".MD",   L".TEX",
    L".ONE",  L".PAGES",L".NUMBERS",

    L".JPG",  L".JPEG", L".PNG",  L".GIF",  L".BMP",  L".PSD",
    L".RAW",  L".TIF",  L".TIFF", L".WEBP", L".HEIC", L".SVG",
    L".ICO",  L".AI",   L".EPS",  L".CR2",  L".NEF",  L".ARW", L".DNG",

    L".MP3",  L".MP4",  L".AVI",  L".MOV",  L".WAV",  L".MKV",
    L".FLAC", L".M4A",  L".WMV",  L".FLV",  L".WEBM", L".M4V",
    L".AAC",  L".OGG",

    L".ZIP",  L".RAR",  L".7Z",   L".TAR",  L".GZ",   L".BZ2",
    L".XZ",   L".ISO",  L".CAB",

    L".SQL",  L".DB",   L".MDB",  L".ACCDB", L".SQLITE", L".SQLITE3",
    L".MDF",  L".LDF",  L".DBF",  L".FRM",  L".MYD",  L".BAK",

    L".JSON", L".XML",  L".YAML", L".YML",  L".TOML", L".INI",
    L".CFG",  L".CONF", L".ENV",  L".LOG",

    L".CPP",  L".H",    L".C",    L".HPP",  L".CS",   L".PY",
    L".JS",   L".TS",   L".JAVA", L".PHP",  L".HTML", L".CSS",
    L".GO",   L".RS",   L".RB",   L".SH",   L".PL",   L".LUA",
    L".SWIFT",L".KT",   L".VB",   L".ASM",  L".SLN",  L".VCXPROJ",

    L".PEM",  L".KEY",  L".CRT",  L".PFX",  L".P12",  L".KDBX", L".OVPN",

    L".PST",  L".OST",  L".EML",  L".MSG",  L".VCF",  L".ICS",

    L".VSD",  L".DWG",  L".DXF",  L".SKP",  L".STL",  L".OBJ",
    L".FBX",  L".BLEND",

    L".VMDK", L".VDI",  L".VHD",  L".VHDX", L".OVA",
};

static const PCWSTR gExecutableExts[] = {
    L".EXE", L".DLL", L".SYS", L".BAT", L".CMD", L".PS1",
    L".MSI", L".VBS", L".COM", L".SCR", L".HTA", L".PIF", L".CPL",
};

static BOOLEAN EndsWithCI(PCUNICODE_STRING Path, PCWSTR Suffix) {
    UNICODE_STRING s;
    RtlInitUnicodeString(&s, Suffix);
    if (Path->Length < s.Length) return FALSE;

    USHORT pChars = Path->Length / sizeof(WCHAR);
    USHORT sChars = s.Length / sizeof(WCHAR);
    USHORT off = pChars - sChars;

    for (USHORT i = sChars; i > 0; i--)
        if (RtlUpcaseUnicodeChar(Path->Buffer[off + i - 1]) !=
            RtlUpcaseUnicodeChar(s.Buffer[i - 1])) return FALSE;
    return TRUE;
}

static BOOLEAN IsValuableExt(PCUNICODE_STRING Path) {
#if RW_COW_BLACKLIST_MODE
    for (int i = 0; i < ARRAYSIZE(gExecutableExts); i++)
        if (EndsWithCI(Path, gExecutableExts[i])) return FALSE;
    return TRUE;
#else
    for (int i = 0; i < ARRAYSIZE(gValuableExts); i++)
        if (EndsWithCI(Path, gValuableExts[i])) return TRUE;
    return FALSE;
#endif
}

/* ---- Path blacklist (H1) ---- */
static const PCWSTR gBlacklist[] = {
    L"\\WINDOWS\\SYSTEM32\\",
    L"\\WINDOWS\\SYSWOW64\\",
    L"\\WINDOWS\\BOOT\\",
    L"\\WINDOWS\\WINSXS\\",
    L"\\RANSOMWALL_BACKUP",
    L"\\RANSOMWALL_QUARANTINE",
    L"\\RANSOMWALL_RESTORED",
};

static BOOLEAN PathContainsCI(PCUNICODE_STRING Path, PCWSTR Needle) {
    UNICODE_STRING n;
    RtlInitUnicodeString(&n, Needle);
    if (Path->Length < n.Length) return FALSE;

    USHORT pChars = Path->Length / sizeof(WCHAR);
    USHORT nChars = n.Length / sizeof(WCHAR);

    for (USHORT i = 0; i + nChars <= pChars; i++) {
        USHORT j = 0;
        for (; j < nChars; j++) {
            WCHAR a = RtlUpcaseUnicodeChar(Path->Buffer[i + j]);
            WCHAR b = RtlUpcaseUnicodeChar(n.Buffer[j]);
            if (a != b) break;
        }
        if (j == nChars) return TRUE;
    }
    return FALSE;
}

static BOOLEAN IsBlacklisted(PCUNICODE_STRING Path) {
    for (int i = 0; i < ARRAYSIZE(gBlacklist); i++)
        if (PathContainsCI(Path, gBlacklist[i])) return TRUE;
    return FALSE;
}

static const PCWSTR gTrustedImages[] = {
    L"\\WINDOWS\\SERVICING\\TRUSTEDINSTALLER.EXE",
    L"\\WINDOWS\\SYSTEM32\\WUAUCLT.EXE",
    L"\\WINDOWS\\SYSTEM32\\SVCHOST.EXE",
};

static BOOLEAN IsTrustedProcess(VOID) {
    if ((ULONG)(ULONG_PTR)PsGetCurrentProcessId() == gRw.SelfPid) return TRUE;

    PUNICODE_STRING img = NULL;
    NTSTATUS st = SeLocateProcessImageName(PsGetCurrentProcess(), &img);
    if (!NT_SUCCESS(st) || img == NULL) return FALSE;

    BOOLEAN trusted = FALSE;
    for (int i = 0; i < ARRAYSIZE(gTrustedImages); i++)
        if (PathContainsCI(img, gTrustedImages[i])) { trusted = TRUE; break; }

    ExFreePool(img);
    return trusted;
}

/* ---- Gửi event lên user-space ---- */
static NTSTATUS SendEvent(PRW_EVENT Ev, BOOLEAN WaitReply, PULONG ReplyCode) {
    if (gRw.ClientPort == NULL) return STATUS_PORT_DISCONNECTED;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;

    if (!WaitReply)
        return FltSendMessage(gRw.Filter, &gRw.ClientPort, Ev, sizeof(RW_EVENT),
            NULL, NULL, NULL);

    RW_REPLY reply = { 0 };
    ULONG replyLen = sizeof(reply);
    LARGE_INTEGER timeout;
    timeout.QuadPart = RW_REPLY_TIMEOUT_100NS;

    NTSTATUS st = FltSendMessage(gRw.Filter, &gRw.ClientPort, Ev, sizeof(RW_EVENT),
        &reply, &replyLen, &timeout);

    /* FAIL-OPEN: user-space treo/chết thì KHÔNG để máy đứng. */
    if (st == STATUS_TIMEOUT || !NT_SUCCESS(st)) {
        if (ReplyCode) *ReplyCode = RwReplyContinue;
        return STATUS_TIMEOUT;
    }
    if (ReplyCode) *ReplyCode = reply.Code;
    return STATUS_SUCCESS;
}

static BOOLEAN FillFileInfo(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
    PRW_EVENT Ev, PUNICODE_STRING* OutName, PFLT_FILE_NAME_INFORMATION* OutInfo)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS st = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(st)) return FALSE;

    FltParseFileNameInformation(nameInfo);

    ULONG copyLen = min(nameInfo->Name.Length, (RW_MAX_PATH - 1) * sizeof(WCHAR));
    RtlZeroMemory(Ev->FilePath, sizeof(Ev->FilePath));
    RtlCopyMemory(Ev->FilePath, nameInfo->Name.Buffer, copyLen);

    FILE_INTERNAL_INFORMATION fi = { 0 };
    ULONG ret = 0;
    if (NT_SUCCESS(FltQueryInformationFile(FltObjects->Instance, FltObjects->FileObject,
        &fi, sizeof(fi), FileInternalInformation, &ret)))
        Ev->FileRef = fi.IndexNumber.QuadPart;
    else
        Ev->FileRef = 0;

    *OutName = &nameInfo->Name;
    *OutInfo = nameInfo;
    return TRUE;
}

/* ---- Core: xử lý chung cho Write / Rename / Delete ---- */

static FLT_PREOP_CALLBACK_STATUS HandleMutation(
    PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, ULONG Action,
    PVOID* CompletionContext)
{
    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    if (pid == gRw.SelfPid) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (PtIsRwDescendant(pid)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (IsDenied(pid)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    RW_EVENT ev = { 0 };
    PUNICODE_STRING name = NULL;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

    if (!FillFileInfo(Data, FltObjects, &ev, &name, &nameInfo))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (IsBlacklisted(name)) {
        BOOLEAN trusted = IsTrustedProcess();
        FltReleaseFileNameInformation(nameInfo);
        if (!trusted) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (IsSkippedPath(name)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    BOOLEAN valuable = IsValuableExt(name);
    LONGLONG ftKey = PathHash64(name);
    FltReleaseFileNameInformation(nameInfo);

    ev.Pid = pid;
    ev.RootPid = PtGetRoot(pid);
    ev.Action = Action;
    ev.FileRef = ftKey;

    BOOLEAN isFirst = valuable && (!gRw.CowPaused) && FtTestAndSet(pid, ftKey);

    if (isFirst && KeGetCurrentIrql() == PASSIVE_LEVEL) {
        ev.IsPending = 1;
        ev.IsFirstTouch = 1;

        ULONG replyCode = RwReplyContinue;
        SendEvent(&ev, TRUE, &replyCode);

        if (replyCode == RwReplyDeny) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }

        /*
         * Đánh dấu để PostMutation gửi thêm MỘT event ASYNC sau khi ghi
         * THẬT SỰ hoàn tất -> Nhánh 2 (F10-F14) ở user-space có cơ hội
         * kiểm tra fingerprint/entropy/DAA cho đúng LẦN GHI ĐẦU TIÊN.
         * Không đánh dấu thì lần ghi đầu tiên (chính lúc nội dung bị mã
         * hoá) chỉ được backup rồi bỏ qua hoàn toàn, không đặc trưng động
         * nào được tính cho nó — ransomware ghi mỗi file đúng một lần sẽ
         * gần như tàng hình trước F10-F14.
         */
        *CompletionContext = (PVOID)(ULONG_PTR)1;
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    ev.IsPending = 0;
    ev.IsFirstTouch = 0;
    if (KeGetCurrentIrql() == PASSIVE_LEVEL)
        SendEvent(&ev, FALSE, NULL);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/*
 * PostMutation — chạy sau khi thao tác ghi/rename ĐÃ HOÀN TẤT thật sự trên
 * đĩa, CHỈ khi HandleMutation đã đánh dấu CompletionContext (đúng lần First
 * Touch bị pend). Gửi thêm một event ASYNC mang đúng nội dung SAU khi ghi,
 * để Nhánh 2 ở user-space có dữ liệu so sánh — xem giải thích ở HandleMutation.
 */
FLT_POSTOP_CALLBACK_STATUS PostMutation(
    _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    if (CompletionContext == NULL) return FLT_POSTOP_FINISHED_PROCESSING;
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) return FLT_POSTOP_FINISHED_PROCESSING;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return FLT_POSTOP_FINISHED_PROCESSING;
    if (!NT_SUCCESS(Data->IoStatus.Status)) return FLT_POSTOP_FINISHED_PROCESSING;

    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    if (pid == gRw.SelfPid) return FLT_POSTOP_FINISHED_PROCESSING;
    if (PtIsRwDescendant(pid)) return FLT_POSTOP_FINISHED_PROCESSING;

    ULONG action;
    ULONG major = Data->Iopb->MajorFunction;
    if (major == IRP_MJ_WRITE) {
        action = RwActionWrite;
    }
    else if (major == IRP_MJ_SET_INFORMATION) {
        switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass) {
        case FileRenameInformation:
        case FileRenameInformationEx:
            action = RwActionRename; break;
        default:
            /* Delete/Truncate: Nhánh 2 (main.cpp) không dùng tới, bỏ qua */
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
    }
    else {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    RW_EVENT ev = { 0 };
    PUNICODE_STRING name = NULL;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    if (!FillFileInfo(Data, FltObjects, &ev, &name, &nameInfo))
        return FLT_POSTOP_FINISHED_PROCESSING;
    FltReleaseFileNameInformation(nameInfo);

    ev.Pid = pid;
    ev.RootPid = PtGetRoot(pid);
    ev.Action = action;
    ev.IsPending = 0;
    ev.IsFirstTouch = 0;

    SendEvent(&ev, FALSE, NULL);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/*
 * PreCreate xử lý hai đường: (A) mở ghi / phá huỷ -> pend, chờ user-space
 * backup; (B) mở đọc -> gửi event không pend, chỉ để bắt honey file và đếm
 * mật độ I/O. Đường B là thứ bắt được kiểu ransomware đọc file gốc rồi ghi
 * ra file mới thay vì ghi đè — trường hợp đó đường A không bao giờ thấy gì.
 */
FLT_PREOP_CALLBACK_STATUS PreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    if (pid == gRw.SelfPid)                    return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (PtIsRwDescendant(pid))                 return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (Data->RequestorMode == KernelMode)     return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)   return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (IsDenied(pid)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    ULONG opts = Data->Iopb->Parameters.Create.Options;
    ULONG disp = (opts >> 24) & 0xFF;

    BOOLEAN destructive =
        (disp == FILE_SUPERSEDE || disp == FILE_OVERWRITE || disp == FILE_OVERWRITE_IF);
    BOOLEAN delOnClose = FlagOn(opts, FILE_DELETE_ON_CLOSE) ? TRUE : FALSE;

    ACCESS_MASK acc = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    BOOLEAN wantsWrite = FlagOn(acc,
        FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | GENERIC_WRITE | GENERIC_ALL)
        ? TRUE : FALSE;

    /* Mở đọc — kiểu tấn công đọc-file-gốc-rồi-ghi-ra-file-mới dùng đường này */
    BOOLEAN wantsRead = FlagOn(acc, FILE_READ_DATA | GENERIC_READ) ? TRUE : FALSE;

    BOOLEAN writePath = (destructive || delOnClose || wantsWrite);

#if RW_TRACK_READ_OPEN
    if (!writePath && !wantsRead) return FLT_PREOP_SUCCESS_NO_CALLBACK;
#else
    if (!writePath) return FLT_PREOP_SUCCESS_NO_CALLBACK;
#endif

    /* File mới toanh — không có gì để cứu, cũng không có gì để bẫy */
    if (disp == FILE_CREATE) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* Đường GHI cần CoW đang bật; đường ĐỌC thì không (chỉ tính điểm) */
    if (writePath && gRw.CowPaused) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* Pre-create PHẢI dùng FLT_FILE_NAME_OPENED (NORMALIZED chưa sẵn sàng) */
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    if (!NT_SUCCESS(FltGetFileNameInformation(Data,
        FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    FltParseFileNameInformation(nameInfo);

    if (IsBlacklisted(&nameInfo->Name) ||
        IsSkippedPath(&nameInfo->Name) ||
        !IsValuableExt(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    LONGLONG key = PathHash64(&nameInfo->Name);

    /* ---- Đường B: mở đọc — không pend, không chặn IRP ---- */
#if RW_TRACK_READ_OPEN
    if (!writePath) {
        /* Key riêng để không ăn mất slot pend của thao tác GHI sau này */
        BOOLEAN firstRead = FtTestAndSet(pid, key ^ RW_READ_MARK);
        if (!firstRead) {
            FltReleaseFileNameInformation(nameInfo);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        RW_EVENT rev = { 0 };
        rev.Pid = pid;
        rev.RootPid = PtGetRoot(pid);
        rev.Action = RwActionRead;
        rev.IsPending = 0;          /* <<< KHÔNG CHỜ. IRP đi tiếp ngay. */
        rev.IsFirstTouch = 1;
        rev.FileRef = key;
        rev.DirEntryCount = disp;

        ULONG rlen = min(nameInfo->Name.Length, (RW_MAX_PATH - 1) * sizeof(WCHAR));
        RtlCopyMemory(rev.FilePath, nameInfo->Name.Buffer, rlen);
        FltReleaseFileNameInformation(nameInfo);

        SendEvent(&rev, FALSE, NULL);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
#endif

    /* ---- Đường A: mở ghi / phá huỷ — pend, chờ user-space backup ---- */
    BOOLEAN isFirst = FtTestAndSet(pid, key);

#ifdef RW_VERBOSE_TRACE
    DbgPrint("[RW-KEY] pid=%lu disp=%lu first=%d key=%lld path=%wZ\n",
        pid, disp, isFirst, key, &nameInfo->Name);
#endif

    if (!isFirst) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    RW_EVENT ev = { 0 };
    ev.Pid = pid;
    ev.RootPid = PtGetRoot(pid);
    ev.Action = RwActionWrite;
    ev.IsPending = 1;
    ev.IsFirstTouch = 1;
    ev.FileRef = key;
    ev.DirEntryCount = disp;

    ULONG copyLen = min(nameInfo->Name.Length, (RW_MAX_PATH - 1) * sizeof(WCHAR));
    RtlCopyMemory(ev.FilePath, nameInfo->Name.Buffer, copyLen);
    FltReleaseFileNameInformation(nameInfo);

    ULONG replyCode = RwReplyContinue;
    SendEvent(&ev, TRUE, &replyCode);

    if (replyCode == RwReplyDeny) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS PreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    return HandleMutation(Data, FltObjects, RwActionWrite, CompletionContext);
}

FLT_PREOP_CALLBACK_STATUS PreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    FILE_INFORMATION_CLASS cls = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    ULONG action;

    switch (cls) {
    case FileRenameInformation:
    case FileRenameInformationEx:
        action = RwActionRename; break;
    case FileDispositionInformation:
    case FileDispositionInformationEx:
        action = RwActionDelete; break;
    case FileEndOfFileInformation:
    case FileAllocationInformation:
        action = RwActionWrite;  break;
    default:
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    return HandleMutation(Data, FltObjects, action, CompletionContext);
}

/* PostDirectoryControl — nguồn dữ liệu THẬT cho F9 */
FLT_POSTOP_CALLBACK_STATUS PostDirectoryControl(
    _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) return FLT_POSTOP_FINISHED_PROCESSING;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return FLT_POSTOP_FINISHED_PROCESSING;
    if (!NT_SUCCESS(Data->IoStatus.Status)) return FLT_POSTOP_FINISHED_PROCESSING;
    if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY) return FLT_POSTOP_FINISHED_PROCESSING;

    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    if (pid == gRw.SelfPid) return FLT_POSTOP_FINISHED_PROCESSING;
    if (PtIsRwDescendant(pid)) return FLT_POSTOP_FINISHED_PROCESSING;

    ULONG count = 0;
    PVOID buf = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
    FILE_INFORMATION_CLASS cls =
        Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;

    if (buf && (cls == FileBothDirectoryInformation ||
        cls == FileDirectoryInformation ||
        cls == FileFullDirectoryInformation ||
        cls == FileIdBothDirectoryInformation)) {
        __try {
            PFILE_BOTH_DIR_INFORMATION p = (PFILE_BOTH_DIR_INFORMATION)buf;
            for (;;) {
                count++;
                if (p->NextEntryOffset == 0 || count > 4096) break;
                p = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)p + p->NextEntryOffset);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { count = 0; }
    }
    if (count == 0) return FLT_POSTOP_FINISHED_PROCESSING;

    RW_EVENT ev = { 0 };
    ev.Pid = pid;
    ev.RootPid = PtGetRoot(pid);
    ev.Action = RwActionDirQuery;
    ev.DirEntryCount = count;
    ev.IsPending = 0;

    PUNICODE_STRING name = NULL;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    if (FillFileInfo(Data, FltObjects, &ev, &name, &nameInfo)) {
        BOOLEAN skip = IsSkippedPath(name);
        FltReleaseFileNameInformation(nameInfo);
        if (skip) return FLT_POSTOP_FINISHED_PROCESSING;
    }

    SendEvent(&ev, FALSE, NULL);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* ---- Process notify: RootPid + command line (F6, F7) ---- */
VOID ProcessNotify(
    _Inout_ PEPROCESS Process, _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;

    if (CreateInfo == NULL) {
        FtRemovePid(pid);
        RemoveDenied(pid);

        RW_EVENT ev = { 0 };
        ev.Pid = pid;
        ev.RootPid = PtGetRoot(pid);
        ev.Action = RwActionProcessExit;
        if (KeGetCurrentIrql() == PASSIVE_LEVEL) SendEvent(&ev, FALSE, NULL);

        PtRemove(pid);
        return;
    }

    ULONG parent = (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId;
    PtInsert(pid, parent, CreateInfo->ImageFileName);

    if (PtIsRwDescendant(pid)) return;

    RW_EVENT ev = { 0 };
    ev.Pid = pid;
    ev.RootPid = PtGetRoot(pid);
    ev.Action = RwActionProcessCreate;

    if (CreateInfo->ImageFileName) {
        ULONG len = min(CreateInfo->ImageFileName->Length, (RW_MAX_PATH - 1) * sizeof(WCHAR));
        RtlCopyMemory(ev.FilePath, CreateInfo->ImageFileName->Buffer, len);
    }
    if (CreateInfo->CommandLine) {
        ULONG len = min(CreateInfo->CommandLine->Length, (RW_MAX_CMDLINE - 1) * sizeof(WCHAR));
        RtlCopyMemory(ev.CommandLine, CreateInfo->CommandLine->Buffer, len);
    }

    if (KeGetCurrentIrql() == PASSIVE_LEVEL) SendEvent(&ev, FALSE, NULL);
}

/* ---- Registry callback (F8) ---- */
static BOOLEAN IsPersistenceKey(PCUNICODE_STRING Key, PCUNICODE_STRING ValueName) {

    if (PathContainsCI(Key, L"\\SERVICES\\BAM\\"))      return FALSE;
    if (PathContainsCI(Key, L"\\SERVICES\\DAM\\"))      return FALSE;
    if (PathContainsCI(Key, L"\\SERVICES\\TCPIP\\"))    return FALSE;
    if (PathContainsCI(Key, L"\\SERVICES\\EVENTLOG\\")) return FALSE;
    if (PathContainsCI(Key, L"\\STATE\\USERSETTINGS"))  return FALSE;
    if (PathContainsCI(Key, L"\\SERVICES\\WINSOCK"))    return FALSE;

    if (PathContainsCI(Key, L"\\CURRENTVERSION\\RUN") ||
        PathContainsCI(Key, L"\\CURRENTVERSION\\RUNONCE") ||
        PathContainsCI(Key, L"\\CURRENTVERSION\\RUNSERVICES") ||
        PathContainsCI(Key, L"\\CURRENTVERSION\\WINLOGON"))
        return TRUE;

    if (PathContainsCI(Key, L"\\CONTROLSET001\\SERVICES\\") ||
        PathContainsCI(Key, L"\\CURRENTCONTROLSET\\SERVICES\\")) {
        if (ValueName == NULL || ValueName->Length == 0) return FALSE;
        if (PathContainsCI(ValueName, L"IMAGEPATH")) return TRUE;
        if (PathContainsCI(ValueName, L"SERVICEDLL")) return TRUE;
        return FALSE;
    }
    return FALSE;
}

NTSTATUS RegistryCallback(_In_ PVOID CallbackContext, _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    if (Argument2 == NULL) return STATUS_SUCCESS;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_SUCCESS;

    REG_NOTIFY_CLASS op = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    if (op != RegNtPreSetValueKey) return STATUS_SUCCESS;

    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    if (pid == gRw.SelfPid) return STATUS_SUCCESS;

    PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
    PCUNICODE_STRING keyName = NULL;

    if (!NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&gRw.RegCookie, info->Object,
        NULL, &keyName, 0)))
        return STATUS_SUCCESS;

    BOOLEAN hit = IsPersistenceKey(keyName, info->ValueName);
    if (hit) {
        RW_EVENT ev = { 0 };
        ev.Pid = pid;
        ev.RootPid = PtGetRoot(pid);
        ev.Action = RwActionRegPersist;
        ULONG len = min(keyName->Length, (RW_MAX_PATH - 1) * sizeof(WCHAR));
        RtlCopyMemory(ev.FilePath, keyName->Buffer, len);
        SendEvent(&ev, FALSE, NULL);
    }
    CmCallbackReleaseKeyObjectIDEx(keyName);
    return STATUS_SUCCESS;
}

/* ---- Communication port ---- */
NTSTATUS PortConnect(_In_ PFLT_PORT ClientPort, _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext, _Outptr_result_maybenull_ PVOID* ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie);
    gRw.ClientPort = ClientPort;
    return STATUS_SUCCESS;
}

VOID PortDisconnect(_In_opt_ PVOID ConnectionCookie) {
    UNREFERENCED_PARAMETER(ConnectionCookie);
    FltCloseClientPort(gRw.Filter, &gRw.ClientPort);
    gRw.ClientPort = NULL;
    gRw.SelfPid = 0;
    FtFlushAll();
}

NTSTATUS PortMessage(_In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength, _Out_ PULONG ReturnOutputBufferLength)
{
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL || InputBufferLength < sizeof(RW_COMMAND))
        return STATUS_INVALID_PARAMETER;

    RW_COMMAND cmd = { 0 };
    __try { RtlCopyMemory(&cmd, InputBuffer, sizeof(cmd)); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return STATUS_INVALID_PARAMETER; }

    switch (cmd.Code) {
    case RwCmdSetSelfPid:  gRw.SelfPid = cmd.Pid;  break;
    case RwCmdDenyPid:     AddDenied(cmd.Pid);     break;
    case RwCmdUndenyPid:   RemoveDenied(cmd.Pid);  break;
    case RwCmdPauseCow:    gRw.CowPaused = TRUE;   FtFlushAll(); break;
    case RwCmdResumeCow:   gRw.CowPaused = FALSE;  break;
    case RwCmdClearTouch:  FtRemoveEntry(cmd.Pid, cmd.FileRef); break;
    default: return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}

/* ---- Filter registration ---- */
NTSTATUS InstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM) return STATUS_FLT_DO_NOT_ATTACH;
    return STATUS_SUCCESS;
}

NTSTATUS FilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);

    if (gRw.RegCallbackOn) { CmUnRegisterCallback(gRw.RegCookie); gRw.RegCallbackOn = FALSE; }
    if (gRw.ProcessNotifyOn) {
        PsSetCreateProcessNotifyRoutineEx(ProcessNotify, TRUE);
        gRw.ProcessNotifyOn = FALSE;
    }
    if (gRw.ServerPort) FltCloseCommunicationPort(gRw.ServerPort);
    if (gRw.Filter)     FltUnregisterFilter(gRw.Filter);

    FtFlushAll();
    PtFlushAll();
    return STATUS_SUCCESS;
}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,            0, PreCreate,          NULL },
    { IRP_MJ_WRITE,             0, PreWrite,           PostMutation },
    { IRP_MJ_SET_INFORMATION,   0, PreSetInformation,  PostMutation },
    { IRP_MJ_DIRECTORY_CONTROL, 0, NULL,               PostDirectoryControl },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION,
    0, NULL, Callbacks, FilterUnload,
    InstanceSetup, NULL, NULL,
    NULL, NULL, NULL, NULL
};

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS st;

    for (ULONG i = 0; i < FT_BUCKETS; i++) InitializeListHead(&gFtBucket[i]);
    for (ULONG i = 0; i < PT_BUCKETS; i++) InitializeListHead(&gPtBucket[i]);
    KeInitializeSpinLock(&gFtLock);
    KeInitializeSpinLock(&gPtLock);
    KeInitializeSpinLock(&gDeniedLock);

    st = FltRegisterFilter(DriverObject, &FilterRegistration, &gRw.Filter);
    if (!NT_SUCCESS(st)) return st;

    UNICODE_STRING portName;
    RtlInitUnicodeString(&portName, RW_PORT_NAME);

    PSECURITY_DESCRIPTOR sd = NULL;
    st = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(st)) { FltUnregisterFilter(gRw.Filter); return st; }

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

    st = FltCreateCommunicationPort(gRw.Filter, &gRw.ServerPort, &oa, NULL,
        PortConnect, PortDisconnect, PortMessage,
        RW_MAX_CONNECTIONS);
    FltFreeSecurityDescriptor(sd);
    if (!NT_SUCCESS(st)) { FltUnregisterFilter(gRw.Filter); return st; }

    st = PsSetCreateProcessNotifyRoutineEx(ProcessNotify, FALSE);
    if (NT_SUCCESS(st)) gRw.ProcessNotifyOn = TRUE;

    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"370010");
    st = CmRegisterCallbackEx(RegistryCallback, &altitude, DriverObject,
        NULL, &gRw.RegCookie, NULL);
    if (NT_SUCCESS(st)) gRw.RegCallbackOn = TRUE;

    st = FltStartFiltering(gRw.Filter);
    if (!NT_SUCCESS(st)) {
        FilterUnload(0);
        return st;
    }
    return STATUS_SUCCESS;
}