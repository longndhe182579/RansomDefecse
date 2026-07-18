/*
 * Driver.c — RansomWall Kernel Minifilter v4.0
 *
 * CHỨC NĂNG:
 *   1. Path blacklist (H1)      — deny cứng vùng hệ thống, không hỏi user-space
 *   2. FirstTouchTable          — pend IRP lần đầu mỗi cặp (PID, FileRef) để CoW backup
 *   3. IRP interceptor          — write / rename / delete / directory query
 *   4. Process tracker          — cây tiến trình, RootPid, command line (F6, F7)
 *   5. Registry callback        — Run/RunOnce/Services (F8)
 *   6. Deny PID enforcement     — sau khi ML kết luận MALWARE
 *
 * CẢNH BÁO:
 *   - CHỈ chạy trong VM. Lỗi kernel = BSOD, không phải exception.
 *   - Cần: bcdedit /set testsigning on  + reboot
 *   - IRQL: FltSendMessage yêu cầu PASSIVE_LEVEL. Ta kiểm tra trước mỗi lần gọi.
 *   - Paging I/O KHÔNG được pend (deadlock với memory manager).
 */

#include <fltKernel.h>
#include <dontuse.h>
#include <ntstrsafe.h>
#include "RwProtocol.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

 /* ==========================================================================
    GLOBALS
    ========================================================================== */

typedef struct _RW_GLOBALS {
    PFLT_FILTER     Filter;
    PFLT_PORT       ServerPort;
    PFLT_PORT       ClientPort;

    ULONG           SelfPid;          /* PID của RansomWall.exe — whitelist */
    BOOLEAN         CowPaused;        /* free disk < RESERVE -> fail-open   */

    LARGE_INTEGER   RegCookie;
    BOOLEAN         RegCallbackOn;
    BOOLEAN         ProcessNotifyOn;
} RW_GLOBALS;

RW_GLOBALS gRw = { 0 };

/* --------------------------------------------------------------------------
   FirstTouchTable — hash table (PID, FileRef) -> đã chạm chưa
   -------------------------------------------------------------------------- */
#define FT_BUCKETS 1024

typedef struct _FT_ENTRY {
    LIST_ENTRY  Link;
    ULONG       Pid;
    LONGLONG    FileRef;
} FT_ENTRY, * PFT_ENTRY;

LIST_ENTRY  gFtBucket[FT_BUCKETS];
KSPIN_LOCK  gFtLock;

#define RW_TAG 'llWR'

static ULONG FtHash(ULONG Pid, LONGLONG FileRef) {
    ULONGLONG h = ((ULONGLONG)Pid * 2654435761ULL) ^ ((ULONGLONG)FileRef * 40503ULL);
    return (ULONG)(h % FT_BUCKETS);
}

/* Trả về TRUE nếu ĐÂY LÀ LẦN ĐẦU (và đã insert). FALSE nếu đã tồn tại. */
static BOOLEAN FtTestAndSet(ULONG Pid, LONGLONG FileRef) {
    ULONG idx = FtHash(Pid, FileRef);
    KIRQL oldIrql;
    PLIST_ENTRY e;
    PFT_ENTRY entry;
    BOOLEAN isFirst = TRUE;

    /* Cấp phát trước khi lấy spinlock — không được alloc ở DISPATCH_LEVEL */
    PFT_ENTRY fresh = (PFT_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(FT_ENTRY), RW_TAG);
    if (fresh == NULL) return FALSE;   /* hết bộ nhớ -> coi như đã chạm, không pend */

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

/* --------------------------------------------------------------------------
   Process tree — Pid -> RootPid
   -------------------------------------------------------------------------- */
#define PT_BUCKETS 256

typedef struct _PT_ENTRY {
    LIST_ENTRY Link;
    ULONG      Pid;
    ULONG      RootPid;
    BOOLEAN    IsRwDescendant;   /* hậu duệ của RansomWall.exe (diec/floss/conhost) */
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

/*
 * PtIsRwDescendant — tiến trình này do CHÍNH RansomWall sinh ra?
 *
 * Chặn đệ quy NGAY TẠI DRIVER, không tốn CreateToolhelp32Snapshot ở user-space
 * (snapshot duyệt toàn bộ process list, ~10-50ms mỗi lần — quá đắt để gọi
 * cho mỗi process create).
 */
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

static VOID PtInsert(ULONG Pid, ULONG ParentPid) {
    /* RootPid của con = RootPid của cha (nếu cha có), ngược lại chính cha */
    ULONG   root = PtGetRoot(ParentPid);
    /* Cờ hậu duệ lan xuống toàn bộ cây con của RansomWall */
    BOOLEAN isRwDesc = (gRw.SelfPid != 0) &&
        (ParentPid == gRw.SelfPid || PtIsRwDescendant(ParentPid));

    PPT_ENTRY fresh = (PPT_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PT_ENTRY), RW_TAG);
    if (!fresh) return;
    fresh->Pid = Pid;
    fresh->RootPid = root;
    fresh->IsRwDescendant = isRwDesc;

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

/* --------------------------------------------------------------------------
   Denied PID list — sau khi ML kết luận MALWARE
   -------------------------------------------------------------------------- */
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

/* ==========================================================================
   BỘ LỌC TRƯỚC KHI PEND — QUYẾT ĐỊNH HIỆU NĂNG CỦA CẢ HỆ THỐNG
   ==========================================================================

   LỖI ĐÃ SỬA (máy lag không dùng được):
     Bản cũ pend MỌI first-touch, kể cả .tmp/.log/.etl/.dat trong C:\Windows.
     Driver không biết VALUABLE_EXTS — danh sách đó nằm ở user-space.
     Windows làm HÀNG NGHÌN first-touch mỗi giây khi chạy bình thường.
     Mỗi cái tốn 2-5ms round-trip -> máy bò, không dùng nổi.

   Quyết định PHẢI nằm trong kernel, TRƯỚC khi pend.
   ========================================================================== */

static BOOLEAN PathContainsCI(PCUNICODE_STRING Path, PCWSTR Needle);   /* fwd decl */

/* Thư mục KHÔNG quan tâm — ransomware không nhắm vào đây, mà I/O thì cực nhiều */
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

/* Đuôi file CoW quan tâm — PHẢI khớp cfg::VALUABLE_EXTS ở user-space */
static const PCWSTR gValuableExts[] = {
    L".DOC",  L".DOCX", L".XLS",  L".XLSX", L".PPT",  L".PPTX",
    L".PDF",  L".TXT",  L".RTF",  L".ODT",  L".CSV",  L".MD",
    L".JPG",  L".JPEG", L".PNG",  L".GIF",  L".BMP",  L".PSD", L".RAW",
    L".MP3",  L".MP4",  L".AVI",  L".MOV",  L".WAV",
    L".ZIP",  L".RAR",  L".7Z",   L".TAR",  L".GZ",
    L".SQL",  L".DB",   L".MDB",  L".ACCDB",L".JSON", L".XML",
    L".CPP",  L".H",    L".C",    L".HPP",  L".CS",   L".PY",
    L".JS",   L".TS",   L".JAVA", L".PHP",  L".HTML", L".CSS",
};

/* So đuôi file ở CUỐI đường dẫn (không phải substring bất kỳ) */
static BOOLEAN EndsWithCI(PCUNICODE_STRING Path, PCWSTR Suffix) {
    UNICODE_STRING s;
    RtlInitUnicodeString(&s, Suffix);
    if (Path->Length < s.Length) return FALSE;

    USHORT pChars = Path->Length / sizeof(WCHAR);
    USHORT sChars = s.Length / sizeof(WCHAR);
    USHORT off = pChars - sChars;

    for (USHORT i = 0; i < sChars; i++)
        if (RtlUpcaseUnicodeChar(Path->Buffer[off + i]) !=
            RtlUpcaseUnicodeChar(s.Buffer[i])) return FALSE;
    return TRUE;
}

static BOOLEAN IsValuableExt(PCUNICODE_STRING Path) {
    for (int i = 0; i < ARRAYSIZE(gValuableExts); i++)
        if (EndsWithCI(Path, gValuableExts[i])) return TRUE;
    return FALSE;
}

/* ==========================================================================
   PATH BLACKLIST (H1)
   ========================================================================== */

   /* So khớp trên NORMALIZED name (\Device\HarddiskVolumeX\Windows\System32\...) */
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

/*
 * Trusted process — CHỈ theo image path tuyệt đối.
 * KHÔNG whitelist theo token SYSTEM: ransomware sau privilege escalation
 * chạy dưới SYSTEM, whitelist theo quyền = tự mở cửa.
 *
 * GHI CHÚ: bản đầy đủ phải verify chữ ký số (làm ở user-space lúc khởi động,
 * cache theo image hash). Ở đây kiểm path là mức tối thiểu.
 */
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

/* ==========================================================================
   GỬI EVENT LÊN USER-SPACE
   ========================================================================== */

   /*
    * SendEvent — gửi event lên user-space.
    *
    * WaitReply = TRUE  -> chờ CMD_CONTINUE (dùng cho pend / CoW backup)
    * WaitReply = FALSE -> gửi rồi quên (dùng cho event tính điểm)
    *
    * BẮT BUỘC PASSIVE_LEVEL. Gọi ở IRQL cao hơn = crash.
    */
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

    /*
     * FAIL-OPEN. Nếu user-space treo/chết, KHÔNG BAO GIỜ để máy người dùng đứng.
     * Mất một file còn hơn treo cả hệ thống.
     */
    if (st == STATUS_TIMEOUT || !NT_SUCCESS(st)) {
        if (ReplyCode) *ReplyCode = RwReplyContinue;
        return STATUS_TIMEOUT;
    }
    if (ReplyCode) *ReplyCode = reply.Code;
    return STATUS_SUCCESS;
}

/* Điền FilePath + FileRef vào event. Trả về FALSE nếu không lấy được tên. */
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

    /* FileRef — bất biến khi rename, chống lách bằng đổi tên rồi ghi */
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

/* ==========================================================================
   CORE: xử lý chung cho Write / Rename / Delete
   ========================================================================== */

static FLT_PREOP_CALLBACK_STATUS HandleMutation(
    PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, ULONG Action)
{
    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    /* Bỏ qua chính mình — nếu không sẽ deadlock khi CoW ghi vào backup store */
    if (pid == gRw.SelfPid) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /*
     * Bỏ qua hậu duệ của RansomWall (diec.exe, floss.exe, conhost.exe của chúng).
     * Không có cái này thì phân tích tĩnh tự kích hoạt chính nó -> đệ quy vô hạn.
     */
    if (PtIsRwDescendant(pid)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* Bỏ qua kernel-mode và paging I/O — pend paging I/O = deadlock memory manager */
    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* PID đã bị ML kết luận MALWARE -> deny thẳng, không hỏi ai */
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

    /* ---- 1.1 PATH BLACKLIST — deny ngay, không hỏi user-space ---- */
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

    /*
     * ---- BỘ LỌC HIỆU NĂNG — PHẢI đứng TRƯỚC mọi FltSendMessage ----
     *
     * Không có khối này, máy KHÔNG DÙNG ĐƯỢC: Windows làm hàng nghìn
     * first-touch mỗi giây vào .tmp/.log/.etl trong C:\Windows, mỗi cái
     * tốn 2-5ms round-trip lên user-space.
     */
    BOOLEAN skipDir = IsSkippedPath(name);
    BOOLEAN valuable = IsValuableExt(name);

    if (skipDir) {
        /* C:\Windows, Temp, Recycle Bin... — không backup, không tính điểm */
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    FltReleaseFileNameInformation(nameInfo);

    ev.Pid = pid;
    ev.RootPid = PtGetRoot(pid);
    ev.Action = Action;

    /* ---- 1.2 FIRST TOUCH -> pend cho CoW backup ----
       CHỈ pend khi đuôi file nằm trong danh sách CoW quan tâm.
       Đuôi khác -> chỉ gửi event tính điểm, không chặn. */
    BOOLEAN isFirst = valuable && (!gRw.CowPaused) && FtTestAndSet(pid, ev.FileRef);

    if (isFirst && KeGetCurrentIrql() == PASSIVE_LEVEL) {
        ev.IsPending = 1;
        ev.IsFirstTouch = 1;

        ULONG replyCode = RwReplyContinue;
        SendEvent(&ev, TRUE, &replyCode);   /* CHỜ user-space copy xong (~2-5ms) */

        if (replyCode == RwReplyDeny) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Lần thứ 2 trở đi (hoặc đuôi không valuable): event tính điểm, cho qua ngay */
    ev.IsPending = 0;
    ev.IsFirstTouch = 0;
    if (KeGetCurrentIrql() == PASSIVE_LEVEL)
        SendEvent(&ev, FALSE, NULL);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ==========================================================================
   PRE-OPERATION CALLBACKS
   ========================================================================== */

FLT_PREOP_CALLBACK_STATUS PreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    return HandleMutation(Data, FltObjects, RwActionWrite);
}

FLT_PREOP_CALLBACK_STATUS PreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    FILE_INFORMATION_CLASS cls = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    ULONG action;

    switch (cls) {
    case FileRenameInformation:
    case FileRenameInformationEx:
        action = RwActionRename; break;
    case FileDispositionInformation:
    case FileDispositionInformationEx:
        action = RwActionDelete; break;
    case FileEndOfFileInformation:      /* truncate = phá dữ liệu */
    case FileAllocationInformation:
        action = RwActionWrite;  break;
    default:
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    return HandleMutation(Data, FltObjects, action);
}

/*
 * PostDirectoryControl — nguồn dữ liệu THẬT cho F9.
 * v3.0 đếm event file bất kỳ rồi gọi nó là "directory enumeration" — sai.
 */
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

    /* Đếm số entry trả về */
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
        /* Bỏ qua liệt kê thư mục hệ thống — indexer/AV quét liên tục, cực nhiều */
        BOOLEAN skip = IsSkippedPath(name);
        FltReleaseFileNameInformation(nameInfo);
        if (skip) return FLT_POSTOP_FINISHED_PROCESSING;
    }

    SendEvent(&ev, FALSE, NULL);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* ==========================================================================
   PROCESS NOTIFY — RootPid + command line (F6, F7)
   ========================================================================== */

VOID ProcessNotify(
    _Inout_ PEPROCESS Process, _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;

    if (CreateInfo == NULL) {
        /* ---- Tiến trình THOÁT ---- */
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

    /* ---- Tiến trình TẠO MỚI ---- */
    ULONG parent = (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId;
    PtInsert(pid, parent);

    /*
     * Không báo lên user-space nếu đây là con của chính RansomWall
     * (diec.exe, floss.exe, conhost.exe của chúng).
     * Không có guard này -> phân tích tĩnh tự kích hoạt chính nó -> đệ quy vô hạn.
     */
    if (PtIsRwDescendant(pid)) return;

    RW_EVENT ev = { 0 };
    ev.Pid = pid;
    ev.RootPid = PtGetRoot(pid);
    ev.Action = RwActionProcessCreate;

    if (CreateInfo->ImageFileName) {
        ULONG len = min(CreateInfo->ImageFileName->Length, (RW_MAX_PATH - 1) * sizeof(WCHAR));
        RtlCopyMemory(ev.FilePath, CreateInfo->ImageFileName->Buffer, len);
    }
    /*
     * Command line — đây là nguồn dữ liệu THẬT cho F6 và F7.
     * v3.0 tìm chuỗi "bcdedit"/"vssadmin" trong FILE — pack là mất.
     * Ở đây ta bắt được lệnh thật lúc chạy.
     */
    if (CreateInfo->CommandLine) {
        ULONG len = min(CreateInfo->CommandLine->Length, (RW_MAX_CMDLINE - 1) * sizeof(WCHAR));
        RtlCopyMemory(ev.CommandLine, CreateInfo->CommandLine->Buffer, len);
    }

    if (KeGetCurrentIrql() == PASSIVE_LEVEL) SendEvent(&ev, FALSE, NULL);
}

/* ==========================================================================
   REGISTRY CALLBACK — nguồn dữ liệu THẬT cho F8
   ========================================================================== */

   /*
    * IsPersistenceKey — F8.
    *
    * LỖI ĐÃ SỬA: điều kiện cũ là PathContainsCI(Key, L"\\CONTROLSET001\\SERVICES")
    * -> khớp \REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\bam\State\UserSettings\...
    *
    * BAM (Background Activity Moderator) được Windows ghi MỖI LẦN bất kỳ .exe nào
    * chạy. Kết quả: F8 bật cho 100% tiến trình -> vô dụng, nhiễu log kinh khủng.
    *
    * Sửa: loại BAM/DAM trước, và với Services chỉ bắt ImagePath/Start
    * (tạo service mới hoặc hijack service) — không bắt mọi value.
    */
static BOOLEAN IsPersistenceKey(PCUNICODE_STRING Key, PCUNICODE_STRING ValueName) {

    /* ---- LOẠI TRỪ: Windows tự ghi cho mọi tiến trình ---- */
    if (PathContainsCI(Key, L"\\SERVICES\\BAM\\"))      return FALSE;  /* thủ phạm chính */
    if (PathContainsCI(Key, L"\\SERVICES\\DAM\\"))      return FALSE;
    if (PathContainsCI(Key, L"\\SERVICES\\TCPIP\\"))    return FALSE;
    if (PathContainsCI(Key, L"\\SERVICES\\EVENTLOG\\")) return FALSE;
    if (PathContainsCI(Key, L"\\STATE\\USERSETTINGS"))  return FALSE;
    if (PathContainsCI(Key, L"\\SERVICES\\WINSOCK"))    return FALSE;

    /* ---- Run / RunOnce: hiếm, giữ nguyên ---- */
    if (PathContainsCI(Key, L"\\CURRENTVERSION\\RUN") ||
        PathContainsCI(Key, L"\\CURRENTVERSION\\RUNONCE") ||
        PathContainsCI(Key, L"\\CURRENTVERSION\\RUNSERVICES") ||
        PathContainsCI(Key, L"\\CURRENTVERSION\\WINLOGON"))
        return TRUE;

    /* ---- Services: CHỈ khi ghi ImagePath/Start (tạo hoặc hijack) ---- */
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

/* ==========================================================================
   COMMUNICATION PORT
   ========================================================================== */

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
    /*
     * User-space ngắt kết nối (thoát hoặc BỊ KILL).
     * Fail-open: xoá FirstTouchTable để không pend nữa — nếu không,
     * mọi IRP sẽ timeout 200ms và máy sẽ bò.
     */
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
    default: return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}

/* ==========================================================================
   FILTER REGISTRATION
   ========================================================================== */

NTSTATUS InstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    /* Chỉ gắn vào ổ đĩa, không gắn vào network/cdrom */
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
    { IRP_MJ_WRITE,             0, PreWrite,           NULL },
    { IRP_MJ_SET_INFORMATION,   0, PreSetInformation,  NULL },
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

    /* --- Communication port --- */
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

    /* --- Process notify (F6, F7, RootPid) --- */
    st = PsSetCreateProcessNotifyRoutineEx(ProcessNotify, FALSE);
    if (NT_SUCCESS(st)) gRw.ProcessNotifyOn = TRUE;
    /* Lỗi thường gặp: STATUS_ACCESS_DENIED nếu thiếu /INTEGRITYCHECK khi link */

    /* --- Registry callback (F8) --- */
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