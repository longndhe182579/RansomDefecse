# RansomWall v4.0 — Hướng dẫn build và chạy

## Đọc trước 30 giây

| Thành phần | "Build là chạy"? |
|---|---|
| **UserSpace** (`RansomWall.sln`) | **Có.** Mở, F5, xong. Tự chạy chế độ SIMULATION nếu chưa có driver. |
| **MLEngine** (Flask) | **Có.** `pip install -r requirements.txt` rồi `python app.py`. |
| **Driver** (minifilter) | **Không.** Cần WDK + test signing + reboot + **bắt buộc VM**. |

Driver không "build là chạy" được — đây là ràng buộc của Windows, không phải của code. Lỗi kernel là BSOD chứ không phải exception. **Đừng chạy driver trên máy thật của bạn.**

---

## Cấu trúc

```
RansomWall/
├── RansomWall.sln              <- Mở file này
├── Common/
│   └── RwProtocol.h            Struct dùng chung kernel <-> user
├── UserSpace/
│   ├── RansomWall.vcxproj
│   ├── main.cpp                Orchestrator + Dynamic Analysis Engine
│   ├── Config.h                MỌI ngưỡng ở đây — sửa ở đây, không rải magic number
│   ├── Util.h                  Logger, entropy, SHA-256, JSON, path
│   ├── Features.h              Latch có decay, SlidingCounter, ProcessFeature
│   ├── FilterClient.h          Giao tiếp driver (IOCP, 4 thread)
│   ├── CowEngine.h             Quota động, LRU giá trị, dedup, manifest
│   ├── StaticAnalyzer.h        F1/F2/F3/F5 — parse PE thật
│   ├── HoneyFiles.h            F4 + whitelist
│   ├── MLClient.h              WinHTTP (không phải _popen+curl)
│   └── Cleanup.h               4 cơ chế dọn dẹp + restore có điều kiện
├── Driver/
│   ├── Driver.c                Minifilter
│   └── RansomWallDriver.inf
└── MLEngine/
    ├── app.py                  Flask :5000/predict
    ├── train.py                Random Forest + confusion matrix
    └── requirements.txt
```

---

## PHẦN 1 — Chạy ngay (5 phút, không cần driver)

### 1.1 ML engine

```powershell
cd MLEngine
pip install -r requirements.txt
python train.py          # tạo model.pkl + metrics.txt
python app.py            # để cửa sổ này chạy
```

Kiểm tra: mở `http://127.0.0.1:5000/health` → phải thấy `"model_loaded": true`.

> `train.py` sinh **dataset tổng hợp** để pipeline chạy được ngay. Số liệu từ nó **không có giá trị khoa học** — xem Phần 4.

### 1.2 User-space

1. Mở `RansomWall.sln` bằng **Visual Studio 2022**
2. Chọn cấu hình **Release | x64**
3. **F5**

Cần: workload "Desktop development with C++" + Windows 10/11 SDK. Project đã đặt sẵn `RequireAdministrator` nên Visual Studio sẽ hỏi quyền admin — phải đồng ý, nếu không chương trình tự thoát.

Bạn sẽ thấy:

```
  ==========================================
        RansomWall v4.0
     CoW Engine + 13 Features + ML
  ==========================================

[INFO] [*] Quet backup mo coi tu phien truoc...
[INFO] [CLEAN-4] Orphan sweep: giu=0  xoa=0  quarantine=0  canh bao=0
[INFO] [HONEY] Da tao 100 honey file trong 10 thu muc.
[INFO] [COW] Disk: free=180 GB  reserve=10 GB  BUDGET=51 GB
[WARN] [!] CHE DO SIMULATION — driver chua load.
```

`CHE DO SIMULATION` là **đúng như thiết kế** khi chưa có driver.

### 1.3 Giới hạn của chế độ SIMULATION — phải hiểu rõ

`ReadDirectoryChangesW` có hai hạn chế không thể khắc phục:

| | Vấn đề |
|---|---|
| **Không biết PID** | API chỉ báo *file nào đổi*, không báo *ai đổi*. Code dùng `GetCurrentProcessId()` làm placeholder → mọi tiến trình dồn chung một rổ điểm. |
| **Không pend được** | Không có cách nào treo I/O. Backup chạy **sau khi** file đã bị ghi → với file `.docx` 200KB bạn sẽ backup **bản đã bị mã hoá**. |

SIMULATION dùng để **kiểm tra logic** (quota động chia bậc đúng chưa, LRU giá trị chọn đúng file rác chưa, cleanup có chạy không, ML có được gọi không). Nó **không phải bảo vệ thật**.

---

## PHẦN 2 — Driver (bắt buộc VM)

### 2.1 Chuẩn bị

1. **VM** (Hyper-V / VMware / VirtualBox) chạy Windows 10/11 x64. Chụp **snapshot** trước.
2. Cài **Windows Driver Kit (WDK)** cùng phiên bản với Visual Studio 2022
3. Trong VM, mở cmd admin:

```cmd
bcdedit /set testsigning on
bcdedit /set nointegritychecks on
shutdown /r /t 0
```

Sau reboot, góc phải màn hình hiện "Test Mode" — đúng rồi.

### 2.2 Build driver

Driver **không** nằm trong `RansomWall.sln` (cố tình — để không ai lỡ tay build nhầm):

1. Visual Studio → **New Project** → **Kernel Mode Driver, Empty (KMDF)**
2. Add existing item: `Driver/Driver.c`
3. Project Properties:
   - **Driver Settings → Type**: `Filter`
   - **Linker → Additional Dependencies**: thêm `fltMgr.lib`
   - **Linker → Command Line**: thêm `/INTEGRITYCHECK`
     *(thiếu cờ này thì `PsSetCreateProcessNotifyRoutineEx` trả `STATUS_ACCESS_DENIED` → F6/F7 chết câm)*
   - **Driver Signing → Sign Mode**: `Test Sign`
4. Build → ra `RansomWallDriver.sys`

### 2.3 Cài trong VM

Chép `.sys` + `.inf` + `.cat` vào VM, rồi:

```cmd
:: Chuột phải RansomWallDriver.inf -> Install
sc start RansomWallDriver

Cai dat
sc create RansomWallDriver type= filesys start= demand binPath= "C:\Users\duclonggg11\Desktop\Driver\KMDF Driver1\ARM64\Debug\KMDF Driver1\KMDFDriver1.sys"
>reg add "HKLM\SYSTEM\CurrentControlSet\Services\RansomWallDriver\Instances" /v DefaultInstance /t REG_SZ /d "RansomWall Instance" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RansomWallDriver\Instances\RansomWall Instance" /v Altitude /t REG_SZ /d "370010" /f
>reg add "HKLM\SYSTEM\CurrentControlSet\Services\RansomWallDriver\Instances\RansomWall Instance" /v Flags /t REG_DWORD /d 0 /f
sc start RansomWallDriver
:: Kiểm tra
fltmc filters
```

Thấy `RansomWallDriver` trong danh sách là được. Giờ chạy `RansomWall.exe` sẽ hiện:

```
[INFO] Ket noi kernel driver thanh cong.
[INFO] [+] CHE DO KERNEL — CoW dong bo qua pend IRP. Bao ve day du.
```

### 2.4 Gỡ

```cmd
sc stop RansomWallDriver
sc delete RansomWallDriver
```

### 2.5 Lỗi thường gặp

| Triệu chứng | Nguyên nhân |
|---|---|
| `sc start` → error 577 | Chưa bật test signing, hoặc chưa test-sign driver |
| `fltmc` không thấy driver | Altitude trùng — đổi `370010` trong cả `.inf` và `DriverEntry` |
| Máy VM **bò cực chậm** | User-space không reply pend → mọi IRP timeout 200ms. Kiểm tra `FilterReplyMessage` |
| **BSOD** `IRQL_NOT_LESS_OR_EQUAL` | Gọi `FltSendMessage` ở IRQL > PASSIVE. Code đã check, nhưng nếu bạn sửa thì phải giữ check đó |
| **BSOD** khi mở file bất kỳ | Deadlock: driver pend I/O của chính RansomWall.exe. Kiểm tra `RwCmdSetSelfPid` đã gửi chưa |
| F6/F7 không bao giờ bật | Thiếu `/INTEGRITYCHECK` khi link |

---

## PHẦN 3 — Kiểm thử

### 3.1 Kiểm thử lành tính (làm được ngay, không cần mẫu độc)

Đây là những test **quan trọng nhất** vì chúng đo tỷ lệ dương tính giả:

| Test | Kỳ vọng | Kiểm tra điều gì |
|---|---|---|
| Nén 5GB bằng 7-Zip | F13 **không** bật, `mean_entropy_delta ≈ 0` | Sửa lỗi F13 (mục 5.2 báo cáo) |
| Mở/lưu 50 file Word | Backup xuất hiện rồi biến mất sau 60s, giữ lại 20 file | Early cleanup ① |
| Copy 200 file vào Documents | `[COW] Backup ...` trong log | CoW hoạt động |
| Copy 100 file **giống hệt nhau** | `[COW] Backup (dedup) ...` | Dedup SHA-256 |
| Chạy `git checkout` trên repo lớn | Score không chạm 6 | Dương tính giả |
| Sửa file honey bằng Notepad | F4 bật (bạn không nằm trong whitelist) | Honey hoạt động |
| Kill RansomWall.exe bằng Task Manager, chạy lại | `[CLEAN-4] Phat hien .session con sot` | Orphan sweep ④ |
| Chạy `vssadmin delete shadows /all` từ cmd | F7 bật cho **cmd.exe** (RootPid) | Quy điểm về RootPid (chỉ ở chế độ kernel) |

### 3.2 Test quota động và LRU giá trị

```powershell
# Sinh nhiều file rác trong Downloads để ép quota tràn
1..500 | % { $n = -join ((48..57)+(97..102) | Get-Random -Count 8 | % {[char]$_})
             fsutil file createnew "$env:USERPROFILE\Downloads\$n.docx" 1048576 }
```

Xem log: file rác phải có `V=` **âm hoặc rất thấp**, và bị evict trước. File thật trong `Documents` phải có `V≈7.0` và được giữ.

### 3.3 Về mẫu ransomware thật

**Tôi không viết mẫu ransomware cho bạn** — kể cả bản "test", vì thứ ghi đè file bằng dữ liệu ngẫu nhiên hàng loạt chính là ransomware, chỉ thiếu phần đòi tiền.

Cách làm đúng cho đồ án:

1. VM **cô lập hoàn toàn**: network `Host-only` hoặc tắt hẳn, không shared folder, không clipboard, snapshot trước mỗi lần chạy
2. Lấy mẫu từ nguồn học thuật: **MalwareBazaar**, **VirusShare**, **theZoo** — có tài khoản nghiên cứu
3. **Xin phép giảng viên hướng dẫn bằng văn bản** trước khi chạy mẫu thật
4. Ghi feature vector thật ra CSV → train lại model (Phần 4)

Nếu không được phép dùng mẫu thật, cách thay thế hợp lệ: dùng chính **7-Zip với tuỳ chọn mã hoá AES** trên một thư mục test rồi xoá bản gốc. Nó tạo ra pattern I/O + entropy tương tự mà không phải malware. Nói rõ trong báo cáo đây là proxy, không phải mẫu thật.

---

## PHẦN 4 — Từ prototype đến đồ án bảo vệ được

Ba việc `train.py` **không** làm thay bạn được:

**1. Dataset thật.** Model hiện tại train trên phân phối do tôi bịa ra. Nó sẽ cho F1 ≈ 0.99 và con số đó vô nghĩa. Cần:

```powershell
python train.py --real data.csv
```

`data.csv` phải có 17 cột feature + cột `label` (1=ransomware, 0=benign), thu từ chạy mẫu thật.

**2. Ba con số phải đo** (mục 6.1 báo cáo):

| Metric | Cách đo |
|---|---|
| Latency pend | p50/p95/p99 của `CopyFileW` với file 1KB / 1MB / 50MB |
| Overhead | Giải nén archive 2GB có/không RansomWall. ShieldFS công bố ~10% |
| **Tỷ lệ file cứu được** | `file khôi phục đúng / tổng file bị mã hoá` ← **metric bán được đồ án** |

Metric thứ ba quan trọng hơn accuracy của ML. Người dùng không quan tâm model đạt 97% — họ quan tâm còn bao nhiêu file.

**3. Quyết định về F8 và F9.** Nếu bạn không chạy được registry callback và directory control, hãy **loại hai chiều này khỏi vector** thay vì để chúng luôn bằng 0. Giữ chiều luôn-bằng-0 chỉ làm nhiễu model và tạo câu hỏi khó khi bảo vệ. Sửa `FEATURE_ORDER` ở cả `app.py`, `train.py`, và `Features.h::ToJson`.

---

## PHẦN 5 — Những chỗ tôi biết là còn yếu

Nói ra trước để bạn không bị hỏi bất ngờ:

- **Driver chưa được test trên phần cứng thật.** Tôi không chạy được Windows kernel. Nó sẽ cần debug — nhiều khả năng ở phần `FltSendMessage` với `FLT_PREOP_PENDING` (đường dẫn IRQL và deadlock là chỗ dễ sai nhất).
- **`ObRegisterCallbacks` self-protection chưa có trong code**, dù báo cáo mục 3.5 mô tả. Nó cần `/INTEGRITYCHECK` + altitude riêng. Thêm sau khi phần còn lại đã ổn.
- **Verify chữ ký số cho trusted process** hiện chỉ so đường dẫn trong `IsTrustedProcess()`. Bản đầy đủ phải verify chữ ký ở user-space lúc khởi động rồi cache theo image hash.
- **`R(f)` trong LRU giá trị** dùng heuristic LastAccessTime, mà Windows tắt cập nhật LastAccess theo mặc định (`NtfsDisableLastAccessUpdate`). Đây là chỗ yếu — cân nhắc đọc Recent/Jump List thay thế.
- **Mã hoá một phần** (intermittent encryption của LockBit/BlackCat — chỉ mã hoá 4KB đầu hoặc phần giữa): F13 lấy mẫu 4KB đầu nên bắt được ca đầu, **miss** ca sau. Cần lấy mẫu nhiều offset.
- **SIMULATION không có PID thật** — đã nói ở 1.3, nhưng nhắc lại vì đây là thứ dễ khiến bạn hiểu nhầm kết quả test.
