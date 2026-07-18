# RansomWall v4.0 — Hướng dẫn Build và Chạy

## Mô tả cấu trúc thư mục

```text
RansomWall/
├── RansomWall.sln             <- File solution chính, mở bằng Visual Studio
├── Common/
│   └── RwProtocol.h            <- Định nghĩa struct dùng chung giữa Kernel và User mode
├── UserSpace/
│   ├── RansomWall.vcxproj
│   ├── main.cpp                <- Điều phối chính (Orchestrator) + Dynamic Analysis Engine
│   ├── Config.h                <- Quản lý tập trung TẤT CẢ các ngưỡng cấu hình (nghiêm cấm magic number)
│   ├── Util.h                  <- Các hàm bổ trợ: Logger, tính entropy, SHA-256, JSON, path
│   ├── Features.h              <- Quản lý Latch (decay), SlidingCounter, ProcessFeature
│   ├── FilterClient.h          <- Tầng giao tiếp với Driver qua IOCP (sử dụng 4 thread xử lý)
│   ├── CowEngine.h             <- Tầng Copy-on-Write: Quota động, chấm điểm LRU giá trị file, dedup, manifest
│   ├── StaticAnalyzer.h        <- Trích xuất tính năng tĩnh (F1/F2/F3/F5) bằng cách parse cấu trúc PE thật
│   ├── HoneyFiles.h            <- Quản lý file mồi (F4) + whitelist các tiến trình an toàn
│   ├── MLClient.h              <- Client WinHTTP gửi dữ liệu lên ML Engine (không dùng popen + curl để tránh gọi shell)
│   └── Cleanup.h               <- Xử lý dọn dẹp (4 cơ chế) + khôi phục file có điều kiện
├── Driver/
│   ├── Driver.c                <- Mã nguồn chính của Minifilter driver
│   └── RansomWallDriver.inf    <- File thông tin cấu hình driver
└── MLEngine/
    ├── app.py                  <- API Flask phục vụ nhận diện (`:5000/predict`)
    ├── train.py                <- Script huấn luyện model Random Forest + xuất confusion matrix
    └── requirements.txt        <- Danh sách thư viện Python cần thiết
  
PHẦN 1: Quick Start (Chạy thử trong 5 phút, không cần driver)
1.1 Khởi động ML Engine
Mở Terminal/PowerShell tại thư mục dự án và chạy các lệnh:
PowerShell
cd MLEngine
pip install -r requirements.txt
python train.py          # Khởi tạo dữ liệu mẫu và sinh file model.pkl + metrics.txt
python app.py            # Giữ command line này để chạy API
Kiểm tra nhanh: Truy cập http://127.0.0.1:5000/health. Nếu thấy trả về "model_loaded": true là API đã sẵn sàng.
Lưu ý về dữ liệu: File train.py tự sinh một tập dataset giả lập để test pipeline. Các chỉ số accuracy/F1-score từ tập dữ liệu này không có giá trị khoa học để đưa vào báo cáo. Xem cách xử lý ở Phần 4.
1.2 Chạy ứng dụng User-Space
Mở RansomWall.sln bằng Visual Studio 2022.
Chuyển cấu hình build sang Release | x64.
Nhấn F5 để chạy.
Yêu cầu: Máy cần cài sẵn gói "Desktop development with C++" và Windows 10/11 SDK. Dự án cấu hình sẵn quyền RequireAdministrator, khi chạy Visual Studio sẽ yêu cầu cấp quyền Admin, bạn cần đồng ý để tránh ứng dụng tự thoát.
Giao diện console khi chạy thành công:
Plaintext
  ==========================================
        RansomWall v4.0
     CoW Engine + 13 Features + ML
  ==========================================

[INFO] [*] Quét backup mồ côi từ phiên trước...
[INFO] [CLEAN-4] Orphan sweep: giữ=0  xóa=0  quarantine=0  cảnh báo=0
[INFO] [HONEY] Đã tạo 100 honey file trong 10 thư mục.
[INFO] [COW] Disk: free=180 GB  reserve=10 GB  BUDGET=51 GB
[WARN] [!] CHẾ ĐỘ SIMULATION — driver chưa load.
Dòng thông báo CHẾ ĐỘ SIMULATION xuất hiện là hoàn toàn bình thường khi hệ thống chưa phát hiện driver kernel.

1.3 Bản chất và giới hạn của chế độ SIMULATION
Khi chạy không có driver, ứng dụng buộc phải dùng API ReadDirectoryChangesW của Windows để giám sát file. Cơ chế này gặp phải 2 điểm nghẽn kỹ thuật không thể sửa:
Mất thông tin PID: API chỉ báo cho bạn biết file nào bị đổi, chứ không chỉ ra tiến trình nào đổi. Code hiện tại đang lấy tạm GetCurrentProcessId() làm giá trị đại diện, khiến mọi hành vi của toàn hệ thống bị cộng dồn vào một rổ điểm chung.
Không thể chặn đứng I/O (No Pend): Bạn không thể bắt luồng ghi file dừng lại để chờ xử lý. Tiến trình CoW chỉ chạy sau khi file đã bị thay đổi trên đĩa. Gặp ransomware thật ghi đè file .docx dung lượng nhỏ, file được backup sẽ là file đã bị mã hóa.
Tóm lại: Chế độ SIMULATION phục vụ mục đích test logic code (xem cơ chế tính quota động hoạt động chuẩn chưa, thuật toán LRU chọn đúng file rác để xóa không, ML client gọi lên API có thông suốt không). Tuyệt đối không dùng chế độ này để chống ransomware thật.

PHẦN 2: Cấu hình Driver chuyên sâu (Bắt buộc dùng máy ảo)
2.1 Chuẩn bị môi trường máy ảo
Chuẩn bị một máy ảo Windows 10/11 x64 (Hyper-V, VMware hoặc VirtualBox). Hãy tạo một bản Snapshot sạch trước.
Máy host/máy ảo cần cài sẵn Windows Driver Kit (WDK) khớp với phiên bản Visual Studio đang dùng.
Mở CMD quyền Administrator trên máy ảo, chạy lệnh sau để bật chế độ Test Mode:
bcdedit /set testsigning on
bcdedit /set nointegritychecks on
shutdown /r /t 0
Sau khi máy khởi động lại, góc phải màn hình hiện chữ "Test Mode" là cấu hình thành công.

2.2 Cấu hình và Build Driver
Mã nguồn driver được tách riêng khỏi file solution chính nhằm tránh việc lỡ tay build nhầm làm crash máy host:
Mở Visual Studio → New Project → Chọn template Kernel Mode Driver, Empty (KMDF).
Click chuột phải vào mục Source Files → Add Existing Item → Chọn file Driver/Driver.c.
Mở Project Properties và cấu hình chính xác các mục sau:
Driver Settings → Type: Đổi thành Filter
Linker → Additional Dependencies: Thêm thư viện fltMgr.lib vào danh sách.
Linker → Command Line → Additional Options: Bắt buộc thêm cờ /INTEGRITYCHECK. (Nếu thiếu cờ này, hàm đăng ký callback tiến trình PsSetCreateProcessNotifyRoutineEx sẽ trả về lỗi STATUS_ACCESS_DENIED, khiến tính năng F6/F7 bị vô hiệu hóa hoàn toàn).
Driver Signing → Sign Mode: Chọn Test Sign.
Tiến hành Build dự án để thu về file RansomWallDriver.sys.

2.3 Deploy và Start Driver trên máy ảo
Copy 3 file sau khi build (.sys, .inf, .cat) vào một thư mục trên máy ảo. Mở CMD (Admin) tại thư mục đó và thực hiện các bước:
:: Cách nhanh: Chuột phải vào file RansomWallDriver.inf -> Chọn Install
:: Hoặc đăng ký thủ công qua service điều khiển driver:
sc create RansomWallDriver type= filesys start= demand binPath= "C:\Đường_dẫn_đến_file\RansomWallDriver.sys"

:: Khai báo thông tin tầng lọc (Altitude) cho Minifilter trong Registry
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RansomWallDriver\Instances" /v DefaultInstance /t REG_SZ /d "RansomWall Instance" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RansomWallDriver\Instances\RansomWall Instance" /v Altitude /t REG_SZ /d "370010" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RansomWallDriver\Instances\RansomWall Instance" /v Flags /t REG_DWORD /d 0 /f

:: Kích hoạt driver
sc start RansomWallDriver

:: Kiểm tra trạng thái hoạt động của các filter
fltmc filters
Nếu tên RansomWallDriver xuất hiện trong danh sách của lệnh fltmc, driver đã chạy ngầm thành công. Lúc này, khi bạn bật ứng dụng RansomWall.exe ở User-space, log hệ thống sẽ chuyển trạng thái:
Plaintext
[INFO] Kết nối kernel driver thành công.
[INFO] [+] CHẾ ĐỘ KERNEL — CoW đồng bộ qua pend IRP. Bảo vệ đầy đủ.

2.4 Lệnh gỡ bỏ Driver
sc stop RansomWallDriver
sc delete RansomWallDriver    