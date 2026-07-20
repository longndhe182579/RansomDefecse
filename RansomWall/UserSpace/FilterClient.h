/*
 * FilterClient.h — Giao tiếp với minifilter driver.
 *
 * QUAN TRỌNG: dùng NHIỀU thread listener.
 *
 * Lỗi kiến trúc của v3.0: callback từ driver chạy trên MỘT thread duy nhất,
 * mà TriggerBlockAndAI lại chờ backupDone NGAY TRONG callback đó — trong khi
 * backupDone chỉ được set khi driver gửi notify, mà notify đó phải đi qua
 * chính callback đang bị chặn. Deadlock logic.
 *
 * v4.0: N thread listener, mỗi thread xử lý event độc lập. Driver pend IRP
 * thì thread nào rảnh sẽ nhận và reply. CoW không bao giờ chờ ML.
 */
#pragma once

#include "Util.h"
#include "RwProtocol.h"

#include <fltUser.h>
#include <functional>
#include <thread>
#include <atomic>
#include <vector>

#pragma comment(lib, "fltlib.lib")

namespace rw {

    /* Message layout khi nhận từ driver: header + payload */
#pragma pack(push, 8)
    struct RwGetMessage {
        FILTER_MESSAGE_HEADER Header;
        RW_EVENT              Event;
    };
    struct RwReplyMessage {
        FILTER_REPLY_HEADER Header;
        RW_REPLY            Reply;
    };
#pragma pack(pop)

    /*
     * ============================================================================
     * KÍCH THƯỚC REPLY — KHÔNG ĐƯỢC DÙNG sizeof(RwReplyMessage)
     * ============================================================================
     *
     * FILTER_REPLY_HEADER chứa ULONGLONG -> alignment của struct là 8
     * -> sizeof(RwReplyMessage) bị đệm thành 24, KHÔNG phải 20:
     *
     *      Header  : offset  0..15
     *      Reply   : offset 16..19
     *      PADDING : offset 20..23   <-- thủ phạm
     *
     * Filter Manager tính payload = dwReplyBufferSize - sizeof(FILTER_REPLY_HEADER).
     * Truyền 24 -> payload 8 byte. Nhưng driver khai replyLen = sizeof(RW_REPLY) = 4.
     * 8 > 4  ->  ERROR_MORE_DATA (0x800700EA).
     *
     * #pragma pack(8) KHÔNG cứu được: nó giới hạn alignment tối đa ở 8,
     * không xoá padding đuôi.
     */
    constexpr DWORD kReplySize =
        (DWORD)(sizeof(FILTER_REPLY_HEADER) + sizeof(RW_REPLY));

    static_assert(sizeof(FILTER_REPLY_HEADER) == 16,
        "FILTER_REPLY_HEADER doi kich thuoc — kiem tra lai kReplySize");
    static_assert(sizeof(RW_REPLY) == 4,
        "RW_REPLY doi kich thuoc — driver va user-space phai khop");
    static_assert(kReplySize <= sizeof(RwReplyMessage),
        "Buffer phai du chua header + payload");

    class FilterClient {
    public:
        // handler trả về RwReplyContinue / RwReplyDeny (chỉ dùng khi IsPending)
        using Handler = std::function<ULONG(const RW_EVENT&)>;

        ~FilterClient() { Disconnect(); }

        bool Connect() {
            HRESULT hr = FilterConnectCommunicationPort(
                RW_PORT_NAME, 0, nullptr, 0, nullptr, &port_);
            if (FAILED(hr)) {
                LOG_W("Khong ket noi duoc driver (hr=0x%08X). Chay che do SIMULATION.", hr);
                port_ = INVALID_HANDLE_VALUE;
                return false;
            }
            connected_ = true;
            LOG_I("Ket noi kernel driver thanh cong.");
            return true;
        }

        void Disconnect() {
            running_ = false;
            if (iocp_) {
                for (size_t i = 0; i < threads_.size(); i++)
                    PostQueuedCompletionStatus(iocp_, 0, 0, nullptr);
            }
            for (auto& t : threads_) if (t.joinable()) t.join();
            threads_.clear();
            if (iocp_) { CloseHandle(iocp_); iocp_ = nullptr; }
            if (port_ != INVALID_HANDLE_VALUE) { CloseHandle(port_); port_ = INVALID_HANDLE_VALUE; }
            connected_ = false;
        }

        bool IsConnected() const { return connected_; }

        /* ---- Lệnh user -> driver ---- */
        bool SendCommand(ULONG code, ULONG pid) {
            if (!connected_) return false;
            RW_COMMAND cmd{ code, pid };
            DWORD ret = 0;
            HRESULT hr = FilterSendMessage(port_, &cmd, sizeof(cmd), nullptr, 0, &ret);
            return SUCCEEDED(hr);
        }
        bool SetSelfPid(ULONG pid) { return SendCommand(RwCmdSetSelfPid, pid); }
        bool DenyPid(ULONG pid) { return SendCommand(RwCmdDenyPid, pid); }
        bool UndenyPid(ULONG pid) { return SendCommand(RwCmdUndenyPid, pid); }
        bool PauseCow() { return SendCommand(RwCmdPauseCow, 0); }
        bool ResumeCow() { return SendCommand(RwCmdResumeCow, 0); }

        /*
         * StartListening — tạo pool thread nhận event.
         *
         * threadCount nên >= 4: khi driver pend IRP, thread đang xử lý bị bận
         * copy file, các thread khác vẫn phải nhận được event mới.
         */
        bool StartListening(Handler h, int threadCount = 4) {
            if (!connected_) return false;
            handler_ = std::move(h);
            running_ = true;

            iocp_ = CreateIoCompletionPort(port_, nullptr, 0, threadCount);
            if (!iocp_) { LOG_E("CreateIoCompletionPort that bai: %lu", GetLastError()); return false; }

            for (int i = 0; i < threadCount; i++)
                threads_.emplace_back([this] { WorkerLoop(); });

            LOG_I("Listener khoi dong voi %d thread.", threadCount);
            return true;
        }

    private:
        struct PendingMsg {
            OVERLAPPED   Ovlp;
            RwGetMessage Msg;
        };

        HANDLE   port_ = INVALID_HANDLE_VALUE;
        HANDLE   iocp_ = nullptr;
        std::vector<std::thread> threads_;
        std::atomic<bool> running_{ false };
        std::atomic<bool> connected_{ false };
        std::atomic<uint64_t> replyFails_{ 0 };
        Handler  handler_;

        void PostReceive(PendingMsg* pm) {
            ZeroMemory(&pm->Ovlp, sizeof(pm->Ovlp));
            HRESULT hr = FilterGetMessage(port_, &pm->Msg.Header,
                sizeof(RwGetMessage), &pm->Ovlp);
            if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
                if (running_) LOG_E("FilterGetMessage that bai: 0x%08X", hr);
                delete pm;
            }
        }

        void WorkerLoop() {
            /* Mồi 2 receive/thread để không bỏ lỡ event lúc đang xử lý */
            for (int i = 0; i < 2; i++) PostReceive(new PendingMsg());

            while (running_) {
                DWORD bytes = 0;
                ULONG_PTR key = 0;
                LPOVERLAPPED ovlp = nullptr;

                BOOL ok = GetQueuedCompletionStatus(iocp_, &bytes, &key, &ovlp, INFINITE);
                if (!running_) break;
                if (!ok || !ovlp) continue;

                PendingMsg* pm = CONTAINING_RECORD(ovlp, PendingMsg, Ovlp);
                ULONGLONG msgId = pm->Msg.Header.MessageId;
                RW_EVENT  ev = pm->Msg.Event;   /* copy ra, giải phóng slot ngay */

                PostReceive(new PendingMsg());  /* mồi lại trước khi xử lý */
                delete pm;

                ULONG replyCode = RwReplyContinue;
                try {
                    if (handler_) replyCode = handler_(ev);
                }
                catch (const std::exception& e) {
                    LOG_E("Handler nem exception: %s", e.what());
                }
                catch (...) {
                    LOG_E("Handler nem exception khong xac dinh");
                }

                /*
                 * BẮT BUỘC reply nếu IsPending — nếu không driver sẽ timeout 200ms
                 * và toàn bộ I/O của máy sẽ bò. Reply nằm ngoài try/catch để
                 * chắc chắn luôn được gửi.
                 */
                if (ev.IsPending) {
                    RwReplyMessage reply{};
                    reply.Header.MessageId = msgId;
                    reply.Header.Status = 0;
                    reply.Reply.Code = replyCode;

                    /* kReplySize = 20, KHÔNG phải sizeof(reply) = 24 (padding đuôi) */
                    HRESULT hr = FilterReplyMessage(port_, &reply.Header, kReplySize);

                    if (FAILED(hr)) {
                        /* Chỉ log 1 lần mỗi 100 lỗi — nếu không sẽ ngập console */
                        if (replyFails_.fetch_add(1) % 100 == 0) {
                            LOG_E("FilterReplyMessage that bai: 0x%08X (da fail %llu lan)",
                                hr, replyFails_.load());
                            if (hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
                                LOG_E("  -> ERROR_MORE_DATA: kich thuoc reply KHONG khop. "
                                    "User gui %lu byte payload, driver khai sizeof(RW_REPLY)=%zu.",
                                    kReplySize - (DWORD)sizeof(FILTER_REPLY_HEADER),
                                    sizeof(RW_REPLY));
                            else if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER))
                                LOG_E("  -> MessageId sai hoac IRP da bi huy.");
                            LOG_E("  -> CoW KHONG HOAT DONG: driver timeout 200ms roi fail-open. "
                                "Khong file nao duoc backup.");
                        }
                    }
                }
            }
        }
    };

} // namespace rw