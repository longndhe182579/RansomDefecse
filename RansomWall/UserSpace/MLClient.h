/*
 * MLClient.h — Gọi ML engine qua WinHTTP.
 *
 * Dùng WinHTTP trực tiếp thay vì spawn "curl" qua _popen: tránh phải ghi
 * payload ra file tạm (race khi nhiều PID gọi đồng thời) và tránh chi phí
 * spawn cmd.exe mỗi lần gọi.
 */
#pragma once

#include "Util.h"
#include "Config.h"
#include "Features.h"

#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

namespace rw {

    struct MLResponse {
        Verdict     verdict = Verdict::Unknown;
        double      confidence = 0.0;
        std::string raw;
    };

    class MLClient {
    public:
        MLResponse Predict(const std::string& jsonBody) {
            MLResponse out;

            HINTERNET session = WinHttpOpen(L"RansomWall/4.0",
                WINHTTP_ACCESS_TYPE_NO_PROXY,
                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
            if (!session) return out;

            WinHttpSetTimeouts(session, cfg::ML_TIMEOUT_MS, cfg::ML_TIMEOUT_MS,
                cfg::ML_TIMEOUT_MS, cfg::ML_TIMEOUT_MS);

            HINTERNET conn = WinHttpConnect(session, cfg::ML_HOST.c_str(),
                (INTERNET_PORT)cfg::ML_PORT, 0);
            if (!conn) { WinHttpCloseHandle(session); return out; }

            HINTERNET req = WinHttpOpenRequest(conn, L"POST", cfg::ML_PATH.c_str(),
                nullptr, WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
            if (!req) { WinHttpCloseHandle(conn); WinHttpCloseHandle(session); return out; }

            const wchar_t* hdr = L"Content-Type: application/json\r\n";
            BOOL ok = WinHttpSendRequest(req, hdr, (DWORD)-1,
                (LPVOID)jsonBody.data(), (DWORD)jsonBody.size(),
                (DWORD)jsonBody.size(), 0);
            if (ok) ok = WinHttpReceiveResponse(req, nullptr);

            if (ok) {
                std::string body;
                for (;;) {
                    DWORD avail = 0;
                    if (!WinHttpQueryDataAvailable(req, &avail) || avail == 0) break;
                    std::string chunk(avail, 0);
                    DWORD read = 0;
                    if (!WinHttpReadData(req, chunk.data(), avail, &read)) break;
                    chunk.resize(read);
                    body += chunk;
                }
                out.raw = body;
                out.verdict = ParseVerdict(body, out.confidence);
            }

            WinHttpCloseHandle(req);
            WinHttpCloseHandle(conn);
            WinHttpCloseHandle(session);
            return out;
        }

    private:
        static Verdict ParseVerdict(const std::string& body, double& conf) {
            if (body.empty()) return Verdict::Unknown;

            JsonVal v;
            if (JsonP::Parse(body, v) && v.type == JsonVal::Obj) {
                conf = v.N("confidence", 0.0);
                std::string d = ToLowerA(v.S("verdict"));
                if (d == "malware" || d == "kill")   return Verdict::Malware;
                if (d == "benign" || d == "safe")   return Verdict::Benign;
            }
            /* Fallback: khớp chuỗi thô, phòng khi Flask trả text thường */
            std::string b = ToLowerA(body);
            if (b.find("malware") != std::string::npos || b.find("kill") != std::string::npos)
                return Verdict::Malware;
            if (b.find("benign") != std::string::npos || b.find("safe") != std::string::npos)
                return Verdict::Benign;
            return Verdict::Unknown;
        }
    };

} // namespace rw