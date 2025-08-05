#include <iostream>
#include <map>
#include <string>
#include <sstream>
#include <iomanip>
#include <thread>
#include <algorithm>
#include <chrono>
#include "windivert.h"
#include "PidMap.h"

constexpr size_t BANDWIDTH_LIMIT_BYTES = 5 * 1024 * 1024;
constexpr DWORD PID_TO_LIMIT = 15164;

struct DownloadSpeed {
    size_t currDownload = 0;
    std::chrono::steady_clock::time_point lastReset = std::chrono::steady_clock::now();
    size_t prevDownload = 0;

    size_t bytesThisSecond = 0;
    std::chrono::steady_clock::time_point windowStart = std::chrono::steady_clock::now();
};

int main()
{
    HANDLE handle = WinDivertOpen("tcp or udp", WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        std::cerr << "WinDivertOpen failed: " << GetLastError() << std::endl;
        return -1;
    }

    UCHAR packet[0xFFFF];
    UINT packet_len = sizeof(packet);
    UINT recv_len = 0;
    WINDIVERT_ADDRESS addr;
    PidMap pidMap;
    DownloadSpeed speed;

    while (true) {
        if (!WinDivertRecv(handle, packet, packet_len, &recv_len, &addr))
            continue;

        PWINDIVERT_IPHDR ip_header = nullptr;
        PWINDIVERT_TCPHDR tcp_header = nullptr;
        PWINDIVERT_UDPHDR udp_header = nullptr;
        if (!WinDivertHelperParsePacket(packet, recv_len, &ip_header, nullptr, nullptr, nullptr, nullptr, &tcp_header, &udp_header, nullptr, nullptr, nullptr, nullptr))
            continue;

        pidMap.refreshPidMap();
        if (ip_header) {
            const DWORD pid = pidMap.extractPid(ip_header, tcp_header, udp_header);
            
            if (pid == PID_TO_LIMIT && !addr.Outbound) {
                auto now = std::chrono::steady_clock::now();

                speed.currDownload += recv_len;
                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - speed.lastReset).count() >= 1000) {
                    double dwspeed = static_cast<double>(speed.currDownload - speed.prevDownload) / (1024.0 * 1024.0);
                    
                    std::ostringstream oss;
                    oss << std::fixed << std::setprecision(2) << dwspeed << " MB/s";
                    
                    std::cout << "[PROCESS " << pid << "] Download: " << oss.str() << std::endl;
                    speed.prevDownload = speed.currDownload;
                    speed.lastReset = now;
                }

                auto timeSinceWindowStart = std::chrono::duration_cast<std::chrono::milliseconds>(now - speed.windowStart).count();
                if (timeSinceWindowStart >= 1000) {
                    speed.bytesThisSecond = 0;
                    speed.windowStart = now;
                    timeSinceWindowStart = 0;
                }

                if (speed.bytesThisSecond + recv_len > BANDWIDTH_LIMIT_BYTES) {
                    auto timeLeftInWindow = 1000 - timeSinceWindowStart;
                    
                    if (timeLeftInWindow > 0) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(timeLeftInWindow));
                        
                        speed.bytesThisSecond = 0;
                        speed.windowStart = std::chrono::steady_clock::now();
                    }
                }

                speed.bytesThisSecond += recv_len;
            }
        }

        WinDivertSend(handle, packet, packet_len, &recv_len, &addr);
    }

    WinDivertClose(handle);

    return 0;
}