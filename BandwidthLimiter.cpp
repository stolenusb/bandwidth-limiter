#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include <tcpmib.h>
#include <thread>
#include <map>
#include "windivert.h"

struct FlowKey {
    UINT32 local_addr;
    UINT16 local_port;
    UINT32 rem_addr;
    UINT16 rem_port;
    
    bool operator<(const FlowKey& other) const {
        return std::tie(local_addr, local_port, rem_addr, rem_port) <
            std::tie(other.local_addr, other.local_port, other.rem_addr, other.rem_port);
    }
};

std::map<FlowKey, DWORD> buildTcpPidMap()
{
    std::map<FlowKey, DWORD> pidMap;

    PMIB_TCPTABLE_OWNER_PID tcpTable = nullptr;
    DWORD size = 0;

    DWORD result = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "GetExtendedTcpTable Error (size query): " << result << std::endl;

        return pidMap;
    }

    tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (!tcpTable)
        return pidMap;

    result = GetExtendedTcpTable(tcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != NO_ERROR) {
        std::cerr << "GetExtendedTcpTable Error (data query): " << result << std::endl;
        free(tcpTable);

        return pidMap;
    }

    for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
        auto row = tcpTable->table[i];

        FlowKey key = {
            row.dwLocalAddr,
            ntohs((u_short)row.dwLocalPort),
            row.dwRemoteAddr,
            ntohs((u_short)row.dwRemotePort)
        };

        pidMap[key] = row.dwOwningPid;
    }

    free(tcpTable);

    return pidMap;
}

int main()
{
    HANDLE handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 0, 0);

    if (handle == INVALID_HANDLE_VALUE) {
        std::cerr << "WinDivertOpen failed: " << GetLastError() << std::endl;

        return -1;
    }
    
    std::cout << "Init tool." << std::endl;

    unsigned char packet[0xFFFF];
    UINT packet_len = sizeof(packet);
    UINT recv_len = 0;
    WINDIVERT_ADDRESS addr;

    std::map<FlowKey, DWORD> pidMap = buildTcpPidMap();
    auto lastRefresh = std::chrono::steady_clock::now();
    while (true) {
        if (!WinDivertRecv(handle, packet, packet_len, &recv_len, &addr))
            continue;
        
        PWINDIVERT_IPHDR ip_header = nullptr;
        PWINDIVERT_TCPHDR tcp_header = nullptr;
        PWINDIVERT_UDPHDR udp_header = nullptr;

        if (!WinDivertHelperParsePacket(
            packet,
            recv_len,
            &ip_header,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            &tcp_header,
            &udp_header,
            nullptr,
            nullptr,
            nullptr,
            nullptr
        ))
            continue;

        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - lastRefresh).count() > 1) {
            pidMap = buildTcpPidMap();
            lastRefresh = now;
        }

        if (ip_header && tcp_header) {
            FlowKey sent = {
                ip_header->SrcAddr,
                ntohs(tcp_header->SrcPort),
                ip_header->DstAddr,
                ntohs(tcp_header->DstPort)
            };

            FlowKey recv = {
                ip_header->DstAddr,
                ntohs(tcp_header->DstPort),
                ip_header->SrcAddr,
                ntohs(tcp_header->SrcPort)
            };

            DWORD pid = 0;
            if (pidMap.count(sent)) {
                pid = pidMap[sent];
                
                if (pid != 0)
                    std::cout << "PROCESS: " << pid << " sent packet." << std::endl;
            } else if (pidMap.count(recv)) {
                pid = pidMap[recv];

                if (pid != 0)
                    std::cout << "PROCESS: " << pid << " received packet." << std::endl;
            }

        }

        WinDivertSend(handle, packet, packet_len, &recv_len, &addr);
    }

    return 0;
}