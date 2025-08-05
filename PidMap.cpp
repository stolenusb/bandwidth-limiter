#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include "PidMap.h"

PidMap::PidMap()
{
    lastRefresh = std::chrono::steady_clock::now();

    buildTcpPidMap();
    buildUdpPidMap();
}

void PidMap::refreshPidMap()
{
    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::seconds>(now - lastRefresh).count() > 1) {
        buildTcpPidMap();
        buildUdpPidMap();

        lastRefresh = now;
    }
}

void PidMap::buildTcpPidMap()
{
    mapTCP.clear();

    PMIB_TCPTABLE_OWNER_PID tcpTable = nullptr;
    DWORD size = 0;

    DWORD tcp_result = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (tcp_result != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "GetExtendedTcpTable Error (size query): " << tcp_result << std::endl;

        return;
    }

    tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (!tcpTable)
        return;

    tcp_result = GetExtendedTcpTable(tcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (tcp_result != NO_ERROR) {
        std::cerr << "GetExtendedTcpTable Error (data query): " << tcp_result << std::endl;
        free(tcpTable);

        return;
    }

    for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
        auto row = tcpTable->table[i];

        TcpMapKey key = {
            row.dwLocalAddr,
            ntohs((u_short)row.dwLocalPort),
            row.dwRemoteAddr,
            ntohs((u_short)row.dwRemotePort)
        };

        mapTCP[key] = row.dwOwningPid;
    }

    free(tcpTable);
}

void PidMap::buildUdpPidMap()
{
    mapUDP.clear();

    PMIB_UDPTABLE_OWNER_PID udpTable = nullptr;
    DWORD size = 0;

    DWORD udp_result = GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (udp_result != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "GetExtendedUdpTable Error (size query): " << udp_result << std::endl;

        return;
    }

    udpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(size);
    if (!udpTable)
        return;

    udp_result = GetExtendedUdpTable(udpTable, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (udp_result != NO_ERROR) {
        std::cerr << "GetExtendedUdpTable Error (data query): " << udp_result << std::endl;
        free(udpTable);

        return;
    }

    for (DWORD i = 0; i < udpTable->dwNumEntries; i++) {
        auto row = udpTable->table[i];

        UINT16 key = ntohs((u_short)row.dwLocalPort);
        mapUDP[key] = row.dwOwningPid;
    }

    free(udpTable);

    return;
}