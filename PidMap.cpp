#include <iostream>
#include <ws2tcpip.h>
#include <iphlpapi.h>
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

DWORD PidMap::extractPid(const PWINDIVERT_IPHDR ip_header, const PWINDIVERT_TCPHDR tcp_header, const PWINDIVERT_UDPHDR udp_header)
{
    DWORD pid = 0;

    char srcIpStr[INET_ADDRSTRLEN];
    char dstIpStr[INET_ADDRSTRLEN];
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;

    inet_ntop(AF_INET, &ip_header->SrcAddr, srcIpStr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_header->DstAddr, dstIpStr, INET_ADDRSTRLEN);

    if (tcp_header) {
        srcPort = ntohs(tcp_header->SrcPort);
        dstPort = ntohs(tcp_header->DstPort);

        TcpMapKey sent = {
            ip_header->SrcAddr,
            srcPort,
            ip_header->DstAddr,
            dstPort
        };

        TcpMapKey recv = {
            ip_header->DstAddr,
            dstPort,
            ip_header->SrcAddr,
            srcPort
        };

        auto sentPkt = mapTCP.find(sent);
        if (sentPkt != mapTCP.end()) {
            pid = sentPkt->second;
            //std::cout << "[PROCESS " << pid << "] " << "(TCP)" << " " << srcIpStr << ":" << srcPort << " -> " << dstIpStr << ":" << dstPort << std::endl;
        } else {
            auto recvPkt = mapTCP.find(recv);
            if (recvPkt != mapTCP.end()) {
                pid = recvPkt->second;
                //std::cout << "[PROCESS " << pid << "] " << "(TCP)" << " " << dstIpStr << ":" << dstPort << " <- " << srcIpStr << ":" << srcPort << std::endl;
            }
        }

        return pid;
    }

    if (udp_header) {
        srcPort = ntohs(udp_header->SrcPort);
        dstPort = ntohs(udp_header->DstPort);

        auto pktSent = mapUDP.find(srcPort);
        if (pktSent != mapUDP.end()) {
            pid = pktSent->second;
            //std::cout << "[PROCESS " << pid << "] (UDP) " << dstIpStr << ":" << dstPort << " <- " << srcIpStr << ":" << srcPort << std::endl;
        } else {
            auto pktRecv = mapUDP.find(dstPort);
            if (pktRecv != mapUDP.end()) {
                pid = pktRecv->second;
                //std::cout << "[PROCESS " << pid << "] (UDP) " << srcIpStr << ":" << srcPort << " -> " << dstIpStr << ":" << dstPort << std::endl;
            }
        }
    }

    return pid;
}

void PidMap::buildTcpPidMap()
{
    mapTCP.clear();

    DWORD size = 0;
    DWORD tcp_result = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (tcp_result != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "GetExtendedTcpTable Error (size query): " << tcp_result << std::endl;

        return;
    }

    PMIB_TCPTABLE_OWNER_PID tcpTable = static_cast<PMIB_TCPTABLE_OWNER_PID>(malloc(size));
    if (!tcpTable)
        return;

    tcp_result = GetExtendedTcpTable(tcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (tcp_result != NO_ERROR) {
        std::cerr << "GetExtendedTcpTable Error (data query): " << tcp_result << std::endl;
        free(tcpTable);

        return;
    }

    mapTCP.reserve(tcpTable->dwNumEntries);
    
    for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
        auto row = tcpTable->table[i];

        TcpMapKey key = {
            row.dwLocalAddr,
            ntohs(static_cast<u_short>(row.dwLocalPort)),
            row.dwRemoteAddr,
            ntohs(static_cast<u_short>(row.dwRemotePort))
        };

        mapTCP[key] = row.dwOwningPid;
    }

    free(tcpTable);
}

void PidMap::buildUdpPidMap()
{
    mapUDP.clear();

    DWORD size = 0;
    DWORD udp_result = GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (udp_result != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "GetExtendedUdpTable Error (size query): " << udp_result << std::endl;

        return;
    }

    PMIB_UDPTABLE_OWNER_PID udpTable = static_cast<PMIB_UDPTABLE_OWNER_PID>(malloc(size));
    if (!udpTable)
        return;

    udp_result = GetExtendedUdpTable(udpTable, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (udp_result != NO_ERROR) {
        std::cerr << "GetExtendedUdpTable Error (data query): " << udp_result << std::endl;
        free(udpTable);

        return;
    }

    mapUDP.reserve(udpTable->dwNumEntries);

    for (DWORD i = 0; i < udpTable->dwNumEntries; i++) {
        auto row = udpTable->table[i];

        UINT16 key = ntohs(static_cast<u_short>(row.dwLocalPort));
        mapUDP[key] = row.dwOwningPid;
    }

    free(udpTable);

    return;
}