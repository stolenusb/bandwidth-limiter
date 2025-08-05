#include <ws2tcpip.h>
#include <iostream>
#include <map>
#include "windivert.h"
#include "PidMap.h"

int main()
{
    HANDLE handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 0, 0);

    if (handle == INVALID_HANDLE_VALUE) {
        std::cerr << "WinDivertOpen failed: " << GetLastError() << std::endl;

        return -1;
    }
    
    std::cout << "Init tool." << std::endl;

    UCHAR packet[0xFFFF];
    UINT packet_len = sizeof(packet);
    UINT recv_len = 0;
    WINDIVERT_ADDRESS addr;

    PidMap pidMap;
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

        pidMap.refreshPidMap();

        if (ip_header) {
            char srcIpStr[INET_ADDRSTRLEN];
            char dstIpStr[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, &ip_header->SrcAddr, srcIpStr, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &ip_header->DstAddr, dstIpStr, INET_ADDRSTRLEN);

            DWORD pid = 0;

            if (tcp_header) {
                UINT16 srcPort = ntohs(tcp_header->SrcPort);
                UINT16 dstPort = ntohs(tcp_header->DstPort);

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

                if (pidMap.mapTCP.count(sent)) {
                    pid = pidMap.mapTCP[sent];
                    std::cout << "[PROCESS " << pid << "] " << "(TCP)" << " " << srcIpStr << ":" << srcPort << " -> " << dstIpStr << ":" << dstPort << std::endl;
                }
                else if (pidMap.mapTCP.count(recv)) {
                    pid = pidMap.mapTCP[recv];
                    std::cout << "[PROCESS " << pid << "] " << "(TCP)" << " " << dstIpStr << ":" << dstPort << " <- " << srcIpStr << ":" << srcPort << std::endl;
                }
            }

            if (udp_header) {
                uint16_t srcPort = ntohs(udp_header->SrcPort);
                uint16_t dstPort = ntohs(udp_header->DstPort);

                if (pidMap.mapUDP.count(srcPort)) {
                    pid = pidMap.mapUDP[srcPort];
                    std::cout << "[PROCESS " << pid << "] (UDP) " << srcIpStr << ":" << srcPort << " -> " << dstIpStr << ":" << dstPort << std::endl;
                }
                else if (pidMap.mapUDP.count(dstPort)) {
                    pid = pidMap.mapUDP[dstPort];
                    std::cout << "[PROCESS " << pid << "] (UDP) " << dstIpStr << ":" << dstPort << " <- " << srcIpStr << ":" << srcPort << std::endl;
                }
            }
        }

        WinDivertSend(handle, packet, packet_len, &recv_len, &addr);
    }

    return 0;
}