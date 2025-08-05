#pragma once
#include <thread>
#include <map>
#include "windivert.h"

struct TcpMapKey {
    UINT32 local_addr;
    UINT16 local_port;
    UINT32 rem_addr;
    UINT16 rem_port;

    bool operator<(const TcpMapKey& other) const {
        return std::tie(local_addr, local_port, rem_addr, rem_port) <
            std::tie(other.local_addr, other.local_port, other.rem_addr, other.rem_port);
    }
};

class PidMap
{
public:
    PidMap();

    void refreshPidMap();
    DWORD extractPid(const PWINDIVERT_IPHDR ip_header, const PWINDIVERT_TCPHDR tcp_header, const PWINDIVERT_UDPHDR udp_header);

private:
    std::map<TcpMapKey, DWORD> mapTCP;
    std::map<UINT16, DWORD> mapUDP;

    void buildTcpPidMap();
    void buildUdpPidMap();

    std::chrono::steady_clock::time_point lastRefresh;
};

