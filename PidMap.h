#pragma once
#include <thread>
#include <unordered_map>
#include "windivert.h"

struct TcpMapKey {
    UINT32 local_addr;
    UINT16 local_port;
    UINT32 rem_addr;
    UINT16 rem_port;

    bool operator==(const TcpMapKey& other) const {
        return (local_addr == other.local_addr && local_port == other.local_port && rem_addr == other.rem_addr && rem_port == other.rem_port);
    }
};

struct TcpMapKeyHash {
    std::size_t operator()(const TcpMapKey& key) const {
        std::size_t h1 = std::hash<UINT32>{}(key.local_addr);
        std::size_t h2 = std::hash<UINT16>{}(key.local_port);
        std::size_t h3 = std::hash<UINT32>{}(key.rem_addr);
        std::size_t h4 = std::hash<UINT16>{}(key.rem_port);

        return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3);
    }
};

class PidMap
{
public:
    PidMap();

    void refreshPidMap();
    DWORD extractPid(const PWINDIVERT_IPHDR ip_header, const PWINDIVERT_TCPHDR tcp_header, const PWINDIVERT_UDPHDR udp_header);

private:
    std::unordered_map<TcpMapKey, DWORD, TcpMapKeyHash> mapTCP;
    std::unordered_map<UINT16, DWORD> mapUDP;

    void buildTcpPidMap();
    void buildUdpPidMap();

    std::chrono::steady_clock::time_point lastRefresh;
};

