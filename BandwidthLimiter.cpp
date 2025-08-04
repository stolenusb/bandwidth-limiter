#include <iostream>
#include <windows.h>
#include "windivert.h"

int main()
{
    HANDLE handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 0, 0);

    if (handle == INVALID_HANDLE_VALUE) {
        std::cerr << "WinDivertOpen failed! Error code: " << GetLastError() << std::endl;

        return 1;
    }

    std::cout << "WinDivert initialized." << std::endl;

    while (true) {

    }

    WinDivertClose(handle);

    return 0;
}