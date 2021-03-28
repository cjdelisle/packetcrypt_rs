/**
 * (C) Copyright 2021
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#include <stdint.h>

struct UdpGro_Sockaddr {
    uint16_t isIpv6;
    uint16_t port;
    uint8_t addr[16];
};

const char* UdpGso_supported();
int UdpGro_enable(int fd, int pktSize);
int UdpGro_recvmsg(int fd, struct UdpGro_Sockaddr* addrOut, uint8_t* buf, int len, int* pktSize);
int UdpGro_sendmsg(int fd, const struct UdpGro_Sockaddr* addr, const uint8_t* data, int length, int pktSize);

int UdpGro_setRecvBuf(int fd, int bufSz);