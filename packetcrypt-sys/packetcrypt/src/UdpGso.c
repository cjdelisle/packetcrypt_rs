/**
 * (C) Copyright 2021
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#include "packetcrypt/UdpGso.h"
#include "Buf.h"

#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <stdio.h>
#include <netinet/udp.h>

#ifndef SOCK_NONBLOCK
    #define SOCK_NONBLOCK 0
    #define NO_GO "SOCK_NONBLOCK"
#endif
#ifndef IPPROTO_UDP
    #define IPPROTO_UDP 0
    #define NO_GO "IPPROTO_UDP"
#endif
#ifndef UDP_SEGMENT
    #define UDP_SEGMENT 0
    #define NO_GO "UDP_SEGMENT"
#endif
#ifndef UDP_GRO
    #define UDP_GRO 0
    #define NO_GO "UDP_GRO"
#endif
#ifndef SOL_UDP
    #define SOL_UDP 0
    #define NO_GO "SOL_UDP"
#endif

bool UdpGso_supported() {
    #if defined(__linux__) || defined(NO_GO)
        return false;
    #endif
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (fd < 0) {
        return false;
    }
    int val = 1;
    bool result = true;
    if (setsockopt(fd, IPPROTO_UDP, UDP_GRO, &val, sizeof(val))) {
        result = false;
    } else if (setsockopt(fd, IPPROTO_UDP, UDP_SEGMENT, &val, sizeof(val))) {
        result = false;
    }
    close(fd);
    return result;
}

int UdpGro_enable(int fd, int pktSize) {
    #ifdef NO_GO
        return -9999;
    #endif
    int val = 1;
    if (setsockopt(fd, IPPROTO_UDP, UDP_GRO, &val, sizeof(val))) {
        printf("Error in setsockopt UDP_GRO %d (%s)", errno, strerror(errno));
        return -errno;
	}
    val = pktSize;
    if (setsockopt(fd, IPPROTO_UDP, UDP_SEGMENT, &val, sizeof(val))) {
        printf("Error in setsockopt UDP_SEGMENT %d (%s)", errno, strerror(errno));
        return -errno;
    }
    return 0;
}

int UdpGro_recvmsg(int fd, struct UdpGro_Sockaddr* addrOut, uint8_t* buf, int length, int* pktSize) {
    #ifdef NO_GO
        return -9999;
    #endif

    struct sockaddr_in6 in6 = {0};
	struct msghdr msg = {0};
    msg.msg_name = &in6;
    msg.msg_namelen = sizeof in6;

	struct iovec iov = { .iov_base = buf, .iov_len = length };
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    char control[CMSG_SPACE(sizeof(uint16_t))] = {0};	
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	*pktSize = -1;
	int len = recvmsg(fd, &msg, MSG_TRUNC | MSG_DONTWAIT);
    if (len == -1) {
        return -errno;
    }

    for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_UDP && cmsg->cmsg_type == UDP_GRO) {
            uint16_t *gsosizeptr = (uint16_t *) CMSG_DATA(cmsg);
            *pktSize = *gsosizeptr;
            break;
        }
    }

    if (msg.msg_namelen == sizeof(struct sockaddr_in6)) {
        addrOut->isIpv6 = 1;
        addrOut->port = in6.sin6_port;
        Buf_OBJCPY(addrOut->addr, &in6.sin6_addr);
    } else if (msg.msg_namelen == sizeof(struct sockaddr_in)) {
        struct sockaddr_in* in = (struct sockaddr_in*) &in6;
        addrOut->isIpv6 = 0;
        addrOut->port = in->sin_port;
        Buf_OBJCPY_LSRC(addrOut->addr, &in->sin_addr);
    } else {
        printf("WARNING: unexpected address length %d\n", msg.msg_namelen);
        return -1000;
    }
	return len;
}

int UdpGro_sendmsg(int fd, const struct UdpGro_Sockaddr* addr, const uint8_t* data, int length, int pktSize) {
    #ifdef NO_GO
        return -9999;
    #endif
    struct msghdr h = {0};

    struct sockaddr_in6 in6 = {0};
    if (addr->isIpv6) {
        in6.sin6_family = AF_INET6;
        Buf_OBJCPY(&in6.sin6_addr, addr->addr);
        in6.sin6_port = addr->port;
        h.msg_name = &in6;
        h.msg_namelen = sizeof in6;
    } else {
        struct sockaddr_in* in = (struct sockaddr_in*) &in6;
        in->sin_family = AF_INET;
        Buf_OBJCPY_LDST(&in->sin_addr, addr->addr);
        in->sin_port = addr->port;
        h.msg_name = in;
        h.msg_namelen = sizeof *in;
    }

    // cast off the const, promise not to change it
    struct iovec v = { .iov_base = (uint8_t*) data, .iov_len = length };
    h.msg_iov = &v;
    h.msg_iovlen = 1;
    char control
        [CMSG_SPACE(sizeof(uint16_t)) + /*gso*/
        CMSG_SPACE(sizeof(uint64_t)) /*txtime*/
    ] = {};
    h.msg_control = control;
    h.msg_controllen = CMSG_SPACE(sizeof(uint16_t));
    {
        struct cmsghdr* cm = CMSG_FIRSTHDR(&h);
        cm->cmsg_level = SOL_UDP;
        cm->cmsg_type = UDP_SEGMENT;
        cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
        uint16_t* gsosizeptr = (uint16_t*) CMSG_DATA(cm);
        *gsosizeptr = pktSize;
    }
    // TODO SCM_TXTIME
    // TODO SO_ZEROCOPY
    ssize_t size = -1;
    do {
      size = sendmsg(fd, &h, 0);
    } while (size == -1 && errno == EINTR);
    if (size < 0) {
        return -errno;
    }
    return size;
}

int UdpGro_setRecvBuf(int fd, int bufSz)
{
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufSz, sizeof(bufSz))) {
        printf("Error in setsockopt SOL_SOCKET %d (%s)", errno, strerror(errno));
        return -errno;
    }
    return 0;
}