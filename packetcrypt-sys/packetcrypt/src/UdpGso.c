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
#include <stdio.h>
#ifdef _WIN32
const char* UdpGso_supported() {
    return "win32";
}
int UdpGro_enable(int _fd, int _pktSize) {
    return -9999;
}
int UdpGro_recvmsg(int _fd, struct UdpGro_Sockaddr* _addrOut, uint8_t* _buf, int _length, int* _pktSize) {
    return -9999;
}
int UdpGro_sendmsg(int _fd, const struct UdpGro_Sockaddr* _addr, const uint8_t* _data, int _length, int _pktSize) {
    return -9999;
}
int UdpGro_setRecvBuf(int _fd, int _bufSz) {
    return -9999;
}
#else
#include <netinet/in.h>
#include <netinet/udp.h>


#ifndef __linux__
    #define NO_GO "not linux"
#endif
#ifndef SOCK_NONBLOCK
    #define SOCK_NONBLOCK 0
    #ifndef NO_GO
        #define NO_GO "missing SOCK_NONBLOCK"
    #endif
#endif
#ifndef IPPROTO_UDP
    #define IPPROTO_UDP 0
    #ifndef NO_GO
        #define NO_GO "missing IPPROTO_UDP"
    #endif
#endif
#ifndef UDP_SEGMENT
    #define UDP_SEGMENT 0
    #ifndef NO_GO
        #define NO_GO "missing UDP_SEGMENT"
    #endif
#endif
#ifndef UDP_GRO
    #define UDP_GRO 0
    #ifndef NO_GO
        #define NO_GO "missing UDP_GRO"
    #endif
#endif
#ifndef SOL_UDP
    #define SOL_UDP 0
    #ifndef NO_GO
        #define NO_GO "missing SOL_UDP"
    #endif
#endif

const char* UdpGso_supported() {
    #ifdef NO_GO
        return NO_GO;
    #endif
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (fd < 0) {
        return "fd < 0";
    }
    int val = 1;
    const char* result = NULL;
    if (setsockopt(fd, IPPROTO_UDP, UDP_GRO, &val, sizeof(val))) {
        printf("setsockopt(UDP_GRO) -> %d (%s)", errno, strerror(errno));
        result = "setsockopt(UDP_GRO)";
    } else if (setsockopt(fd, IPPROTO_UDP, UDP_SEGMENT, &val, sizeof(val))) {
        printf("setsockopt(UDP_SEGMENT) -> %d (%s)", errno, strerror(errno));
        result = "setsockopt(UDP_SEGMENT)";
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
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
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
        addrOut->port = ntohs(in6.sin6_port);
        Buf_OBJCPY(addrOut->addr, &in6.sin6_addr);
    } else if (msg.msg_namelen == sizeof(struct sockaddr_in)) {
        struct sockaddr_in* in = (struct sockaddr_in*) &in6;
        addrOut->isIpv6 = 0;
        addrOut->port = ntohs(in->sin_port);
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
        in6.sin6_port = htons(addr->port);
        h.msg_name = &in6;
        h.msg_namelen = sizeof in6;
    } else {
        struct sockaddr_in* in = (struct sockaddr_in*) &in6;
        in->sin_family = AF_INET;
        Buf_OBJCPY_LDST(&in->sin_addr, addr->addr);
        in->sin_port = htons(addr->port);
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
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -errno;
    }
    return size;
}

#ifndef SO_RCVBUFFORCE
    #define SO_RCVBUFFORCE 0
    #define HAS_RCVBUFFORCE 0
#else
    #define HAS_RCVBUFFORCE 1
#endif

int UdpGro_setRecvBuf(int fd, int bufSz)
{
    if (HAS_RCVBUFFORCE) {
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &bufSz, sizeof(bufSz))) {
            if (errno != EPERM) {
                printf("Error in setsockopt SO_RCVBUFFORCE %d (%s)", errno, strerror(errno));
                return -errno;
            }
        }    
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufSz, sizeof(bufSz))) {
        printf("Error in setsockopt SO_RCVBUF %d (%s)", errno, strerror(errno));
        return -errno;
    }
    int bufSz1 = 0;
    socklen_t bufSz1l = sizeof(bufSz1);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufSz1, &bufSz1l)) {
        printf("Error in getsockopt SO_RCVBUF %d (%s)", errno, strerror(errno));
        return -errno;
    }
    if (bufSz1 != bufSz) {
        printf("Error Unable to set SOL_SOCKET %d (%s)", errno, strerror(errno));
    }
    return 0;
}

#endif