#pragma once

#include <inttypes.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int socklen_t;
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#endif

#include <cstring>
#include <string>

namespace aoo {
namespace net {

struct ip_address {
    ip_address(){
        memset(&address, 0, sizeof(address));
        length = sizeof(address);
    }
    ip_address(const struct sockaddr *sa, socklen_t len){
        memcpy(&address, sa, len);
        length = len;
    }
    ip_address(uint32_t ipv4, int port){
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(ipv4);
        sa.sin_port = htons(port);
        memcpy(&address, &sa, sizeof(sa));
        length = sizeof(sa);
    }
    ip_address(const std::string& host, int port, bool prefer_ipv6 = false){
        struct addrinfo hints, *res = nullptr;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_NUMERICHOST;

        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", port);

        if (getaddrinfo(host.c_str(), port_str, &hints, &res) == 0 && res != nullptr) {
            // If prefer_ipv6, try to find an IPv6 address first
            struct addrinfo *selected = res;
            if (prefer_ipv6) {
                for (struct addrinfo *r = res; r != nullptr; r = r->ai_next) {
                    if (r->ai_family == AF_INET6) {
                        selected = r;
                        break;
                    }
                }
            }
            memcpy(&address, selected->ai_addr, selected->ai_addrlen);
            length = (socklen_t)selected->ai_addrlen;
            freeaddrinfo(res);
        } else {
            // Fallback to IPv4
            struct sockaddr_in sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET;
            sa.sin_addr.s_addr = inet_addr(host.c_str());
            sa.sin_port = htons(port);
            memcpy(&address, &sa, sizeof(sa));
            length = sizeof(sa);
        }
    }

    ip_address(const ip_address& other){
        memcpy(&address, &other.address, other.length);
        length = other.length;
    }
    ip_address& operator=(const ip_address& other){
        memcpy(&address, &other.address, other.length);
        length = other.length;
        return *this;
    }

    bool operator==(const ip_address& other) const {
        if (address.ss_family == other.address.ss_family){
            if (address.ss_family == AF_INET){
                auto a = (const struct sockaddr_in *)&address;
                auto b = (const struct sockaddr_in *)&other.address;
                return (a->sin_addr.s_addr == b->sin_addr.s_addr)
                        && (a->sin_port == b->sin_port);
            } else if (address.ss_family == AF_INET6) {
                auto a = (const struct sockaddr_in6 *)&address;
                auto b = (const struct sockaddr_in6 *)&other.address;
                return (memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(struct in6_addr)) == 0)
                        && (a->sin6_port == b->sin6_port);
            } else {
                return false;
            }
        } else {
            // Check for IPv4-mapped IPv6 addresses
            const struct sockaddr_in *v4 = nullptr;
            const struct sockaddr_in6 *v6 = nullptr;
            if (address.ss_family == AF_INET && other.address.ss_family == AF_INET6) {
                v4 = (const struct sockaddr_in *)&address;
                v6 = (const struct sockaddr_in6 *)&other.address;
            } else if (address.ss_family == AF_INET6 && other.address.ss_family == AF_INET) {
                v6 = (const struct sockaddr_in6 *)&address;
                v4 = (const struct sockaddr_in *)&other.address;
            }
            if (v4 && v6 && IN6_IS_ADDR_V4MAPPED(&v6->sin6_addr)) {
                uint32_t mapped_ipv4;
                memcpy(&mapped_ipv4, &v6->sin6_addr.s6_addr[12], 4);
                return (v4->sin_addr.s_addr == mapped_ipv4) && (v4->sin_port == v6->sin6_port);
            }
            return false;
        }
    }

    std::string name() const {
        char buf[INET6_ADDRSTRLEN];
        if (address.ss_family == AF_INET){
            auto addr = reinterpret_cast<const struct sockaddr_in *>(&address);
            if (inet_ntop(AF_INET, &addr->sin_addr, buf, sizeof(buf))) {
                return buf;
            }
        } else if (address.ss_family == AF_INET6) {
            auto addr = reinterpret_cast<const struct sockaddr_in6 *>(&address);
            if (inet_ntop(AF_INET6, &addr->sin6_addr, buf, sizeof(buf))) {
                return buf;
            }
        }
        return "";
    }

    int port() const {
        if (address.ss_family == AF_INET){
            return ntohs(reinterpret_cast<const struct sockaddr_in *>(&address)->sin_port);
        } else if (address.ss_family == AF_INET6) {
            return ntohs(reinterpret_cast<const struct sockaddr_in6 *>(&address)->sin6_port);
        }
        return -1;
    }

    int family() const {
        return address.ss_family;
    }

    bool is_ipv6() const {
        return address.ss_family == AF_INET6;
    }

    bool is_ipv4() const {
        return address.ss_family == AF_INET;
    }

    ip_address to_ipv6_mapped() const {
        if (address.ss_family == AF_INET6) {
            return *this;
        }
        if (address.ss_family == AF_INET) {
            auto ipv4 = reinterpret_cast<const struct sockaddr_in *>(&address);
            struct sockaddr_in6 sa6;
            memset(&sa6, 0, sizeof(sa6));
            sa6.sin6_family = AF_INET6;
            sa6.sin6_port = ipv4->sin_port;
            memset(&sa6.sin6_addr.s6_addr[0], 0, 10);
            sa6.sin6_addr.s6_addr[10] = 0xff;
            sa6.sin6_addr.s6_addr[11] = 0xff;
            memcpy(&sa6.sin6_addr.s6_addr[12], &ipv4->sin_addr.s_addr, 4);
            return ip_address(reinterpret_cast<struct sockaddr*>(&sa6), sizeof(sa6));
        }
        return *this;
    }

    struct sockaddr_storage address;
    socklen_t length;
};

void socket_close(int sock);

std::string socket_strerror(int err);

int socket_errno();

int socket_set_nonblocking(int socket, int nonblocking);

int socket_connect(int socket, const ip_address& addr, float timeout);

} // net
} // aoo
