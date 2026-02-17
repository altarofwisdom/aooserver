#include "net_utils.hpp"

#include <stdio.h>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace aoo {
namespace net {

void socket_close(socket_type sock){
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

std::string socket_strerror(int err)
{
#ifdef _WIN32
    wchar_t wbuf[1024] = {};
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, 0,
                   err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), wbuf,
                   1024, nullptr);
    if (wbuf[0] == 0) {
        return {};
    }
    int size = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return {};
    }
    std::string out;
    out.resize(static_cast<size_t>(size - 1));
    WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, out.data(), size, nullptr, nullptr);
    return out;
#else
    char buf[1024];
    snprintf(buf, 1024, "%s", strerror(err));
    return buf;
#endif
}

int socket_errno(){
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

int socket_set_nonblocking(socket_type socket, int nonblocking)
{
#ifdef _WIN32
    u_long modearg = nonblocking;
    if (ioctlsocket(socket, FIONBIO, &modearg) != NO_ERROR) {
        // Log the actual error for debugging
        int err = WSAGetLastError();
        fprintf(stderr, "socket_set_nonblocking failed: %d\n", err);
        return -1;
    }
#else
    int sockflags = fcntl(socket, F_GETFL, 0);
    if (nonblocking)
        sockflags |= O_NONBLOCK;
    else
        sockflags &= ~O_NONBLOCK;
    if (fcntl(socket, F_SETFL, sockflags) < 0)
        return -1;
#endif
    return 0;
}

// kudos to https://stackoverflow.com/a/46062474/6063908
int socket_connect(socket_type socket, const ip_address& addr, float timeout)
{
    // set nonblocking and connect
    if (socket_set_nonblocking(socket, 1) < 0) {
        fprintf(stderr, "socket_connect: failed to set nonblocking\n");
        return -1;
    }

    int connect_result = connect(socket, (const struct sockaddr *)&addr.address, addr.length);
    int connect_errno = socket_errno();
    
    if (connect_result < 0)
    {
        int status;
        struct timeval timeoutval;
        fd_set writefds, errfds;
    #ifdef _WIN32
        if (connect_errno != WSAEWOULDBLOCK)
    #else
        if (connect_errno != EINPROGRESS)
    #endif
        {
            fprintf(stderr, "socket_connect: connect failed immediately with error %d\n", connect_errno);
            return -1; // break on "real" error
        }

        // block with select using timeout
        if (timeout < 0) timeout = 0;
        timeoutval.tv_sec = (int)timeout;
        timeoutval.tv_usec = (timeout - timeoutval.tv_sec) * 1000000;
        FD_ZERO(&writefds);
        FD_SET(socket, &writefds); // socket is connected when writable
        FD_ZERO(&errfds);
        FD_SET(socket, &errfds); // catch exceptions

        status = select(socket+1, NULL, &writefds, &errfds, &timeoutval);
        if (status < 0) // select failed
        {
            fprintf(stderr, "socket_connect: select failed");
            return -1;
        }
        else if (status == 0) // connection timed out
        {
        #ifdef _WIN32
            WSASetLastError(WSAETIMEDOUT);
        #else
            errno = ETIMEDOUT;
        #endif
            return -1;
        }

        if (FD_ISSET(socket, &errfds)) // connection failed
        {
            int err; socklen_t len = sizeof(err);
            getsockopt(socket, SOL_SOCKET, SO_ERROR, (char *)&err, &len);
        #ifdef _WIN32
            WSASetLastError(err);
        #else
            errno = err;
        #endif
            return -1;
        }
    }
    // done, set blocking again
    socket_set_nonblocking(socket, 0);
    return 0;
}

} // net
} // aoo
