// Implementation of the Socket class.

#include "socket.hh"
#include <string.h>
#include <string>
#include <iostream>
#include <errno.h>
#include <fcntl.h>

#ifndef _WIN32
#include <sys/ioctl.h>
#define closesocket(s)	close(s)
#else

#endif

#include "../common/debug.hh"
#include "../common/convertor.hh"

using namespace std;

Socket::Socket() :
m_sock(INVALID_SOCKET) {

#ifdef _WIN32
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	wVersionRequested = MAKEWORD(2, 2);
	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0)
		debug("Setup Failed");
#endif

	memset(&m_addr, 0, sizeof(m_addr));
}

Socket::~Socket() {
	if (is_valid())
		closesocket(m_sock);

	debug("Socket %d closed\n", (uint32_t)m_sock);
#ifndef _WIN32

#else
	WSACleanup();
#endif
}

bool Socket::create() {
	m_sock = socket(AF_INET, SOCK_STREAM, 0);
	debug("Socket %d created\n", (uint32_t)m_sock);

	if (!is_valid())
		return false;

	int sndbuf_size = stringToByte("10M");
	if (setsockopt(m_sock, SOL_SOCKET, SO_SNDBUF, (const char*)&sndbuf_size, sizeof(sndbuf_size)) == SOCKET_ERROR){
		debug("Failed to Set Send Buf Size to %d\n", sndbuf_size);
	}

	// TIME_WAIT - argh
	int on = 1;

	if (setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on,
		sizeof(on)) == SOCKET_ERROR)
		return false;

	return true;
}

bool Socket::bind(const int port) {

	if (!is_valid()) {
		return false;
	}

	m_addr.sin_family = AF_INET;
	m_addr.sin_addr.s_addr = INADDR_ANY;
	m_addr.sin_port = htons(port);

	int bind_return = ::bind(m_sock, (struct sockaddr *) &m_addr,
		sizeof(m_addr));

	if (bind_return == INVALID_SOCKET) {
		return false;
	}

	return true;
}

bool Socket::listen() const {
	if (!is_valid()) {
		return false;
	}

	int listen_return = ::listen(m_sock, MAXCONNECTIONS);

	if (listen_return == SOCKET_ERROR) {
		return false;
	}

	return true;
}

bool Socket::accept(Socket* new_socket) const {
	int addr_length = sizeof(m_addr);
	new_socket->m_sock = ::accept(m_sock, (sockaddr *)&m_addr,
		(socklen_t *)&addr_length);

	if (new_socket->m_sock == INVALID_SOCKET)
		return false;
	else
		return true;
}

int32_t Socket::sendn(const char* buf, int32_t buf_len) {

	const SOCKET sd = m_sock;

	int32_t n_left = buf_len; // actual data bytes sent
	int32_t n;
	while (n_left > 0) {

		// -----------
		// check if tcp socket is writable
		// -----------

		if (DEBUG) {
			fd_set wfds;
			struct timeval tv = { 0, 0 };
			int retval;

			FD_ZERO(&wfds);
			FD_SET(m_sock, &wfds);

			retval = select(m_sock + 1, NULL, &wfds, NULL, &tv);

			if (retval == SOCKET_ERROR)
				perror("select()\n");
			else if (retval)
				debug("FD = %" PRIu32 " Writable\n", sd);
			else
				debug("FD = %" PRIu32 " Not Writable\n", sd);

			fflush(stdout);
		}

		// -----------

		if ((n = send(sd, buf + (buf_len - n_left), n_left, 0)) == SOCKET_ERROR) {
			perror("sendn");
			exit(-1);
		}
		else if (n == 0) {
			return 0;
		}
		n_left -= n;
	}
	return buf_len;
}

int32_t Socket::recvn(char* buf, int32_t buf_len) {

	const SOCKET sd = m_sock;

	int32_t n_left = buf_len;
	int32_t n = 0;
	while (n_left > 0) {
		if ((n = recv(sd, buf + (buf_len - n_left), n_left, 0)) == SOCKET_ERROR) {
			perror("recvn");
			exit(-1);
		}
		else if (n == 0) {
			return 0;
		}
		n_left -= n;
	}
	return buf_len;
}

int32_t Socket::aggressiveRecv(char* dst, int32_t maxRecvByte) {

	const SOCKET sd = m_sock;

	int32_t recvByte = recv(sd, dst, maxRecvByte, 0);
	if (recvByte == SOCKET_ERROR) {
		perror("Aggressive Recv");
		exit(-1);
	}
	return recvByte;
}

bool Socket::connect(const std::string host, const int port) {
	if (!is_valid())
		return false;

	m_addr.sin_family = AF_INET;
	m_addr.sin_port = htons(port);

	int addresslen = host.length();

#ifndef _WIN32
	char* address = host.c_str();
#else
	WCHAR *address = new WCHAR[addresslen];
	mbstowcs(address, host.c_str(), addresslen);
#endif
	int status = inet_pton(AF_INET, address, &m_addr.sin_addr);

#ifndef _WIN32
	if (errno == EAFNOSUPPORT)
		return false;
#else
	if (WSAGetLastError() == WSAEAFNOSUPPORT)
		return false;
#endif

	status = ::connect(m_sock, (sockaddr *)&m_addr, sizeof(m_addr));

	if (status == SOCKET_ERROR)
		return false;

	return true;
}

void Socket::set_non_blocking(const bool b) {

#ifndef _WIN32
	int opts;

	opts = fcntl(m_sock, F_GETFL);

	if (opts < 0) {
		return;
	}

	if (b)
		opts = (opts | O_NONBLOCK);
	else
		opts = (opts & ~O_NONBLOCK);

	fcntl(m_sock, F_SETFL, opts);
#else
	u_long b_mode = 0;
	if (b)
		b_mode = 1;
	int status = ioctlsocket(m_sock, FIONBIO, &b_mode);
	if (status == SOCKET_ERROR)
		return;
#endif

}

SOCKET Socket::getSockfd() {
	return (SOCKET)m_sock;
}

uint16_t Socket::getPort() {
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);
	if (getsockname(m_sock, (struct sockaddr *)&sin, &len) == SOCKET_ERROR)
		perror("getsockname");
	else
		return ntohs(sin.sin_port);
	return 0;
}
