// Definition of the Socket class

#ifndef __SOCKET_HH__
#define __SOCKET_HH__

#include <sys/types.h>
#include <stdint.h>
#include <string>

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>

#define INVALID_SOCKET -1
#define SOCKET_ERROR   -1
typedef uint32_t SOCKET;
#else
#include <WinSock2.h>
#include <WS2tcpip.h>
typedef int socklen_t;
#define inet_pton InetPton
#define inet_ntop InetNtop
#endif

const int MAXHOSTNAME = 200;
const int MAXCONNECTIONS = 10;

using namespace std;

class Socket {
public:

	/**
	 * Constructor
	 */

	Socket();

	/**
	 * Destructor
	 */

	virtual ~Socket();

	// Server initialization

	/**
	 * Create a socket
	 * @return true if success, false if error
	 */

	bool create();

	/**
	 * Bind a socket to a port
	 * @param port Desired port number
	 * @return true if success, false if error
	 */

	bool bind(const int port);

	/**
	 * Set the maximum connections to listen
	 * @return true if success, false if error
	 */

	bool listen() const;

	/**
	 * Accept an incoming connection and save the sockfd in the Socket segment
	 * @param Pointer to a new socket segment (for the new connection)
	 * @return true if success, false if error
	 */

	bool accept(Socket*) const;

	// Client initialization

	/**
	 * Initialize a connection to the destination
	 * @param host Destination IP
	 * @param port Destination port
	 * @return true if success, false if error
	 */

	bool connect(const std::string host, const int port);

	// Data Transimission

	/**
	 * Send a certain number of bytes from a buffer to the socket
	 * @param buf Buffer to send
	 * @param buf_len Length to send
	 * @return Number of bytes sent
	 */

	int32_t sendn(const char* buf, int32_t buf_len);

	/**
	 * Receive a certain number of bytes form a socket to buffer
	 * @param buf Buffer to store the received data
	 * @param buf_len Lenth to receive
	 * @return Number of bytes received
	 */

	int32_t recvn(char* buf, int32_t buf_len);

	/**
	 * Aggressive read
	 * @param dst buffer place
	 * @param maxRecvByte max receive byte
	 * @return Number of bytes received
	 */
	int32_t aggressiveRecv(char* dst, int32_t maxRecvByte);

	void set_non_blocking(const bool);

	/**
	 * Check if the socket number is valid
	 * @return true if valid, false if invalid
	 */

	bool is_valid() const {
		return m_sock != -1;
	}

	SOCKET getSockfd();

	uint16_t getPort();

private:

	int m_sock;
	sockaddr_in m_addr;

};

#endif
