#ifndef __NETFUNC_HH__
#define __NETFUNC_HH__
#include <stdint.h>
#include <sys/types.h>
#include <string.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <ifaddrs.h>
#else
#include <WinSock2.h>
#include <WS2tcpip.h>
typedef int socklen_t;
#define inet_pton InetPton
#define inet_ntop InetNtop
#endif

#include <errno.h>
#include <stdio.h>
#include <string>
using namespace std;

//Ref:http://publib.boulder.ibm.com/infocenter/iseries/v7r1m0/index.jsp?topic=%2Fapis%2Fgetifaddrs.htm
uint32_t getInterfaceAddressV4(char* interfaceName) {
	uint32_t ret = 0;
#ifndef _WIN32
	struct ifaddrs *interfaceArray = NULL, *iter = NULL;
	void *addrPtr = NULL;
	int rc = 0;

	rc = getifaddrs(&interfaceArray);  /* retrieve the current interfaces */
	if (0 == rc) {
		for (iter = interfaceArray; iter != NULL; iter = iter->ifa_next) {
			if (iter->ifa_addr->sa_family == AF_INET) {
				addrPtr = &((struct sockaddr_in *)iter->ifa_addr)->sin_addr;
				if (!strcmp(interfaceName, iter->ifa_name)) {
					ret = ((struct in_addr*)addrPtr)->s_addr;
				}
			}
		}
		freeifaddrs(interfaceArray);             /* free the dynamic memory */
		interfaceArray = NULL;                   /* prevent use after free  */
	}
	else {
		printf("getifaddrs() failed with errno =  %d %s \n", errno, strerror(errno));
	}
#else
		/// TODO: Implement Get Interface Address
#endif
	return ret;
}

void printIp(uint32_t ip) {
	printf("%u.%u.%u.%u\n",ip&0xff,(ip>>8)&0xff,(ip>>16)&0xff,(ip>>24)&0xff);
}

string Ipv4Int2Str(uint32_t ip) {
	struct in_addr addr;
	addr.s_addr = ip;
	char buf[INET_ADDRSTRLEN];
#ifndef _WIN32
	inet_ntop(AF_INET, &addr.s_addr, buf, sizeof(buf));
#else
	WCHAR tbuf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &addr.s_addr, tbuf, INET_ADDRSTRLEN);
	wcstombs(buf, tbuf, INET_ADDRSTRLEN);
#endif
	return string(buf);
}

#endif
