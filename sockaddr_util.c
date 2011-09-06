
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

#include "log.h"
#include "sockaddr_util.h"

int sockaddr_cmp(union sockaddr_any *a, union sockaddr_any *b)
{
	if (a->sa.sa_family != b->sa.sa_family)
		return a->sa.sa_family - b->sa.sa_family;
	
	switch (a->sa.sa_family) {
	case AF_INET:
		return a->sin.sin_addr.s_addr - b->sin.sin_addr.s_addr;
		break;
	case AF_INET6:
		return memcmp((char *) &a->sin6.sin6_addr,
		       (char *) &b->sin6.sin6_addr,
		       sizeof(a->sin6.sin6_addr));
		break;
	}
	return -1;
}

union sockaddr_any *sockaddr_set4(union sockaddr_any *sa, void *addr)
{
	sa->sa.sa_family = AF_INET;
	sa->sin.sin_addr.s_addr = *(uint32_t *)addr;
	return sa;
}

union sockaddr_any *sockaddr_set6(union sockaddr_any *sa, void *addr)
{
	sa->sa.sa_family = AF_INET6;
	memcpy(&sa->sin6.sin6_addr, addr, sizeof(sa->sin6.sin6_addr));
	return sa;
}

union sockaddr_any *sockaddr_init(union sockaddr_any *sa, int family,
				  void *addr)
{
	memset(sa, 0, sizeof(*sa));
	if (addr == NULL)
		return sa;
	switch (family) {
	case AF_INET:
		return sockaddr_set4(sa, addr);
		break;
	case AF_INET6:
		return sockaddr_set6(sa, addr);
		break;
	}
	return NULL;
}

union sockaddr_any *sockaddr_from_addrinfo(union sockaddr_any *sa, 
					     struct addrinfo *ai)
{
	struct sockaddr_in *in = (struct sockaddr_in *)ai->ai_addr;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)ai->ai_addr;
	memset(sa, 0, sizeof(*sa));
	if (ai == NULL)
		return sa;
	switch (ai->ai_family) {
	case AF_INET:
		return sockaddr_set4(sa, &in->sin_addr);
		break;
	case AF_INET6:
		return sockaddr_set6(sa, &in6->sin6_addr);
		break;
	}
	return NULL;
}

char *sockaddr_to_string(union sockaddr_any *sa, char *str, size_t size)
{
	switch (sa->sa.sa_family) {
	case AF_INET:
		inet_ntop(sa->sa.sa_family, &sa->sin.sin_addr, str, size);
		break;
	case AF_INET6:
		inet_ntop(sa->sa.sa_family, &sa->sin6.sin6_addr, str, size);
		break;
	}
	return str;
}

socklen_t sockaddr_len(union sockaddr_any *sa)
{
	socklen_t len = 0;
	switch (sa->sa.sa_family) {
	case AF_INET:
		len = sizeof(sa->sin);
		break;
	case AF_INET6:
		len = sizeof(sa->sin6);
		break;
	}
	return len;
}
