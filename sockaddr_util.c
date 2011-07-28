
#include <netinet/in.h>
#include <string.h>

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

union sockaddr_any *sockaddr_init(union sockaddr_any *sa, int family,
				  void *addr)
{
	memset(sa, 0, sizeof(sa));
	if (addr == NULL)
		return sa;
	sa->sa.sa_family = family;
	switch (family) {
	case AF_INET:
		sa->sin.sin_addr.s_addr = *(uint32_t *)addr;
		break;
	case AF_INET6:
		memcpy(&sa->sin6.sin6_addr, addr,
		       sizeof(sa->sin6.sin6_addr));
		break;
	}
	return sa;
}
