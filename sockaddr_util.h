/* sockaddr_any utils */

#ifndef SOCKADDR_UTIL_H
#define SOCKADDR_UTIL_H

#include <netinet/in.h>

union sockaddr_any {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
};

int sockaddr_cmp(union sockaddr_any *a, union sockaddr_any *b);
union sockaddr_any *sockaddr_init(union sockaddr_any *sa, int family,
				  void *addr);

#endif /* SOCKADDR_UTIL_H */
