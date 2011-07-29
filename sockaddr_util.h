/* sockaddr_any utils */

#ifndef SOCKADDR_UTIL_H
#define SOCKADDR_UTIL_H

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netdb.h>

union sockaddr_any {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
};

int sockaddr_cmp(union sockaddr_any *a, union sockaddr_any *b);
union sockaddr_any *sockaddr_init(union sockaddr_any *sa, int family,
				  void *addr);
union sockaddr_any *sockaddr_from_addrinfo(union sockaddr_any *sa,
					  struct addrinfo *ai);

char *sockaddr_to_string(union sockaddr_any *sa, char *str, size_t size);

#endif /* SOCKADDR_UTIL_H */
