
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xlib.h"

void *xmalloc(size_t size)
{
	void *p = malloc(size);
	if (p == NULL)
		err(EXIT_FAILURE, "malloc");
	return p;
}

void *xrealloc(void *ptr, size_t size)
{
	void *p = realloc(ptr, size);
	if (p == NULL)
		err(EXIT_FAILURE, "realloc");
	return p;
}

char *xstrdup(const char *str)
{
	char *s = strdup(str);
	if (s == NULL)
		err(EXIT_FAILURE, "strdup");
	return s;
}

int init_sockaddr(struct sockaddr_in *addr, const char *host)
{
	memset((char *) addr, 0, sizeof(struct sockaddr_in));
	addr->sin_family = AF_INET;
	if (inet_aton(host, &addr->sin_addr) == 0) {
		struct hostent *hp;		
		hp = gethostbyname(host);
		if (!hp) 
			return -1;
		memcpy(&addr->sin_addr, hp->h_addr, 4);
	}
	return 0;
}

