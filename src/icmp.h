#ifndef PINGU_ICMP_H
#define PINGU_ICMP_H

#include <asm/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>

int icmp_parse_reply(__u8 *buf, int len, int seq,
		     struct sockaddr *addr,
		     struct sockaddr *origdest);
int icmp_send(int fd, struct sockaddr *to, int tolen, void *buf, int buflen);
int icmp_send_frag_needed(int fd, struct sockaddr *to, int tolen,
			  struct iphdr *iph, int newmtu);
int icmp_send_ping(int fd, struct sockaddr *to, int tolen,
		   int seq, int total_size);
int icmp_read_reply(int fd, struct sockaddr *from, socklen_t fromlen,
		    __u8 *buf, int buflen);
int icmp_open(float timeout);
void icmp_close(int fd);


#endif
